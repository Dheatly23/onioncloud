use std::alloc::{Layout, alloc, dealloc, handle_alloc_error};
#[cfg(test)]
use std::any::type_name;
#[cfg(test)]
use std::cell::Cell;
use std::marker::{PhantomData, PhantomPinned};
use std::mem::forget;
use std::ops::Deref;
use std::ptr::{NonNull, drop_in_place, write};
use std::sync::atomic::{AtomicUsize, Ordering::*, fence};

#[cfg(test)]
thread_local! {
    pub(crate) static DROP_CNT: Cell<usize> = Cell::new(0);
}

#[cfg(test)]
pub(crate) fn reset_drop_cnt() {
    DROP_CNT.set(0);
}

#[cfg(test)]
pub(crate) fn get_drop_cnt() -> usize {
    DROP_CNT.get()
}

#[cfg(test)]
pub(crate) fn inc_drop_cnt() {
    DROP_CNT.with(|v| v.set(v.get() + 1));
}

pub(crate) struct InnerArcLike<T: Sized> {
    inner: T,
    cnt: AtomicUsize,
    _pinned: PhantomPinned,
}

pub(crate) struct ArcLike<T: Sized> {
    p: NonNull<InnerArcLike<T>>,
    _phantom: PhantomData<*mut T>,
}

// SAFETY: Follows std::sync::Arc.
unsafe impl<T: Sized + Send + Sync> Send for ArcLike<T> {}
// SAFETY: Follows std::sync::Arc.
unsafe impl<T: Sized + Send + Sync> Sync for ArcLike<T> {}

impl<T: Sized> Drop for ArcLike<T> {
    fn drop(&mut self) {
        // SAFETY: We're dropping inner.
        unsafe { self.dec() }
    }
}

impl<T: Sized> Clone for ArcLike<T> {
    fn clone(&self) -> Self {
        // SAFETY: We're cloning inner.
        unsafe {
            self.inc();
            Self {
                p: self.p,
                _phantom: PhantomData,
            }
        }
    }

    fn clone_from(&mut self, src: &Self) {
        if self.p != src.p {
            // SAFETY: We're dropping self and cloning source.
            unsafe {
                self.dec();
                src.inc();
            }
            self.p = src.p;
        }
    }
}

impl<T: Sized + Default> Default for ArcLike<T> {
    fn default() -> Self {
        Self::new(T::default())
    }
}

impl<T: Sized> Deref for ArcLike<T> {
    type Target = T;

    fn deref(&self) -> &T {
        // SAFETY: Pointer points to valid allocation.
        unsafe { &self.p.as_ref().inner }
    }
}

impl<T: Sized> ArcLike<T> {
    pub(crate) fn new(value: T) -> Self {
        let layout: Layout = Layout::new::<InnerArcLike<T>>();
        // SAFETY: Layout is valid and never zero sized.
        let Some(ret) = NonNull::new(unsafe { alloc(layout) }.cast::<InnerArcLike<T>>()) else {
            handle_alloc_error(layout)
        };
        // SAFETY: Pointer points to uninitialized allocation.
        let ret = unsafe {
            write(
                ret.as_ptr(),
                InnerArcLike {
                    cnt: AtomicUsize::new(1),
                    inner: value,
                    _pinned: PhantomPinned,
                },
            );
            Self::from_raw(ret)
        };

        #[cfg(test)]
        {
            tracing::trace!(
                addr = ?ret.p.as_ptr(),
                "creating new value of {}",
                type_name::<T>()
            );
        }

        ret
    }

    #[cfg(test)]
    pub(crate) fn get_raw(&self) -> NonNull<InnerArcLike<T>> {
        self.p
    }

    pub(crate) fn into_raw(self) -> NonNull<InnerArcLike<T>> {
        let r = self.p;
        forget(self);
        r
    }

    pub(crate) unsafe fn from_raw(ptr: NonNull<InnerArcLike<T>>) -> Self {
        Self {
            p: ptr,
            _phantom: PhantomData,
        }
    }

    unsafe fn inc(&self) {
        #[cfg(test)]
        {
            tracing::trace!(
                addr = ?self.p.as_ptr(),
                "increasing reference count of {}",
                type_name::<T>()
            );
        }

        // SAFETY: Pointer points to valid allocation.
        let r = unsafe { self.p.as_ref().cnt.fetch_add(1, Relaxed) };
        // NOTE: Should be process abort but eh.
        assert!(r != 0, "reference count overflow");
    }

    unsafe fn dec(&self) {
        #[cfg(test)]
        {
            tracing::trace!(
                addr = ?self.p.as_ptr(),
                "decreasing reference count of {}",
                type_name::<T>()
            );
        }

        // SAFETY: Pointer points to valid allocation.
        let r = unsafe { self.p.as_ref().cnt.fetch_sub(1, Release) };
        if r == 1 {
            fence(Acquire);

            let p = self.p.as_ptr();

            #[cfg(test)]
            {
                tracing::trace!(
                    addr = ?p,
                    "dropping value of {}",
                    type_name::<T>()
                );
                inc_drop_cnt();
            }

            // SAFETY: Pointer points to valid allocation and we're about to drop it.
            unsafe {
                let layout = Layout::for_value(&*p);
                drop_in_place(p);
                dealloc(p.cast(), layout);
            }
        }
    }
}

#[cfg(test)]
pub(crate) fn run_test(f: impl Fn() + Send + Sync + 'static) {
    cfg_select! {
        feature = "loom" => {
            loom::model(f);
        }
        _ => {
            f();
        }
    }
}

#[cfg(all(test, feature = "loom"))]
pub(crate) fn run_async(
    f: impl AsyncFnOnce() + Send + Sync + 'static,
) -> loom::thread::JoinHandle<()> {
    use loom::sync::{Condvar, Mutex};
    use std::mem::replace;
    use std::pin::pin;
    use std::sync::Arc;
    use std::task::{Context, Wake, Waker};

    #[derive(Default)]
    struct InnerWaker {
        condvar: Condvar,
        mutex: Mutex<bool>,
    }

    impl Wake for InnerWaker {
        fn wake(self: Arc<Self>) {
            self.wake_by_ref();
        }

        fn wake_by_ref(self: &Arc<Self>) {
            *self.mutex.lock().unwrap() = true;
            self.condvar.notify_one();
        }
    }

    loom::thread::spawn(move || {
        let inner = Arc::new(InnerWaker::default());
        let mut guard = inner.mutex.lock().unwrap();
        let waker = Waker::from(inner.clone());
        let mut cx = Context::from_waker(&waker);
        let mut fut = pin!(f());

        while fut.as_mut().poll(&mut cx).is_pending() {
            while !replace(&mut *guard, false) {
                guard = inner.condvar.wait(guard).unwrap();
            }
        }
    })
}
