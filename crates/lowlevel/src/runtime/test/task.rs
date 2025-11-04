use std::cell::UnsafeCell;
use std::future::Future;
use std::marker::PhantomPinned;
use std::ops::Deref;
use std::pin::Pin;
use std::ptr::NonNull;
use std::sync::Arc;
use std::sync::atomic::Ordering::*;
use std::sync::atomic::{AtomicU8, AtomicU16, AtomicUsize};
use std::task::{Context, Poll, RawWaker, RawWakerVTable, Waker};

use tracing::{Span, info_span};

use crate::util::set_option_waker;

#[derive(Default)]
pub(super) struct Tasks {
    tasks: Vec<Option<Pin<Box<dyn Send + Future<Output = ()>>>>>,
    wakers: Vec<TestWakerWrapper>,
}

impl Tasks {
    #[inline]
    pub(super) fn len(&self) -> usize {
        self.tasks.len()
    }

    pub(super) fn is_finished(&self) -> bool {
        self.tasks.iter().all(|v| v.is_none())
    }

    pub(super) fn task_count(&self) -> usize {
        self.tasks.iter().filter(|v| v.is_some()).count()
    }

    pub(super) fn is_task_finished(&self, ix: usize) -> bool {
        self.tasks[ix].is_none()
    }

    pub(super) fn is_task_awake(&self, ix: usize) -> bool {
        self.wakers[ix / 16].is_wake((ix % 16) as _)
    }

    pub(super) fn run_task(&mut self, ix: usize) -> bool {
        let p = &mut self.tasks[ix];
        let Some(task) = p else { return true };
        let j = (ix % 16) as u8;
        let w = &self.wakers[ix / 16];

        if !w.take_wake_at_flipped(j) {
            false
        } else if info_span!("task", id = ix).in_scope(|| {
            task.as_mut()
                .poll(&mut Context::from_waker(&w.create_waker(j)))
                .is_ready()
        }) {
            *p = None;
            true
        } else {
            false
        }
    }

    pub(super) fn run_tasks(&mut self) -> usize {
        for w in &self.wakers {
            w.swap_wake();
        }

        let mut run = 0;
        for (i, w) in self.wakers.iter().enumerate() {
            let t = w.take_wake();
            for j in 0..16u8 {
                let i = i * 16 + usize::from(j);
                if t & 1 << j == 0 {
                    continue;
                }

                let p = &mut self.tasks[i];
                let Some(task) = p else { continue };
                run += 1;
                if info_span!("task", id = i).in_scope(|| {
                    task.as_mut()
                        .poll(&mut Context::from_waker(&w.create_waker(j)))
                        .is_ready()
                }) {
                    *p = None;
                }
            }
        }

        run
    }

    pub(super) fn add_pending(
        &mut self,
        tasks: impl IntoIterator<Item = Pin<Box<dyn Send + Future<Output = ()>>>>,
    ) {
        let it = tasks.into_iter();
        let l = it.size_hint().0;
        self.tasks.reserve(l);
        self.wakers.reserve((l + 15) / 16);

        for t in it {
            let i = self.tasks.len();
            self.tasks.push(Some(t));
            match i % 16 {
                0 => {
                    let w = TestWakerWrapper::new();
                    w.wake(0);
                    self.wakers.push(w);
                }
                i => self.wakers.last().unwrap().wake(i as _),
            }
        }
    }
}

#[repr(align(16))]
struct TestWaker {
    count: AtomicUsize,
    data: [AtomicU16; 2],
    _pinned: PhantomPinned,
}

impl TestWaker {
    fn swap_wake(&self) {
        self.count.fetch_xor(1, Release);
    }

    fn take_wake(&self) -> u16 {
        self.data[!self.count.load(Acquire) & 1].swap(0, AcqRel)
    }

    fn take_wake_at_flipped(&self, ix: u8) -> bool {
        assert!(ix < 16, "{ix} >= 16");
        let m = 1 << ix;
        self.data[!self.count.load(Acquire) & 1].fetch_and(!m, AcqRel) & m != 0
    }

    fn is_wake(&self, ix: u8) -> bool {
        assert!(ix < 16, "{ix} >= 16");
        self.data[self.count.load(Acquire) & 1].load(Acquire) & 1 << ix != 0
    }

    fn wake(&self, ix: u8) {
        assert!(ix < 16, "{ix} >= 16");
        self.data[self.count.load(Acquire) & 1].fetch_or(1 << ix, Relaxed);
    }
}

unsafe fn drop_waker(this: NonNull<TestWaker>) {
    let this = this.as_ptr().map_addr(|a| a & !15);

    // SAFETY: This is non-null and count is greater than 0.
    let c = unsafe { (*this).count.fetch_sub(2, Release) & !1 };
    assert_ne!(c, 0);
    if c == 2 {
        // SAFETY: This is originally created from Box.
        unsafe { drop(Box::from_raw(this)) }
    }
}

struct TestWakerWrapper(NonNull<TestWaker>);

unsafe impl Send for TestWakerWrapper {}
unsafe impl Sync for TestWakerWrapper {}

impl Drop for TestWakerWrapper {
    fn drop(&mut self) {
        // SAFETY: Pointer is originally created from Box.
        unsafe { drop_waker(self.0) }
    }
}

impl Deref for TestWakerWrapper {
    type Target = TestWaker;

    fn deref(&self) -> &TestWaker {
        // SAFETY: Pointer is a valid TestWaker instance.
        unsafe { self.0.as_ref() }
    }
}

impl TestWakerWrapper {
    fn new() -> Self {
        // SAFETY: Box pointer must be non-null
        unsafe {
            Self(NonNull::new_unchecked(Box::into_raw(Box::new(TestWaker {
                count: 2usize.into(),
                data: [0u16.into(), 0u16.into()],
                _pinned: PhantomPinned,
            }))))
        }
    }

    fn create_waker(&self, ix: u8) -> Waker {
        assert!(ix < 16, "{ix} >= 16");

        static VTABLE: RawWakerVTable =
            RawWakerVTable::new(clone_waker, wake_waker, wake_ref_waker, drop_waker2);

        fn clone_waker(p_: *const ()) -> RawWaker {
            let p = p_.cast::<TestWaker>().map_addr(|a| a & !15);

            // SAFETY: Pointer is a TestWaker instance.
            unsafe {
                let c = (*p).count.fetch_add(2, Relaxed);
                assert!(c < usize::MAX & !1, "{c} >= {}", usize::MAX & !1);
                RawWaker::new(p_, &VTABLE)
            }
        }

        fn wake_waker(p: *const ()) {
            wake_ref_waker(p);
            drop_waker2(p);
        }

        fn wake_ref_waker(p: *const ()) {
            let p = p.cast::<TestWaker>();

            let off = p.addr() & 15;
            let p = p.map_addr(|a| a & !15);

            // SAFETY: Pointer is a TestWaker instance.
            unsafe { (*p).wake(off as _) }
        }

        fn drop_waker2(p: *const ()) {
            // SAFETY: Pointer is a TestWaker instance that is created from Box.
            unsafe { drop_waker(NonNull::new_unchecked(p.cast::<TestWaker>().cast_mut())) }
        }

        unsafe {
            Waker::from_raw(clone_waker(
                self.0.as_ptr().byte_add(ix as _).cast_const().cast(),
            ))
        }
    }
}

pub struct Handle<T> {
    inner: Arc<InnerHandle<T>>,
}

struct InnerHandle<T> {
    flags: AtomicU8,
    waker: UnsafeCell<Option<Waker>>,
    value: UnsafeCell<Option<T>>,
}

unsafe impl<T: Send> Send for InnerHandle<T> {}
unsafe impl<T: Send> Sync for InnerHandle<T> {}

impl<T: Send> Future for Handle<T> {
    type Output = T;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<T> {
        let inner = &*Pin::into_inner(self).inner;
        let flags = inner.flags.fetch_and(2, AcqRel);

        let mut registered = false;
        loop {
            if flags & 1 != 0 {
                // SAFETY: Value is already written.
                unsafe {
                    break Poll::Ready((*inner.value.get()).take().expect("task panicked"));
                }
            } else if registered {
                break Poll::Pending;
            }

            registered = true;
            debug_assert!(flags & 2 != 0, "{flags} & 2 == 0");

            // SAFETY: Waker is not being read.
            unsafe { set_option_waker(&mut *inner.waker.get(), cx) }

            let flags = inner.flags.fetch_add(2, AcqRel);
            debug_assert!(flags & 2 == 0, "{flags} & 2 != 0");
        }
    }
}

impl<T: Send> InnerHandle<T> {
    fn resolve(self: Arc<Self>, value: T) {
        // SAFETY: Value is not read.
        unsafe {
            let p = &mut *self.value.get();
            debug_assert!(p.is_none());
            *p = Some(value);
        }

        let flags = self.flags.swap(1, AcqRel);
        debug_assert!(flags & 1 == 0, "{flags} & 1 != 0");
        if flags & 2 != 0 {
            // SAFETY: Waker is not being written.
            unsafe {
                if let Some(w) = (*self.waker.get()).take() {
                    w.wake();
                }
            }
        }
    }
}

pub(super) fn spawn<F>(fut: F) -> (Handle<F::Output>, Pin<Box<dyn Send + Future<Output = ()>>>)
where
    F: Future + Send + 'static,
    F::Output: Send + 'static,
{
    let inner = Arc::new(InnerHandle {
        flags: 0u8.into(),
        value: None.into(),
        waker: None.into(),
    });
    let handle = Handle {
        inner: inner.clone(),
    };

    (handle, Box::pin(async move { inner.resolve(fut.await) }))
}
