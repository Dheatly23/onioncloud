use std::alloc::{Layout, alloc, dealloc, handle_alloc_error};
use std::cell::UnsafeCell;
use std::future::Future;
use std::marker::{PhantomData, PhantomPinned};
use std::pin::Pin;
use std::ptr::{NonNull, drop_in_place, write};
#[cfg(not(feature = "loom"))]
use std::sync::atomic::{AtomicU8, Ordering::*, fence};
use std::task::{Context, Poll, Waker, ready};

use futures_core::FusedFuture;
#[cfg(feature = "loom")]
use loom::sync::atomic::{AtomicU8, Ordering::*, fence};
use pin_project::{pin_project, pinned_drop};
use tracing::instrument;

#[cfg(test)]
use crate::utils::inc_drop_cnt;

/// Inner value.
///
/// # Ownership semantics
///
/// Fields which are not atomic have specific ownership.
/// It's not allowed to read and write fields outside of the owner.
///
/// Ownership of `inner` and `recv_waker` is as follows:
/// - Before [`STATE_DATA_SENT`] is set, `inner` is owned by sender.
///   `recv_waker` is owned by receiver if [`STATE_RECV_WAIT`] is cleared.
/// - After [`STATE_DATA_SENT`] is set, `inner` is owned by receiver.
///   `recv_waker` is owned by sender if [`STATE_RECV_WAIT`] is set.
///
/// # [`STATE_RECV_WAIT`] flag behavior
///
/// Before [`STATE_DATA_SENT`] is set, only receiver may modify the flag to indicate it's (not) ready to register the waker.
/// After [`STATE_DATA_SENT`] is set, sender may may read the flag to determine if it's safe to access the waker.
struct Inner<T> {
    inner: UnsafeCell<Option<T>>,

    state: AtomicU8,

    recv_waker: UnsafeCell<Option<Waker>>,

    _pinned: PhantomPinned,
}

unsafe fn drop_inner<T: Sized>(p: NonNull<Inner<T>>) {
    fence(Acquire);

    let p = p.as_ptr();

    #[cfg(test)]
    {
        tracing::trace!(addr = ?p, "dropping oneshot channel");
        inc_drop_cnt();
    }

    // SAFETY: Pointer points to valid allocation and we're about to drop it.
    unsafe {
        let layout = Layout::for_value(&*p);
        drop_in_place(p);
        dealloc(p.cast(), layout);
    }
}

const STATE_RECV_WAIT: u8 = 1;
const STATE_DATA_SENT: u8 = 2;
const SENDER_FLAG: u8 = 1 << 7;
const RECEIVER_FLAG: u8 = 1 << 6;
const INIT_STATE: u8 = SENDER_FLAG | RECEIVER_FLAG;

/// Sender of value.
#[pin_project(PinnedDrop)]
pub(crate) struct Sender<T: Sized> {
    p: Option<NonNull<Inner<T>>>,
    #[expect(clippy::type_complexity, reason = "all elements are important")]
    _phantom: PhantomData<(T, fn(T) -> T)>,
}

// SAFETY: Sender is send if and only if T is send.
unsafe impl<T: Sized + Send> Send for Sender<T> {}
// SAFETY: Sender is sync if and only if T is send.
unsafe impl<T: Sized + Send> Sync for Sender<T> {}

#[pinned_drop]
impl<T: Sized> PinnedDrop for Sender<T> {
    fn drop(mut self: Pin<&mut Self>) {
        if self.p.is_none() {
            return;
        }
        self.send(None);
    }
}

impl<T: Sized> Sender<T> {
    #[instrument(level = "trace", skip_all, fields(has_value = value.is_some()))]
    pub(crate) fn send(&mut self, value: Option<T>) {
        let Some(p) = self.p else {
            panic!("future polled after it finished");
        };
        // SAFETY: Pointer points to valid allocation.
        let r = unsafe { p.as_ref() };

        #[cfg(test)]
        {
            tracing::trace!(addr = ?p.as_ptr(), "sending value");
        }

        // SAFETY: We have not set STATE_DATA_SENT flag yet.
        unsafe { *r.inner.get() = value };

        // Sets STATE_DATA_SENT.
        // Using acquire semantics because we're acquiring recv waker.
        // While release is done when sender is dropped.
        let mut t = r.state.fetch_add(STATE_DATA_SENT, Acquire);
        assert!(
            t & STATE_DATA_SENT == 0,
            "Flag {t:02x} contains data sent flag. It's a double-free bug."
        );

        if t & RECEIVER_FLAG == 0 {
            self.p = None;
            // SAFETY: Receiver dropped.
            unsafe { drop_inner(p) };
            return;
        } else if t & STATE_RECV_WAIT != 0 {
            #[cfg(test)]
            {
                tracing::trace!(addr = ?p.as_ptr(), "waking receiver");
            }

            // SAFETY: Waker has swapped ownership to sender.
            let w = unsafe { (*r.recv_waker.get()).take() };
            if let Some(w) = w {
                w.wake();
            }
        }

        #[cfg(test)]
        {
            tracing::trace!(
                addr = ?p.as_ptr(),
                "dropping sending half"
            );
        }

        // Drop sender.
        self.p = None;
        t = r.state.fetch_sub(SENDER_FLAG, Release);
        assert!(
            t & SENDER_FLAG != 0,
            "Flag {t:02x} does not contain sender flag. It's a double-free bug."
        );

        if t & RECEIVER_FLAG == 0 {
            // SAFETY: Receiver dropped.
            unsafe { drop_inner(p) }
        }
    }
}

/// Receiver of value.
#[pin_project(PinnedDrop)]
pub(crate) struct Receiver<T: Sized> {
    p: Option<NonNull<Inner<T>>>,
    #[expect(clippy::type_complexity, reason = "all elements are important")]
    _phantom: PhantomData<(T, fn(T) -> T)>,
}

// SAFETY: Receiver is send if and only if T is send.
unsafe impl<T: Sized + Send> Send for Receiver<T> {}
// SAFETY: Receiver is sync if and only if T is send.
unsafe impl<T: Sized + Send> Sync for Receiver<T> {}

#[pinned_drop]
impl<T: Sized> PinnedDrop for Receiver<T> {
    #[instrument(level = "trace", skip_all)]
    fn drop(self: Pin<&mut Self>) {
        let Some(p) = self.p else { return };
        // SAFETY: Pointer points to valid allocation.
        let r = unsafe { p.as_ref() };

        if r.state.load(Relaxed) & STATE_DATA_SENT != 0 {
            // Fence here to synchronize with data write.
            fence(Acquire);

            #[cfg(test)]
            {
                tracing::trace!(addr = ?p.as_ptr(), "receiving value");
            }

            // SAFETY: Data has swapped ownership to receiver.
            unsafe { *r.inner.get() = None }
        }

        #[cfg(test)]
        {
            tracing::trace!(
                addr = ?p.as_ptr(),
                "dropping receiving half"
            );
        }

        // Drop receiver.
        let t = r.state.fetch_sub(RECEIVER_FLAG, Release);
        assert!(
            t & RECEIVER_FLAG != 0,
            "Flag {t:02x} does not contain receiver flag. It's a double-free bug."
        );

        if t & SENDER_FLAG == 0 {
            // SAFETY: Sender dropped.
            unsafe { drop_inner(p) }
        }
    }
}

impl<T: Sized> Future for Receiver<T> {
    type Output = T;

    #[instrument(level = "trace", skip_all)]
    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<T> {
        let this = self.project();
        let Some(p) = *this.p else {
            panic!("polled after future has returned value");
        };
        // SAFETY: Pointer points to valid allocation.
        let r = unsafe { p.as_ref() };

        // Clears STATE_RECV_WAIT flag.
        // Using acquire semantics because we're acquiring recv waker and/or data.
        let mut t = r.state.fetch_and(!STATE_RECV_WAIT, Acquire);
        let mut ret = Poll::Pending;
        if t & STATE_DATA_SENT != 0 {
            #[cfg(test)]
            {
                tracing::trace!(addr = ?p.as_ptr(), "receiving data");
            }

            // SAFETY: Data has swapped ownership to receiver.
            unsafe { ret = Poll::Ready((*r.inner.get()).take()) }
        } else {
            #[cfg(test)]
            {
                tracing::trace!(
                    addr = ?p.as_ptr(),
                    "setting receiver waker"
                );
            }

            {
                // SAFETY: Waker has not swapped ownership.
                let w = unsafe { &mut *r.recv_waker.get() };
                match w {
                    Some(w) => w.clone_from(cx.waker()),
                    None => *w = Some(cx.waker().clone()),
                }
            }

            // Sets STATE_RECV_WAIT flag.
            // Using release semantics because we're releasing recv waker.
            t = r.state.load(Relaxed);
            assert!(
                t & STATE_RECV_WAIT == 0,
                "Flag {t:02x} contains receiver waker flag. It's a double-free bug."
            );
            loop {
                if t & STATE_DATA_SENT != 0 {
                    // Fence here to synchronize with data write.
                    fence(Acquire);

                    #[cfg(test)]
                    {
                        tracing::trace!(addr = ?p.as_ptr(), "receiving data");
                    }

                    // SAFETY: Data has swapped ownership to receiver.
                    unsafe { ret = Poll::Ready((*r.inner.get()).take()) };
                    break;
                }

                match r
                    .state
                    .compare_exchange_weak(t, t | STATE_RECV_WAIT, Release, Relaxed)
                {
                    Ok(_) => break,
                    Err(v) => t = v,
                }
            }
        }

        let ret = ready!(ret);

        #[cfg(test)]
        {
            tracing::trace!(
                addr = ?p.as_ptr(),
                "dropping receiving half"
            );
        }

        // Drop receiver.
        *this.p = None;
        t = r.state.fetch_sub(RECEIVER_FLAG, Release);
        assert!(
            t & RECEIVER_FLAG != 0,
            "Flag {t:02x} does not contain receiver flag. It's a double-free bug."
        );

        if t & SENDER_FLAG == 0 {
            // SAFETY: Sender dropped.
            unsafe { drop_inner(p) }
        }

        let Some(ret) = ret else {
            panic!("future has panicked");
        };

        Poll::Ready(ret)
    }
}

impl<T: Sized> FusedFuture for Receiver<T> {
    fn is_terminated(&self) -> bool {
        self.p.is_none()
    }
}

pub(crate) fn oneshot<T: Sized>() -> (Sender<T>, Receiver<T>) {
    let layout: Layout = Layout::new::<Inner<T>>();
    // SAFETY: Layout is valid and nonzero.
    let Some(ret) = NonNull::new(unsafe { alloc(layout) }.cast::<Inner<T>>()) else {
        handle_alloc_error(layout)
    };
    // SAFETY: Pointer points to uninitialized allocation.
    unsafe {
        write(
            ret.as_ptr(),
            Inner {
                inner: UnsafeCell::new(None),

                state: AtomicU8::new(INIT_STATE),

                recv_waker: UnsafeCell::new(None),

                _pinned: PhantomPinned,
            },
        );
    }

    #[cfg(test)]
    {
        tracing::trace!(
            addr = ?ret.as_ptr(),
            "creating new oneshot channel"
        );
    }

    (
        Sender {
            p: Some(ret),
            _phantom: PhantomData,
        },
        Receiver {
            p: Some(ret),
            _phantom: PhantomData,
        },
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::hint::black_box;

    use test_log::test;
    use tracing::info;

    #[cfg(feature = "loom")]
    use crate::utils::run_async;
    use crate::utils::{get_drop_cnt, reset_drop_cnt, run_test};
    use crate::waker::{MultiWaker, Selector};

    #[test]
    fn test_oneshot_create() {
        #[instrument]
        fn test() {
            reset_drop_cnt();
            black_box(oneshot::<()>());
            assert_eq!(get_drop_cnt(), 1, "drop count mismatch");
        }

        run_test(test);
    }

    #[test]
    fn test_oneshot_send() {
        #[instrument]
        fn test(drop_send_first: bool) {
            let (mut send, mut recv) = oneshot::<u32>();

            info!("sending data");
            send.send(Some(658770));

            info!("receiving data");
            let ret = Pin::new(&mut recv).poll(&mut Context::from_waker(Waker::noop()));
            info!(?ret, "received data");
            assert_eq!(ret, Poll::Ready(658770));

            if drop_send_first {
                drop(send);
                drop(recv);
            } else {
                drop(recv);
                drop(send);
            }
        }

        run_test(|| {
            test(false);
            test(true);
        });
    }

    #[test]
    fn test_oneshot_send_pending() {
        #[instrument]
        fn test(drop_send_first: bool) {
            let (mut send, mut recv) = oneshot::<u32>();

            info!("receiving data");
            let ret = Pin::new(&mut recv).poll(&mut Context::from_waker(Waker::noop()));
            info!(?ret, "received data");
            assert_eq!(ret, Poll::Pending);

            info!("sending data");
            send.send(Some(602334));

            info!("receiving data");
            let ret = Pin::new(&mut recv).poll(&mut Context::from_waker(Waker::noop()));
            info!(?ret, "received data");
            assert_eq!(ret, Poll::Ready(602334));

            if drop_send_first {
                drop(send);
                drop(recv);
            } else {
                drop(recv);
                drop(send);
            }
        }

        run_test(|| {
            test(false);
            test(true);
        });
    }

    #[test]
    fn test_oneshot_send_woken() {
        #[instrument]
        fn test(drop_send_first: bool) {
            let (mut send, mut recv) = oneshot::<u32>();
            let waker = MultiWaker::new(Selector::default());
            let w = waker.make_waker(0);
            let mut cx = Context::from_waker(&w);

            info!("receiving data");
            let ret = Pin::new(&mut recv).poll(&mut cx);
            info!(?ret, "received data");
            assert_eq!(ret, Poll::Pending);

            info!("sending data");
            send.send(Some(288698));
            assert_eq!(waker.take_flags(false), 1);

            info!("receiving data");
            let ret = Pin::new(&mut recv).poll(&mut cx);
            info!(?ret, "received data");
            assert_eq!(ret, Poll::Ready(288698));

            if drop_send_first {
                drop(send);
                drop(recv);
            } else {
                drop(recv);
                drop(send);
            }
        }

        run_test(|| {
            test(false);
            test(true);
        });
    }

    #[cfg(feature = "loom")]
    #[test]
    fn test_oneshot_parallel_send_pending() {
        use std::pin::pin;

        #[instrument]
        fn test() {
            let (mut send, recv) = oneshot::<u32>();

            let handle = run_async(async move || {
                info!("receiving data");
                let ret = pin!(recv).await;
                info!(?ret, "received data");
                assert_eq!(ret, 602334);
            });

            info!("sending data");
            send.send(Some(602334));
            info!("done sending");

            handle.join().unwrap();
        }

        run_test(test);
    }
}
