#![allow(unsafe_op_in_unsafe_fn)]

use std::cell::UnsafeCell;
use std::fmt::{Debug, Formatter, Result as FmtResult};
use std::marker::PhantomPinned;
use std::mem::MaybeUninit;
use std::pin::Pin;
use std::ptr::{NonNull, drop_in_place, write};
use std::task::{Context, Poll, Waker};

use futures_core::Stream;
use futures_sink::Sink;
#[cfg(any(test, feature = "tracing"))]
use tracing::{debug, instrument, trace};

#[cfg(not(loom))]
use std::alloc::{Layout, alloc, dealloc};
#[cfg(not(loom))]
use std::sync::atomic::{AtomicU8, Ordering::*};

#[cfg(loom)]
use loom::alloc::{Layout, alloc, dealloc};
#[cfg(loom)]
use loom::sync::atomic::{AtomicU8, Ordering::*};

struct Inner<T> {
    data: UnsafeCell<MaybeUninit<T>>,
    send_waker: UnsafeCell<Option<Waker>>,
    recv_waker: UnsafeCell<Option<Waker>>,
    state: State,

    _phantom: PhantomPinned,
}

/// Sender of channel pair.
///
/// Use [`new`] to construct it. Implements [`Sink`] for it's operation.
pub struct Sender<T: Send> {
    inner: Option<NonNull<Inner<T>>>,
}

unsafe impl<T: Send> Send for Sender<T> {}
unsafe impl<T: Send> Sync for Sender<T> {}
impl<T: Send> Unpin for Sender<T> {}

impl<T: Send> Debug for Sender<T> {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        write!(f, "Sender")
    }
}

/// Receiver of channel pair.
///
/// Use [`new`] to construct it. Implements [`Stream`] for it's operation.
pub struct Receiver<T: Send> {
    inner: NonNull<Inner<T>>,
}

unsafe impl<T: Send> Send for Receiver<T> {}
unsafe impl<T: Send> Sync for Receiver<T> {}
impl<T: Send> Unpin for Receiver<T> {}

impl<T: Send> Debug for Receiver<T> {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        write!(f, "Receiver")
    }
}

/// Error type for [`Sender`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TrySendError<T> {
    Full(T),
    Disconnected(T),
}

/// Create new zero-buffer channel pair.
#[cfg_attr(any(test, feature = "tracing"), instrument(level = "trace"))]
pub fn new<T: Send>() -> (Sender<T>, Receiver<T>) {
    let inner;
    unsafe {
        inner = NonNull::new_unchecked(alloc(Layout::new::<Inner<T>>()).cast::<Inner<T>>());
        write(inner.as_ptr(), Inner::new());
    }

    (Sender { inner: Some(inner) }, Receiver { inner })
}

impl<T: Send> Drop for Sender<T> {
    fn drop(&mut self) {
        if let Some(p) = self.inner {
            unsafe {
                Inner::drop(p.as_ptr(), true);
            }
        }
    }
}

impl<T: Send> Drop for Receiver<T> {
    fn drop(&mut self) {
        unsafe {
            Inner::drop(self.inner.as_ptr(), false);
        }
    }
}

impl<T: Send> Sink<T> for Sender<T> {
    type Error = TrySendError<T>;

    fn poll_ready(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        unsafe {
            let Some(p) = Pin::into_inner_unchecked(self).inner else {
                return Poll::Ready(Ok(()));
            };
            p.as_ref().poll_send(cx)
        }
    }

    fn start_send(self: Pin<&mut Self>, item: T) -> Result<(), Self::Error> {
        unsafe {
            let Some(p) = Pin::into_inner_unchecked(self).inner else {
                return Err(TrySendError::Disconnected(item));
            };
            p.as_ref().send_data(item)
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.poll_ready(cx)
    }

    fn poll_close(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        unsafe {
            let inner = &mut Pin::into_inner_unchecked(self).inner;
            let Some(p) = *inner else {
                return Poll::Ready(Ok(()));
            };
            let ret = p.as_ref().poll_close(cx);
            if ret.is_ready() {
                *inner = None;
                Inner::drop(p.as_ptr(), true);
            }
            ret
        }
    }
}

impl<T: Send> Stream for Receiver<T> {
    type Item = T;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<T>> {
        unsafe { Pin::into_inner_unchecked(self).inner.as_ref().poll_recv(cx) }
    }
}

struct State {
    refcnt: AtomicU8,
    data: AtomicU8,
    send_waker: AtomicU8,
    recv_waker: AtomicU8,
}

// Data flags
const FLAG_DATA_READY: u8 = 1 << 1;
const FLAG_CLOSING: u8 = 1 << 3;
const FLAG_DISCONNECTED: u8 = 1 << 5;
// Waker flags
const FLAG_REGISTERING: u8 = 1 << 1;
const FLAG_WAKING: u8 = 1 << 3;

#[cfg(any(test, feature = "tracing"))]
fn send_frag(send: bool) -> &'static str {
    if send { "send" } else { "recv" }
}

#[inline]
#[track_caller]
fn assert_data_state(state: u8) -> u8 {
    #[cfg(any(test, feature = "tracing"))]
    trace!("data state = {state:08b}");

    debug_assert_eq!(
        state & !(FLAG_DATA_READY | FLAG_CLOSING | FLAG_DISCONNECTED),
        0
    );
    state
}

#[inline]
#[track_caller]
fn assert_waker_state(state: u8) -> u8 {
    #[cfg(any(test, feature = "tracing"))]
    trace!("waker state = {state:08b}");

    debug_assert_eq!(state & !(FLAG_WAKING | FLAG_REGISTERING), 0);
    state
}

impl<T> Inner<T> {
    fn new() -> Self {
        Self {
            data: UnsafeCell::new(MaybeUninit::uninit()),
            send_waker: Default::default(),
            recv_waker: Default::default(),

            state: State {
                refcnt: 2u8.into(),
                data: 0u8.into(),
                send_waker: 0u8.into(),
                recv_waker: 0u8.into(),
            },

            _phantom: PhantomPinned,
        }
    }

    #[cfg_attr(any(test, feature = "tracing"), instrument(level = "trace"))]
    unsafe fn drop(ptr: *const Self, send: bool) {
        let this = &*ptr;
        assert_data_state(this.state.data.fetch_or(FLAG_DISCONNECTED, Relaxed));

        this.wake_waker(!send);

        let refcnt = this.state.refcnt.fetch_sub(1, Release);
        debug_assert!(refcnt <= 2);
        if refcnt == 1 {
            // Last reference holder, dropping inner
            if assert_data_state(this.state.data.load(Relaxed)) & FLAG_DATA_READY != 0 {
                // SAFETY: Data is initialized
                #[cfg(any(test, feature = "tracing"))]
                debug!("dropping data");
                (*this.data.get()).assume_init_drop();
            }

            drop_in_place(ptr.cast_mut());
            dealloc(ptr.cast_mut().cast(), Layout::new::<Self>());
        }
    }

    unsafe fn take_data(&self) -> T {
        #[cfg(any(test, feature = "tracing"))]
        debug!("popping data");

        // SAFETY: Data is ready
        let ret = (*self.data.get()).assume_init_read();
        assert_data_state(self.state.data.fetch_sub(FLAG_DATA_READY, Release));
        ret
    }

    unsafe fn register_waker(&self, cx: &mut Context<'_>, send: bool) {
        let (waker, state) = if send {
            (&mut *self.send_waker.get(), &self.state.send_waker)
        } else {
            (&mut *self.recv_waker.get(), &self.state.recv_waker)
        };

        // Copy atomic waker register()
        match assert_waker_state(
            state
                .compare_exchange(0, FLAG_REGISTERING, Acquire, Acquire)
                .unwrap_or_else(|x| x),
        ) {
            0 => {
                // SAFETY: Waker is initialized and we are registering
                if let Some(w) = waker {
                    #[cfg(any(test, feature = "tracing"))]
                    debug!("swapping {} waker", if send { "send" } else { "recv" });

                    w.clone_from(cx.waker());
                } else {
                    #[cfg(any(test, feature = "tracing"))]
                    debug!("setting {} waker", if send { "send" } else { "recv" });

                    *waker = Some(cx.waker().clone());
                }

                match state.compare_exchange(FLAG_REGISTERING, 0, AcqRel, Acquire) {
                    Err(s) => {
                        assert_waker_state(s);
                        assert_eq!(s, FLAG_REGISTERING | FLAG_WAKING);
                        state.swap(0, AcqRel);
                    }
                    Ok(s) => {
                        assert_waker_state(s);
                    }
                }
            }
            FLAG_WAKING => cx.waker().wake_by_ref(),
            _ => (),
        };
    }

    unsafe fn wake_waker(&self, send: bool) {
        let (waker, state) = if send {
            (&mut *self.send_waker.get(), &self.state.send_waker)
        } else {
            (&mut *self.recv_waker.get(), &self.state.recv_waker)
        };

        // Copy atomic waker take()
        if assert_waker_state(state.fetch_or(FLAG_WAKING, AcqRel)) == 0 {
            // SAFETY: Waker is initialized and neither registering nor waking from other thread
            #[cfg(any(test, feature = "tracing"))]
            debug!("waking {} waker", send_frag(send));
            let waker = waker.take();

            let state = assert_waker_state(state.fetch_and(!FLAG_WAKING, Release));
            debug_assert_eq!(state & FLAG_WAKING, FLAG_WAKING);

            if let Some(w) = waker {
                w.wake();
            }
        }
    }

    #[cfg_attr(any(test, feature = "tracing"), instrument(level = "trace", skip_all, fields(?self = self as *const Self)))]
    unsafe fn send_data(&self, data: T) -> Result<(), TrySendError<T>> {
        let state = assert_data_state(self.state.data.load(Acquire));
        if state & FLAG_DISCONNECTED != 0 {
            // Receiver disconnected
            let data = if state & FLAG_DATA_READY == 0 {
                data
            } else {
                // Value is stuck in inner
                drop(data);
                // SAFETY: We are the only holder of inner
                self.take_data()
            };

            #[cfg(any(test, feature = "tracing"))]
            debug!("receiver disconnected");
            return Err(TrySendError::Disconnected(data));
        } else if state & FLAG_CLOSING != 0 {
            // Sender closed
            #[cfg(any(test, feature = "tracing"))]
            debug!("sender closed");
            return Err(TrySendError::Disconnected(data));
        } else if state & FLAG_DATA_READY != 0 {
            // Sender full
            #[cfg(any(test, feature = "tracing"))]
            debug!("sender full");
            return Err(TrySendError::Full(data));
        }

        (*self.data.get()).write(data);
        assert_data_state(self.state.data.fetch_add(FLAG_DATA_READY, Release));
        self.wake_waker(false);

        #[cfg(any(test, feature = "tracing"))]
        trace!("item pushed");
        Ok(())
    }

    #[cfg_attr(any(test, feature = "tracing"), instrument(level = "trace", skip_all, fields(?self = self as *const Self)))]
    unsafe fn poll_send(&self, cx: &mut Context<'_>) -> Poll<Result<(), TrySendError<T>>> {
        let mut has_registered = false;

        loop {
            let state = assert_data_state(self.state.data.load(Acquire));

            if state & FLAG_DISCONNECTED != 0 {
                // Receiver disconnected
                return Poll::Ready(if state & FLAG_DATA_READY != 0 {
                    // SAFETY: We are the only holder of inner
                    #[cfg(any(test, feature = "tracing"))]
                    debug!("receiver disconnected");
                    Err(TrySendError::Disconnected(self.take_data()))
                } else {
                    #[cfg(any(test, feature = "tracing"))]
                    debug!("item sent");
                    Ok(())
                });
            } else if state & FLAG_DATA_READY == 0 {
                // Data is consumed
                #[cfg(any(test, feature = "tracing"))]
                debug!("item sent");
                return Poll::Ready(Ok(()));
            } else if has_registered {
                #[cfg(any(test, feature = "tracing"))]
                tracing::info!("pending");
                return Poll::Pending;
            }

            self.register_waker(cx, true);
            has_registered = true;
        }
    }

    #[cfg_attr(any(test, feature = "tracing"), instrument(level = "trace", skip_all, fields(?self = self as *const Self)))]
    unsafe fn poll_close(&self, cx: &mut Context<'_>) -> Poll<Result<(), TrySendError<T>>> {
        let mut has_registered = false;

        loop {
            let state = assert_data_state(self.state.data.fetch_or(FLAG_CLOSING, Acquire));

            if state & FLAG_DISCONNECTED != 0 {
                // Receiver disconnected
                return Poll::Ready(if state & FLAG_DATA_READY != 0 {
                    // SAFETY: We are the only holder of inner
                    #[cfg(any(test, feature = "tracing"))]
                    debug!("receiver disconnected");
                    Err(TrySendError::Disconnected(self.take_data()))
                } else {
                    #[cfg(any(test, feature = "tracing"))]
                    debug!("sender closed");
                    Ok(())
                });
            } else if state & FLAG_DATA_READY == 0 {
                // Data is consumed
                self.wake_waker(false);

                #[cfg(any(test, feature = "tracing"))]
                debug!("sender closed");
                return Poll::Ready(Ok(()));
            } else if has_registered {
                #[cfg(any(test, feature = "tracing"))]
                tracing::info!("pending");
                return Poll::Pending;
            }

            self.register_waker(cx, true);
            has_registered = true;
        }
    }

    #[cfg_attr(any(test, feature = "tracing"), instrument(level = "trace", skip_all, fields(?self = self as *const Self)))]
    unsafe fn poll_recv(&self, cx: &mut Context<'_>) -> Poll<Option<T>> {
        let mut has_registered = false;

        loop {
            let state = assert_data_state(self.state.data.load(Acquire));

            if state & FLAG_DATA_READY != 0 {
                // SAFETY: Data is ready
                let data = self.take_data();
                self.wake_waker(true);

                #[cfg(any(test, feature = "tracing"))]
                debug!("item received");
                return Poll::Ready(Some(data));
            } else if state & FLAG_DISCONNECTED != 0 {
                // Sender disconnected
                #[cfg(any(test, feature = "tracing"))]
                debug!("sender disconnected");
                return Poll::Ready(None);
            } else if state & FLAG_CLOSING != 0 {
                // Sender closed
                self.wake_waker(true);

                #[cfg(any(test, feature = "tracing"))]
                debug!("sender closed");
                return Poll::Ready(None);
            } else if has_registered {
                #[cfg(any(test, feature = "tracing"))]
                tracing::info!("pending");
                return Poll::Pending;
            }

            self.register_waker(cx, false);
            has_registered = true;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::hint::black_box;

    use futures_util::{SinkExt, StreamExt};
    use tokio::spawn;
    use tracing::{Instrument, info, info_span};

    #[test_log::test(tokio::test)]
    #[instrument]
    async fn test_send_recv() {
        let (mut send, mut recv) = new::<u64>();

        let handle = spawn(
            async move {
                for i in 0..3 {
                    send.feed(i).await.unwrap();
                    info!("sent {i}");
                }
                send.close().await.unwrap();
                info!("send finished");
            }
            .instrument(info_span!("sender")),
        );

        async move {
            for i in 0..3 {
                let v = recv.next().await;
                info!("received {v:?}");
                assert_eq!(v, Some(i));
            }
            assert_eq!(recv.next().await, None);
            info!("receive finished");
        }
        .instrument(info_span!("receiver"))
        .await;

        handle.await.unwrap();
    }

    #[test_log::test(tokio::test)]
    #[instrument]
    async fn test_send_drop() {
        let (mut send, mut recv) = new::<u64>();

        let handle = spawn(
            async move {
                for i in 0..3 {
                    send.feed(i).await.unwrap();
                    info!("sent {i}");
                }
                drop(send);
            }
            .instrument(info_span!("sender")),
        );

        async move {
            for i in 0..3 {
                let v = recv.next().await;
                info!("received {v:?}");
                assert_eq!(v, Some(i));
            }
            assert_eq!(recv.next().await, None);
            info!("receive finished");
        }
        .instrument(info_span!("receiver"))
        .await;

        handle.await.unwrap();
    }

    #[test_log::test(tokio::test)]
    #[instrument]
    async fn test_recv_drop() {
        let (mut send, mut recv) = new::<u64>();

        let handle = spawn(
            async move {
                for i in 0..3 {
                    send.feed(i).await.unwrap();
                    info!("sent {i}");
                }
                assert_eq!(send.send(10).await, Err(TrySendError::Disconnected(10)));
            }
            .instrument(info_span!("sender")),
        );

        async move {
            for i in 0..3 {
                let v = recv.next().await;
                info!("received {v:?}");
                assert_eq!(v, Some(i));
            }
            drop(recv)
        }
        .instrument(info_span!("receiver"))
        .await;

        handle.await.unwrap();
    }

    #[test_log::test]
    #[ignore = "stress test"]
    #[instrument]
    fn test_stress_test() {
        let rt = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(4)
            .enable_time()
            .build()
            .unwrap();

        let f = |i| {
            async {
                for i in 0..10000 {
                    let (mut send, mut recv) = new::<Box<u64>>();

                    let handle = spawn(
                        async move {
                            for i in 0..3 {
                                send.feed(black_box(Box::new(i))).await.unwrap();
                                info!("sent {i}");
                            }
                            send.close().await.unwrap();
                            info!("send finished");
                        }
                        .instrument(info_span!("sender", i)),
                    );

                    async move {
                        for i in 0..3 {
                            let v = black_box(recv.next().await);
                            info!("received {v:?}");
                            assert_eq!(v.as_deref(), Some(&i));
                        }
                        assert_eq!(black_box(recv.next().await), None);
                        info!("receive finished");
                    }
                    .instrument(info_span!("receiver", i))
                    .await;

                    handle.await.unwrap();
                }
            }
            .instrument(info_span!("main", i))
        };

        rt.block_on(f(0));
    }
}
