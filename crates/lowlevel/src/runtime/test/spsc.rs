use std::fmt::{Debug, Formatter, Result as FmtResult};
use std::marker::PhantomPinned;
use std::pin::Pin;
use std::ptr::NonNull;
use std::sync::atomic::AtomicU8;
use std::sync::atomic::Ordering::*;
use std::task::{Context, Poll, Waker};

use futures_core::stream::Stream;
use futures_sink::Sink;
use parking_lot::Mutex;
use pin_project::{pin_project, pinned_drop};

use crate::private::Sealed;
use crate::runtime::{PipeReceiver, PipeSender, SendError};
use crate::util::set_option_waker;

struct SPSCPipeInner<T> {
    buf: Box<[Option<T>]>,
    start: usize,
    end: usize,
    send_waker: Option<Waker>,
    recv_waker: Option<Waker>,
}

struct SPSCPipe<T> {
    inner: Mutex<SPSCPipeInner<T>>,
    flags: AtomicU8,
    _pinned: PhantomPinned,
}

impl<T> SPSCPipeInner<T> {
    fn wake_send(&mut self) {
        if let Some(w) = self.send_waker.take() {
            w.wake();
        }
    }

    fn wake_recv(&mut self) {
        if let Some(w) = self.recv_waker.take() {
            w.wake();
        }
    }
}

#[pin_project(PinnedDrop)]
pub struct SPSCPipeSender<T> {
    inner: Option<NonNull<SPSCPipe<T>>>,
    buf: Option<T>,
    #[pin]
    _pinned: PhantomPinned,
}

impl<T> SPSCPipeSender<T> {
    fn close(self: Pin<&mut Self>) {
        let Some(v) = self.project().inner.take() else {
            return;
        };
        // SAFETY: This is originally created from Box.
        let p = unsafe { v.as_ref() };

        let t = p.flags.fetch_sub(1, Release);
        debug_assert_eq!(t & !2, 1);
        if t & 2 != 0 {
            p.inner.lock().wake_recv();
        }

        if t == 1 {
            // SAFETY: This is originally created from Box.
            unsafe { drop(Box::from_raw(v.as_ptr())) }
        }
    }
}

unsafe impl<T: Send> Send for SPSCPipeSender<T> {}
unsafe impl<T: Send> Sync for SPSCPipeSender<T> {}

impl<T: Send> Sealed for SPSCPipeSender<T> {}

#[pinned_drop]
impl<T> PinnedDrop for SPSCPipeSender<T> {
    fn drop(self: Pin<&mut Self>) {
        self.close();
    }
}

impl<T: Send> Sink<T> for SPSCPipeSender<T> {
    type Error = SendError<T>;

    fn poll_ready(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        let this = self.project();
        if this.buf.is_none() {
            return Poll::Ready(Ok(()));
        }

        let inner = this.inner.expect("channel closed");
        // SAFETY: This is originally created from Box.
        let inner = unsafe { inner.as_ref() };
        let guard = &mut *inner.inner.lock();

        let p = &mut guard.buf[guard.end];
        if p.is_none() {
            *p = this.buf.take();
            if p.is_some() {
                guard.end = (guard.end + 1) % guard.buf.len();
            }
            guard.wake_recv();
            Poll::Ready(Ok(()))
        } else if inner.flags.load(Acquire) & 2 == 0 {
            Poll::Ready(Err(SendError(this.buf.take().unwrap())))
        } else {
            guard.wake_recv();
            set_option_waker(&mut guard.send_waker, cx);
            Poll::Pending
        }
    }

    fn start_send(self: Pin<&mut Self>, item: T) -> Result<(), Self::Error> {
        let this = self.project();
        if this.buf.is_some() {
            Err(SendError(item))
        } else {
            *this.buf = Some(item);
            Ok(())
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.poll_ready(cx)
    }

    fn poll_close(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        match self.as_mut().poll_ready(cx) {
            r @ Poll::Ready(Ok(())) => {
                self.close();
                r
            }
            r => r,
        }
    }
}

impl<T: Send> PipeSender<T> for SPSCPipeSender<T> {
    fn is_disconnected(&self) -> bool {
        let Some(inner) = self.inner else { return true };
        // SAFETY: This is originally created from Box.
        let inner = unsafe { inner.as_ref() };

        inner.flags.load(Acquire) != 3
    }
}

impl<T> Debug for SPSCPipeSender<T> {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        f.write_str("SPSCPipeSender")
    }
}

#[pin_project(PinnedDrop)]
pub struct SPSCPipeReceiver<T>(NonNull<SPSCPipe<T>>, #[pin] PhantomPinned);

unsafe impl<T: Send> Send for SPSCPipeReceiver<T> {}
unsafe impl<T: Send> Sync for SPSCPipeReceiver<T> {}

impl<T: Send> Sealed for SPSCPipeReceiver<T> {}

#[pinned_drop]
impl<T> PinnedDrop for SPSCPipeReceiver<T> {
    fn drop(self: Pin<&mut Self>) {
        // SAFETY: This is originally created from Box.
        let p = unsafe { self.0.as_ref() };

        let t = p.flags.fetch_sub(2, Release);
        debug_assert_eq!(t & !1, 2);
        if t & 1 != 0 {
            p.inner.lock().wake_send();
        }

        if t == 2 {
            // SAFETY: This is originally created from Box.
            unsafe { drop(Box::from_raw(self.0.as_ptr())) }
        }
    }
}

impl<T: Send> Stream for SPSCPipeReceiver<T> {
    type Item = T;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        // SAFETY: This is originally created from Box.
        let inner = unsafe { self.0.as_ref() };
        let guard = &mut *inner.inner.lock();

        if let v @ Some(_) = guard.buf[guard.start].take() {
            guard.start = (guard.start + 1) % guard.buf.len();
            guard.wake_send();
            Poll::Ready(v)
        } else if inner.flags.load(Relaxed) & 1 == 0 {
            Poll::Ready(None)
        } else {
            guard.wake_send();
            set_option_waker(&mut guard.recv_waker, cx);
            Poll::Pending
        }
    }
}

impl<T: Send> PipeReceiver<T> for SPSCPipeReceiver<T> {
    fn is_disconnected(&self) -> bool {
        // SAFETY: This is originally created from Box.
        let inner = unsafe { self.0.as_ref() };

        inner.flags.load(Acquire) != 3
    }
}

impl<T> Debug for SPSCPipeReceiver<T> {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        f.write_str("SPSCPipeSender")
    }
}

pub(super) fn make_spsc_pair<T: Send>(n: usize) -> (SPSCPipeSender<T>, SPSCPipeReceiver<T>) {
    let mut buf = Vec::<Option<T>>::with_capacity(n);
    for _ in 0..n {
        buf.push(None);
    }

    // SAFETY: Box pointer must be non-null
    let inner = unsafe {
        NonNull::new_unchecked(Box::into_raw(Box::new(SPSCPipe {
            flags: 3u8.into(),
            inner: Mutex::new(SPSCPipeInner {
                buf: buf.into(),
                start: 0,
                end: 0,
                send_waker: None,
                recv_waker: None,
            }),
            _pinned: PhantomPinned,
        })))
    };
    (
        SPSCPipeSender {
            inner: Some(inner),
            buf: None,
            _pinned: PhantomPinned,
        },
        SPSCPipeReceiver(inner, PhantomPinned),
    )
}
