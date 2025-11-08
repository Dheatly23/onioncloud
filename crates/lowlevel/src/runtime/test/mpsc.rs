use std::fmt::{Debug, Formatter, Result as FmtResult};
use std::marker::PhantomPinned;
use std::num::Wrapping;
use std::pin::Pin;
use std::ptr::NonNull;
use std::sync::atomic::AtomicUsize;
use std::sync::atomic::Ordering::*;
use std::task::{Context, Poll, Waker};

use futures_core::stream::Stream;
use futures_sink::Sink;
use parking_lot::Mutex;
use pin_project::{pin_project, pinned_drop};

use crate::private::Sealed;
use crate::runtime::{PipeReceiver, PipeSender, SendError};
use crate::util::set_option_waker;

struct MPSCPipeInner<T> {
    buf: Box<[Option<T>]>,
    start: usize,
    end: usize,
    send_wakers: Vec<Waker>,
    send_wakers_gen: Wrapping<u64>,
    recv_waker: Option<Waker>,
}

struct MPSCPipe<T> {
    inner: Mutex<MPSCPipeInner<T>>,
    senders: AtomicUsize,
    receiver: AtomicUsize,
    _pinned: PhantomPinned,
}

impl<T> MPSCPipeInner<T> {
    fn wake_send(&mut self) {
        if self.send_wakers.is_empty() {
            return;
        }

        self.send_wakers_gen += 1;
        for w in self.send_wakers.drain(..) {
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
pub struct MPSCPipeSender<T> {
    inner: Option<NonNull<MPSCPipe<T>>>,
    buf: Option<T>,
    ix: usize,
    r#gen: Wrapping<u64>,
    #[pin]
    _pinned: PhantomPinned,
}

impl<T> MPSCPipeSender<T> {
    fn close(self: Pin<&mut Self>) {
        let Some(v) = self.project().inner.take() else {
            return;
        };
        // SAFETY: This is originally created from Box.
        let p = unsafe { v.as_ref() };

        let s = p.senders.fetch_sub(1, Release);
        debug_assert_ne!(s, 0);
        let r = p.receiver.load(Acquire);
        if s == 1 {
            if r > 0 {
                p.inner.lock().wake_recv();
            } else {
                // SAFETY: This is originally created from Box.
                unsafe { drop(Box::from_raw(v.as_ptr())) }
            }
        }
    }
}

unsafe impl<T: Send> Send for MPSCPipeSender<T> {}
unsafe impl<T: Send> Sync for MPSCPipeSender<T> {}

impl<T: Send> Sealed for MPSCPipeSender<T> {}

#[pinned_drop]
impl<T> PinnedDrop for MPSCPipeSender<T> {
    fn drop(self: Pin<&mut Self>) {
        self.close();
    }
}

impl<T: Send> Clone for MPSCPipeSender<T> {
    fn clone(&self) -> Self {
        if let Some(p) = self.inner {
            // SAFETY: This is originally created from Box.
            let t = unsafe { p.as_ref().senders.fetch_add(1, Relaxed) };
            assert_ne!(t, usize::MAX);
        }

        Self {
            inner: self.inner,
            buf: None,
            ix: 0,
            r#gen: self.r#gen - Wrapping(1),
            _pinned: PhantomPinned,
        }
    }

    fn clone_from(&mut self, src: &Self) {
        // Discard current buffered value.
        self.buf = None;

        if self.inner != src.inner
            && let Some(p) = src.inner
        {
            // SAFETY: This is originally created from Box.
            let t = unsafe { p.as_ref().senders.fetch_add(1, Relaxed) };
            assert_ne!(t, usize::MAX);
            self.inner = src.inner;
        }

        self.ix = 0;
        self.r#gen = src.r#gen - Wrapping(1);
    }
}

impl<T: Send> Sink<T> for MPSCPipeSender<T> {
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
        } else if inner.receiver.load(Acquire) == 0 {
            Poll::Ready(Err(SendError(this.buf.take().unwrap())))
        } else {
            guard.wake_recv();
            if *this.r#gen == guard.send_wakers_gen
                && let Some(w) = guard.send_wakers.get_mut(*this.ix)
            {
                w.clone_from(cx.waker());
            } else {
                *this.r#gen = guard.send_wakers_gen;
                *this.ix = guard.send_wakers.len();
                guard.send_wakers.push(cx.waker().clone());
            }

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

impl<T: Send> PipeSender<T> for MPSCPipeSender<T> {
    fn is_disconnected(&self) -> bool {
        let Some(inner) = self.inner else { return true };
        // SAFETY: This is originally created from Box.
        let inner = unsafe { inner.as_ref() };

        inner.receiver.load(Acquire) == 0
    }
}

impl<T> Debug for MPSCPipeSender<T> {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        f.write_str("MPSCPipeSender")
    }
}

#[pin_project(PinnedDrop)]
pub struct MPSCPipeReceiver<T>(NonNull<MPSCPipe<T>>, #[pin] PhantomPinned);

unsafe impl<T: Send> Send for MPSCPipeReceiver<T> {}
unsafe impl<T: Send> Sync for MPSCPipeReceiver<T> {}

impl<T: Send> Sealed for MPSCPipeReceiver<T> {}

#[pinned_drop]
impl<T> PinnedDrop for MPSCPipeReceiver<T> {
    fn drop(self: Pin<&mut Self>) {
        // SAFETY: This is originally created from Box.
        let p = unsafe { self.0.as_ref() };

        let r = p.receiver.fetch_sub(1, Release);
        debug_assert_eq!(r, 1);
        let s = p.senders.load(Acquire);
        if s != 0 {
            p.inner.lock().wake_send();
        } else {
            // SAFETY: This is originally created from Box.
            unsafe { drop(Box::from_raw(self.0.as_ptr())) }
        }
    }
}

impl<T: Send> Stream for MPSCPipeReceiver<T> {
    type Item = T;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        // SAFETY: This is originally created from Box.
        let inner = unsafe { self.0.as_ref() };
        let guard = &mut *inner.inner.lock();

        if let v @ Some(_) = guard.buf[guard.start].take() {
            guard.start = (guard.start + 1) % guard.buf.len();
            guard.wake_send();
            Poll::Ready(v)
        } else if inner.senders.load(Relaxed) == 0 {
            Poll::Ready(None)
        } else {
            guard.wake_send();
            set_option_waker(&mut guard.recv_waker, cx);
            Poll::Pending
        }
    }
}

impl<T: Send> PipeSender<T> for MPSCPipeReceiver<T> {
    fn is_disconnected(&self) -> bool {
        // SAFETY: This is originally created from Box.
        let inner = unsafe { self.0.as_ref() };

        inner.senders.load(Acquire) == 0
    }
}

impl<T> Debug for MPSCPipeReceiver<T> {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        f.write_str("MPSCPipeSender")
    }
}

pub(super) fn make_mpsc_pair<T: Send>(n: usize) -> (MPSCPipeSender<T>, MPSCPipeReceiver<T>) {
    let mut buf = Vec::<Option<T>>::with_capacity(n);
    for _ in 0..n {
        buf.push(None);
    }

    // SAFETY: Box pointer must be non-null
    let inner = unsafe {
        NonNull::new_unchecked(Box::into_raw(Box::new(MPSCPipe {
            senders: 1usize.into(),
            receiver: 1usize.into(),
            inner: Mutex::new(MPSCPipeInner {
                buf: buf.into(),
                start: 0,
                end: 0,
                send_wakers: Vec::new(),
                send_wakers_gen: Wrapping(0),
                recv_waker: None,
            }),
            _pinned: PhantomPinned,
        })))
    };
    (
        MPSCPipeSender {
            inner: Some(inner),
            buf: None,
            ix: 0,
            r#gen: Wrapping(u64::MAX),
            _pinned: PhantomPinned,
        },
        MPSCPipeReceiver(inner, PhantomPinned),
    )
}
