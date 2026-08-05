use std::alloc::{Layout, alloc, dealloc, handle_alloc_error};
use std::cell::UnsafeCell;
use std::collections::VecDeque;
use std::error::Error;
use std::fmt::{Debug, Display, Formatter, Result as FmtResult};
use std::marker::{PhantomData, PhantomPinned};
use std::mem::{MaybeUninit, forget};
use std::ops::{Deref, DerefMut};
use std::pin::Pin;
use std::ptr::{NonNull, drop_in_place, write};
use std::sync::atomic::{AtomicU8, AtomicUsize, Ordering::*, fence};
use std::task::{Context, Poll, Waker};

use futures_core::Stream;
use futures_sink::Sink;
use pin_project::{pin_project, pinned_drop};
#[cfg(test)]
use tracing::{instrument, trace};

#[cfg(test)]
use crate::utils::inc_drop_cnt;

struct RecvInner<T: Sized> {
    buf: Box<[MaybeUninit<T>]>,
    off: usize,
    len: usize,
    waker: Option<Waker>,
    ready: VecDeque<NonNull<SendOuter<T>>>,
}

struct SendInner<T: Sized> {
    inner: Option<T>,
    waker: Option<Waker>,
}

impl<T: Sized> Default for SendInner<T> {
    fn default() -> Self {
        Self {
            inner: None,
            waker: None,
        }
    }
}

impl<T: Sized> Drop for RecvInner<T> {
    fn drop(&mut self) {
        self.wake_all_senders();

        self.validate_state();
        if self.len == 0 {
            return;
        }

        let mut i = self.off.wrapping_add(self.len) % self.buf.len();
        while self.len > 0 {
            i = i.checked_sub(1).unwrap_or(self.buf.len() - 1);
            self.len -= 1;

            // SAFETY: Element is at the end of the ring.
            unsafe {
                self.buf[i].assume_init_drop();
            }
        }
    }
}

impl<T: Sized> RecvInner<T> {
    #[inline]
    fn new(size: usize) -> Self {
        Self {
            buf: Box::new_uninit_slice(size),
            off: 0,
            len: 0,
            waker: None,
            ready: VecDeque::new(),
        }
    }

    #[track_caller]
    fn validate_state(&self) {
        debug_assert!(
            self.len <= self.buf.len(),
            "length > capacity ({} > {})",
            self.len,
            self.buf.len()
        );
        debug_assert!(
            self.off <= self.buf.len(),
            "offset > capacity ({} > {})",
            self.off,
            self.buf.len()
        );
    }

    fn push(&mut self, item: T) -> Result<(), T> {
        self.validate_state();
        if self.len == self.buf.len() {
            return Err(item);
        }

        let i = self.off.checked_sub(1).unwrap_or(self.buf.len() - 1);
        self.buf[i].write(item);
        self.off = i;
        self.len += 1;
        Ok(())
    }

    fn pop(&mut self) -> Option<T> {
        self.validate_state();
        if self.len == 0 {
            return None;
        }

        self.len -= 1;
        let i = self.off.wrapping_add(self.len) % self.buf.len();
        // SAFETY: Element is at the end of the ring.
        let ret = unsafe { self.buf[i].assume_init_read() };
        Some(ret)
    }

    fn wake_sender(&mut self) {
        self.validate_state();

        while self.len != self.buf.len() {
            let Some(p) = self.ready.pop_front() else {
                return;
            };
            // SAFETY: Pointer points to valid allocation.
            let r = unsafe { p.as_ref() };

            let mut g = r.try_lock().ok();
            if let Some(r) = &mut g {
                if let Some(i) = r.inner.take() {
                    let _ = self.push(i);
                }
                if let Some(w) = r.waker.take() {
                    #[cfg(test)]
                    {
                        tracing::trace!(addr = ?p.as_ptr(), "waking mpsc sender");
                    }

                    w.wake();
                }
            }

            #[cfg(test)]
            {
                tracing::trace!(addr = ?p.as_ptr(), "dropping receiving half of mpsc sender");
            }

            let t = RECEIVER_FLAG | if g.is_some() { LOCK_FLAG } else { 0 };
            forget(g);
            let t = r.lock.fetch_sub(t, Release);

            if t & SENDER_FLAG == 0 {
                // SAFETY: We're exclusively owns value.
                unsafe { SendOuter::drop_outer(p) };
            }
        }
    }

    fn wake_all_senders(&mut self) {
        while let Some(p) = self.ready.pop_front() {
            // SAFETY: Pointer points to valid allocation.
            let r = unsafe { p.as_ref() };

            #[cfg(test)]
            {
                tracing::trace!(addr = ?p.as_ptr(), "dropping receiving half of mpsc sender");
            }

            let mut g = r.try_lock().ok();
            if let Some(r) = &mut g
                && let Some(w) = r.waker.take()
            {
                w.wake();
            }

            let t = RECEIVER_FLAG | if g.is_some() { LOCK_FLAG } else { 0 };
            forget(g);
            let t = r.lock.fetch_sub(t, Release);

            if t & SENDER_FLAG == 0 {
                // SAFETY: We're exclusively owns value.
                unsafe { SendOuter::drop_outer(p) };
            }
        }
    }
}

struct RecvOuter<T: Sized> {
    inner: UnsafeCell<RecvInner<T>>,
    senders: AtomicUsize,
    lock: AtomicU8,
    _pinned: PhantomPinned,
}

struct SendOuter<T: Sized> {
    inner: UnsafeCell<SendInner<T>>,
    lock: AtomicU8,
    _pinned: PhantomPinned,
}

const SENDER_FLAG: u8 = 1;
const RECEIVER_FLAG: u8 = 2;
const LOCK_FLAG: u8 = 16;
const INIT_STATE: u8 = SENDER_FLAG | RECEIVER_FLAG;

impl<T: Sized> RecvOuter<T> {
    fn new(size: usize) -> NonNull<Self> {
        let layout: Layout = Layout::new::<Self>();
        // SAFETY: Layout is valid and never zero sized.
        let Some(ret) = NonNull::new(unsafe { alloc(layout) }.cast::<Self>()) else {
            handle_alloc_error(layout)
        };
        // SAFETY: Pointer points to uninitialized allocation.
        unsafe {
            write(
                ret.as_ptr(),
                Self {
                    senders: AtomicUsize::new(1),
                    lock: AtomicU8::new(INIT_STATE),
                    inner: UnsafeCell::new(RecvInner::new(size)),
                    _pinned: PhantomPinned,
                },
            );
        }

        #[cfg(test)]
        {
            trace!(addr = ?ret.as_ptr(), size, "creating new mpsc channel");
        }

        ret
    }

    fn try_lock(&self) -> Result<Guard<'_, RecvInner<T>>, u8> {
        #[cfg(test)]
        {
            trace!(addr = ?(self as *const Self), "locking mpsc channel");
        }

        let Err(t) =
            self.lock
                .compare_exchange(INIT_STATE, INIT_STATE | LOCK_FLAG, Acquire, Relaxed)
        else {
            // SAFETY: We locked value.
            return Ok(Guard(unsafe { &mut *self.inner.get() }, &self.lock));
        };

        assert!(
            t & LOCK_FLAG == 0,
            "Trying to lock channel twice. Please do not use channel with multi-threaded runtime."
        );

        Err(t)
    }

    fn lock(&self) -> Guard<'_, RecvInner<T>> {
        #[cfg(test)]
        {
            trace!(addr = ?(self as *const Self), "locking mpsc channel");
        }

        let t = self.lock.fetch_or(LOCK_FLAG, Acquire);

        assert!(
            t & LOCK_FLAG == 0,
            "Trying to lock channel twice. Please do not use channel with multi-threaded runtime."
        );

        // SAFETY: We locked value.
        Guard(unsafe { &mut *self.inner.get() }, &self.lock)
    }

    unsafe fn drop_outer(p: NonNull<Self>) {
        fence(Acquire);

        let p = p.as_ptr();

        #[cfg(test)]
        {
            tracing::trace!(
                addr = ?p, "dropping mpsc channel"
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

impl<T: Sized> SendOuter<T> {
    fn new() -> NonNull<Self> {
        let layout: Layout = Layout::new::<Self>();
        // SAFETY: Layout is valid and never zero sized.
        let Some(ret) = NonNull::new(unsafe { alloc(layout) }.cast::<Self>()) else {
            handle_alloc_error(layout)
        };
        // SAFETY: Pointer points to uninitialized allocation.
        unsafe {
            write(
                ret.as_ptr(),
                Self {
                    lock: AtomicU8::new(SENDER_FLAG),
                    inner: UnsafeCell::default(),
                    _pinned: PhantomPinned,
                },
            );
        }

        #[cfg(test)]
        {
            trace!(addr = ?ret.as_ptr(), "creating new mpsc sender");
        }

        ret
    }

    fn try_lock(&self) -> Result<Guard<'_, SendInner<T>>, u8> {
        #[cfg(test)]
        {
            trace!(addr = ?(self as *const Self), "locking mpsc sender");
        }

        let Err(t) =
            self.lock
                .compare_exchange(INIT_STATE, INIT_STATE | LOCK_FLAG, Acquire, Relaxed)
        else {
            // SAFETY: We locked value.
            return Ok(Guard(unsafe { &mut *self.inner.get() }, &self.lock));
        };

        assert!(
            t & LOCK_FLAG == 0,
            "Trying to lock channel twice. Please do not use channel with multi-threaded runtime."
        );

        Err(t)
    }

    unsafe fn drop_outer(p: NonNull<Self>) {
        fence(Acquire);

        let p = p.as_ptr();

        #[cfg(test)]
        {
            tracing::trace!(
                addr = ?p, "dropping mpsc sender"
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

struct Guard<'a, T: Sized>(&'a mut T, &'a AtomicU8);

impl<T: Sized> Drop for Guard<'_, T> {
    fn drop(&mut self) {
        #[cfg(test)]
        {
            trace!(addr = ?(self.0 as *const T), "unlocking value");
        }

        let t = self.1.fetch_sub(LOCK_FLAG, Release);
        debug_assert!(
            t & LOCK_FLAG != 0,
            "Flag {t:02x} does not contain lock flag. It's a double-free bug."
        );
    }
}

impl<T: Sized> Deref for Guard<'_, T> {
    type Target = T;

    fn deref(&self) -> &T {
        &*self.0
    }
}

impl<T: Sized> DerefMut for Guard<'_, T> {
    fn deref_mut(&mut self) -> &mut T {
        &mut *self.0
    }
}

/// Sending half of MPSC channel.
#[must_use]
#[pin_project(PinnedDrop, project = SenderProj)]
pub struct Sender<T: Sized> {
    inner: Option<SenderInner<T>>,
    #[pin]
    _phantom: PhantomData<(T, fn(T) -> T, PhantomPinned)>,
}

struct SenderInner<T: Sized> {
    p: NonNull<RecvOuter<T>>,
    s: NonNull<SendOuter<T>>,
}

/// Type for marking send error.
///
/// It's not defined what error it is.
/// Most likely reason is receiver disconnection.
/// But only for [`Sender::start_send`], it could also means the buffer is full.
#[derive(Clone)]
#[non_exhaustive]
pub struct SendError {}

impl Debug for SendError {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        write!(f, "SendError")
    }
}

impl Display for SendError {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        write!(f, "error sending data")
    }
}

impl Error for SendError {}

// SAFETY: Sender is send if T is send.
unsafe impl<T: Sized + Send> Send for Sender<T> {}
// SAFETY: Sender is sync if T is send.
unsafe impl<T: Sized + Send> Sync for Sender<T> {}

#[pinned_drop]
impl<T: Sized> PinnedDrop for Sender<T> {
    #[cfg_attr(test, instrument(level = "trace", name = "send_drop", skip_all))]
    fn drop(self: Pin<&mut Self>) {
        let SenderProj {
            inner: &mut Some(SenderInner { p, s }),
            ..
        } = self.project()
        else {
            return;
        };

        // SAFETY: Pointer points to valid allocation of outer.
        let r = unsafe { s.as_ref() };

        #[cfg(test)]
        {
            trace!(addr = ?s.as_ptr(), "dropping sending half of mpsc sender");
        }

        let t = r.lock.fetch_sub(SENDER_FLAG, Release);
        assert!(
            t & SENDER_FLAG != 0,
            "Flag {t:02x} does not contain sender flag. It's a double-free bug."
        );

        if t & RECEIVER_FLAG == 0 {
            // SAFETY: Pointer points to valid allocation and we're exclusively owns it.
            unsafe { SendOuter::drop_outer(s) };
        }

        // SAFETY: Pointer points to valid allocation of outer.
        let r = unsafe { p.as_ref() };

        #[cfg(test)]
        {
            trace!(addr = ?p.as_ptr(), "dropping sending half of mpsc channel");
        }

        let t = r.senders.fetch_sub(1, Relaxed);
        assert!(t != 0, "Too many senders dropped. It's a double-free bug.");
        if t == 1 {
            let mut g = r.try_lock().ok();
            if let Some(r) = &mut g
                && let Some(w) = r.waker.take()
            {
                w.wake();
            }

            let t = SENDER_FLAG | if g.is_some() { LOCK_FLAG } else { 0 };
            forget(g);
            let t = r.lock.fetch_sub(t, Release);
            assert!(
                t & SENDER_FLAG != 0,
                "Flag {t:02x} does not contain sender flag. It's a double-free bug."
            );

            if t & RECEIVER_FLAG == 0 {
                // SAFETY: Pointer points to valid allocation and we're exclusively owns it.
                unsafe { RecvOuter::drop_outer(p) };
            }
        }
    }
}

impl<T: Sized> Clone for Sender<T> {
    fn clone(&self) -> Self {
        Self {
            inner: if let Some(SenderInner { p, .. }) = self.inner {
                // SAFETY: Pointer points to valid allocation of outer.
                let r = unsafe { p.as_ref() };
                let t = r.senders.fetch_add(1, Relaxed);
                assert!(t != usize::MAX, "reference count overflow");
                Some(SenderInner {
                    p,
                    s: SendOuter::new(),
                })
            } else {
                None
            },
            _phantom: PhantomData,
        }
    }
}

impl<T: Sized> Debug for Sender<T> {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        f.debug_struct("Sender")
            .field("disconnected", &self.is_disconnected())
            .finish_non_exhaustive()
    }
}

impl<T: Sized> Sink<T> for Sender<T> {
    type Error = SendError;

    #[cfg_attr(test, instrument(level = "trace", skip_all))]
    fn poll_ready(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        let &SenderInner { p, s } = self.inner.as_ref().ok_or(SendError {})?;

        // SAFETY: Pointer points to valid allocation.
        let r = unsafe { s.as_ref() };

        let needs_register;
        {
            let mut g;
            let r = if let Ok(v) = r.try_lock() {
                g = v;
                needs_register = false;
                &mut *g
            } else {
                needs_register = true;
                // SAFETY: We exclusively owns value.
                unsafe { &mut *r.inner.get() }
            };

            if r.inner.is_none() {
                // SAFETY: Pointer points to valid allocation.
                let r = unsafe { p.as_ref() };

                return Poll::Ready(if r.lock.load(Relaxed) & RECEIVER_FLAG == 0 {
                    drop(Self {
                        inner: self.project().inner.take(),
                        _phantom: PhantomData,
                    });

                    Err(SendError {})
                } else {
                    Ok(())
                });
            }
            match r.waker {
                Some(ref mut w) => w.clone_from(cx.waker()),
                ref mut w @ None => *w = Some(cx.waker().clone()),
            }
        }

        if needs_register {
            #[cfg(test)]
            {
                trace!(addr = ?s.as_ptr(), "registering sender to mpsc channel");
            }

            // SAFETY: Pointer points to valid allocation.
            unsafe { s.as_ref().lock.fetch_add(RECEIVER_FLAG, Relaxed) };

            // SAFETY: Pointer points to valid allocation.
            let r = unsafe { p.as_ref() };

            let Ok(mut g) = r.try_lock() else {
                drop(Self {
                    inner: self.project().inner.take(),
                    _phantom: PhantomData,
                });

                return Poll::Ready(Err(SendError {}));
            };
            g.ready.push_back(s);
        }

        Poll::Pending
    }

    #[cfg_attr(test, instrument(level = "trace", skip_all))]
    fn start_send(self: Pin<&mut Self>, item: T) -> Result<(), Self::Error> {
        let &SenderInner { p, s } = self.inner.as_ref().ok_or(SendError {})?;

        // SAFETY: Pointer points to valid allocation.
        let r = unsafe { p.as_ref() };

        let Ok(mut g) = r.try_lock() else {
            drop(Self {
                inner: self.project().inner.take(),
                _phantom: PhantomData,
            });

            return Err(SendError {});
        };

        let Err(item) = g.push(item) else {
            if g.len == 1
                && let Some(w) = g.waker.take()
            {
                w.wake();
            }

            return Ok(());
        };

        // SAFETY: Pointer points to valid allocation.
        let r = unsafe { s.as_ref() };

        if r.lock
            .compare_exchange(SENDER_FLAG, SENDER_FLAG | RECEIVER_FLAG, Relaxed, Relaxed)
            .is_err()
        {
            // We're queueing for receiver already.
            return Err(SendError {});
        }

        // SAFETY: We're exclusively owns value.
        let r = unsafe { &mut *r.inner.get() };
        r.inner = Some(item);
        r.waker = None;

        g.ready.push_back(s);

        Ok(())
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.poll_ready(cx)
    }

    /// Closing sender.
    ///
    /// Unlike other methods, this will always succeed.
    /// This is to preserve it's idempotence.
    #[cfg_attr(test, instrument(level = "trace", skip_all))]
    fn poll_close(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        if self.as_mut().poll_ready(cx).is_ready() {
            drop(Self {
                inner: self.project().inner.take(),
                _phantom: PhantomData,
            });
            Poll::Ready(Ok(()))
        } else {
            Poll::Pending
        }
    }
}

impl<T: Sized> Sender<T> {
    /// Check if receiver has disconnected.
    ///
    /// Once receiver has disconnected, any further attempt at sending data will result in [`SendError`].
    /// Exception being [`Sender::poll_close`], which will always succeed.
    pub fn is_disconnected(&self) -> bool {
        let Some(SenderInner { p, .. }) = &self.inner else {
            return true;
        };
        // SAFETY: Pointer points to valid allocation of outer.
        let r = unsafe { p.as_ref() };
        r.lock.load(Relaxed) & RECEIVER_FLAG == 0
    }
}

/// Receiving half of SPSC channel.
#[must_use]
#[pin_project(PinnedDrop)]
pub struct Receiver<T: Sized> {
    p: Option<NonNull<RecvOuter<T>>>,
    #[pin]
    _phantom: PhantomData<(T, fn(T) -> T, PhantomPinned)>,
}

// SAFETY: Receiver is send if T is send.
unsafe impl<T: Sized + Send> Send for Receiver<T> {}
// SAFETY: Receiver is sync if T is send.
unsafe impl<T: Sized + Send> Sync for Receiver<T> {}

#[pinned_drop]
impl<T: Sized> PinnedDrop for Receiver<T> {
    #[cfg_attr(test, instrument(level = "trace", name = "recv_drop", skip_all))]
    fn drop(self: Pin<&mut Self>) {
        let Some(p) = *self.project().p else { return };
        // SAFETY: Pointer points to valid allocation of outer.
        let r = unsafe { p.as_ref() };

        let mut g = r.try_lock().ok();

        if let Some(g) = &mut g {
            g.wake_all_senders();
        }

        #[cfg(test)]
        {
            trace!(addr = ?p.as_ptr(), "dropping receiving half of mpsc channel");
        }

        let t = RECEIVER_FLAG | if g.is_some() { LOCK_FLAG } else { 0 };
        forget(g);
        let t = r.lock.fetch_sub(t, Release);
        assert!(
            t & RECEIVER_FLAG != 0,
            "Flag {t:02x} does not contain receiver flag. It's a double-free bug."
        );

        if t & SENDER_FLAG == 0 {
            // SAFETY: Pointer points to valid allocation and we're exclusively owns it.
            unsafe { RecvOuter::drop_outer(p) };
        }
    }
}

impl<T: Sized> Debug for Receiver<T> {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        f.debug_struct("Receiver")
            .field("disconnected", &self.is_disconnected())
            .finish_non_exhaustive()
    }
}

impl<T: Sized> Stream for Receiver<T> {
    type Item = T;

    #[cfg_attr(test, instrument(level = "trace", skip_all))]
    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let p_ = self.project().p;
        let Some(p) = *p_ else {
            return Poll::Ready(None);
        };
        // SAFETY: Pointer points to valid allocation of outer.
        let o = unsafe { &*p.as_ptr() };
        let mut g = o.lock();
        let r = &mut *g;

        loop {
            if let ret @ Some(_) = r.pop() {
                if o.lock.load(Relaxed) & SENDER_FLAG != 0 {
                    r.wake_sender();
                }

                return Poll::Ready(ret);
            } else if o.lock.load(Relaxed) & SENDER_FLAG != 0 {
                r.wake_sender();
                if r.len == 0 {
                    break;
                }
            } else {
                break;
            }
        }

        if o.lock.load(Relaxed) & SENDER_FLAG == 0 {
            drop(g);
            *p_ = None;
            drop(Receiver {
                p: Some(p),
                _phantom: PhantomData,
            });
            return Poll::Ready(None);
        }

        match r.waker {
            Some(ref mut w) => w.clone_from(cx.waker()),
            ref mut w @ None => *w = Some(cx.waker().clone()),
        }

        Poll::Pending
    }
}

impl<T: Sized> Receiver<T> {
    /// Check if sender has disconnected.
    ///
    /// NOTE: There might be data still in transit.
    pub fn is_disconnected(&self) -> bool {
        let Some(p) = self.p else { return true };
        // SAFETY: Pointer points to valid allocation of outer.
        let r = unsafe { p.as_ref() };
        r.lock.load(Relaxed) & SENDER_FLAG == 0
    }
}

/// Create new MPSC channel.
///
/// NOTE: `size` cannot be zero.
#[cfg_attr(test, instrument(level = "trace"))]
pub fn make_channel<T: Sized>(size: usize) -> (Sender<T>, Receiver<T>) {
    assert!(size > 0, "size is 0");
    let p = RecvOuter::<T>::new(size);
    (
        Sender {
            inner: Some(SenderInner {
                p,
                s: SendOuter::new(),
            }),
            _phantom: PhantomData,
        },
        Receiver {
            p: Some(p),
            _phantom: PhantomData,
        },
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::assert_matches;
    use std::hint::black_box;
    use std::pin::pin;

    use futures_util::{SinkExt, StreamExt};
    use test_log::test;
    use tracing::{info, instrument};

    use crate::rt::Executor;
    use crate::utils::{get_drop_cnt, reset_drop_cnt, run_test};
    use crate::waker::{MultiWaker, Selector};

    #[test]
    fn test_mpsc_create() {
        #[instrument]
        fn test() {
            reset_drop_cnt();
            let _ = black_box(make_channel::<Box<u32>>(1));
            assert_eq!(get_drop_cnt(), 2, "drop count mismatch");
        }

        run_test(test);
    }

    #[test]
    fn test_mpsc_send() {
        #[instrument]
        fn test() {
            reset_drop_cnt();

            let waker = MultiWaker::new(Selector::default());

            {
                let w = waker.make_waker(0);
                let mut cx = Context::from_waker(&w);
                let (send, recv) = make_channel::<u32>(1);
                let mut send = pin!(send);
                let mut recv = pin!(recv);

                info!("sending data");
                assert_eq!(waker.take_flags(false), 0);
                assert_matches!(send.as_mut().poll_ready(&mut cx), Poll::Ready(Ok(())));
                assert_eq!(waker.take_flags(false), 0);
                assert_matches!(send.as_mut().start_send(1), Ok(()));
                assert_matches!(send.as_mut().poll_ready(&mut cx), Poll::Ready(Ok(())));
                assert_eq!(waker.take_flags(false), 0);
                assert_matches!(send.as_mut().start_send(2), Ok(()));
                assert_matches!(send.as_mut().poll_ready(&mut cx), Poll::Pending);
                assert_eq!(waker.take_flags(false), 0);

                info!("receiving data");
                assert_eq!(recv.as_mut().poll_next(&mut cx), Poll::Ready(Some(1)));
                assert_eq!(waker.take_flags(false), 1);
                assert_eq!(recv.as_mut().poll_next(&mut cx), Poll::Ready(Some(2)));
                assert_eq!(waker.take_flags(false), 0);
                assert_eq!(recv.as_mut().poll_next(&mut cx), Poll::Pending);
                assert_eq!(waker.take_flags(false), 0);

                info!("closing sender");
                assert_matches!(send.as_mut().poll_close(&mut cx), Poll::Ready(Ok(())));
                assert_eq!(waker.take_flags(false), 1);
                assert_eq!(recv.as_mut().poll_next(&mut cx), Poll::Ready(None));
                assert_eq!(waker.take_flags(false), 0);
            }

            assert_eq!(get_drop_cnt(), 2, "drop count mismatch");
        }

        run_test(test);
    }

    #[test]
    fn test_mpsc_send_close_first() {
        #[instrument]
        fn test() {
            reset_drop_cnt();

            let waker = MultiWaker::new(Selector::default());

            {
                let w = waker.make_waker(0);
                let mut cx = Context::from_waker(&w);
                let (send, recv) = make_channel::<u32>(1);
                let mut send = pin!(send);
                let mut recv = pin!(recv);

                info!("sending data");
                assert_eq!(waker.take_flags(false), 0);
                assert_matches!(send.as_mut().poll_ready(&mut cx), Poll::Ready(Ok(())));
                assert_eq!(waker.take_flags(false), 0);
                assert_matches!(send.as_mut().start_send(1), Ok(()));
                assert_matches!(send.as_mut().poll_ready(&mut cx), Poll::Ready(Ok(())));
                assert_eq!(waker.take_flags(false), 0);
                assert_matches!(send.as_mut().start_send(2), Ok(()));
                assert_matches!(send.as_mut().poll_ready(&mut cx), Poll::Pending);
                assert_eq!(waker.take_flags(false), 0);

                info!("closing sender");
                assert_eq!(send.is_disconnected(), false);
                assert_eq!(recv.is_disconnected(), false);
                assert_matches!(send.as_mut().poll_close(&mut cx), Poll::Pending);
                assert_eq!(waker.take_flags(false), 0);

                info!("receiving data");
                assert_eq!(recv.as_mut().poll_next(&mut cx), Poll::Ready(Some(1)));
                assert_eq!(waker.take_flags(false), 1);

                info!("closing sender");
                assert_matches!(send.as_mut().poll_close(&mut cx), Poll::Ready(Ok(())));
                assert_eq!(waker.take_flags(false), 0);
                assert_eq!(send.is_disconnected(), true);
                assert_eq!(recv.is_disconnected(), true);

                info!("receiving data");
                assert_eq!(recv.as_mut().poll_next(&mut cx), Poll::Ready(Some(2)));
                assert_eq!(waker.take_flags(false), 0);
            }

            assert_eq!(get_drop_cnt(), 2, "drop count mismatch");
        }

        run_test(test);
    }

    #[test]
    fn test_mpsc_recv_drop() {
        #[instrument]
        fn test() {
            reset_drop_cnt();

            let waker = MultiWaker::new(Selector::default());

            {
                let w = waker.make_waker(0);
                let mut cx = Context::from_waker(&w);
                let (send, recv) = make_channel::<u32>(2);
                let mut send = pin!(send);

                info!("sending data");
                assert_eq!(waker.take_flags(false), 0);
                assert_matches!(send.as_mut().poll_ready(&mut cx), Poll::Ready(Ok(())));
                assert_eq!(waker.take_flags(false), 0);
                assert_matches!(send.as_mut().start_send(1), Ok(()));
                assert_matches!(send.as_mut().poll_ready(&mut cx), Poll::Ready(Ok(())));
                assert_eq!(waker.take_flags(false), 0);

                assert_eq!(send.is_disconnected(), false);
                assert_eq!(recv.is_disconnected(), false);
                {
                    let mut recv = pin!(recv);
                    info!("receiving data");
                    assert_eq!(recv.as_mut().poll_next(&mut cx), Poll::Ready(Some(1)));
                    assert_eq!(waker.take_flags(false), 0);
                    assert_eq!(recv.as_mut().poll_next(&mut cx), Poll::Pending);
                    assert_eq!(waker.take_flags(false), 0);
                }
                assert_eq!(send.is_disconnected(), true);

                info!("trying to send data");
                assert_matches!(send.as_mut().poll_ready(&mut cx), Poll::Ready(Err(_)));
                assert_eq!(waker.take_flags(false), 0);
            }

            assert_eq!(get_drop_cnt(), 2, "drop count mismatch");
        }

        run_test(test);
    }

    #[test]
    fn test_mpsc_send_many() {
        #[instrument]
        fn test() {
            reset_drop_cnt();

            let waker = MultiWaker::new(Selector::default());

            {
                let w = waker.make_waker(0);
                let mut cx = Context::from_waker(&w);
                let (send, recv) = make_channel::<u32>(1);
                let mut send = pin!(send);
                let mut recv = pin!(recv);

                info!("sending data");
                assert_eq!(waker.take_flags(false), 0);
                assert_matches!(send.as_mut().poll_ready(&mut cx), Poll::Ready(Ok(())));
                assert_eq!(waker.take_flags(false), 0);
                assert_matches!(send.as_mut().start_send(1), Ok(()));
                assert_matches!(send.as_mut().poll_ready(&mut cx), Poll::Ready(Ok(())));
                assert_eq!(waker.take_flags(false), 0);
                assert_matches!(send.as_mut().start_send(2), Ok(()));
                assert_matches!(send.as_mut().poll_ready(&mut cx), Poll::Pending);
                assert_eq!(waker.take_flags(false), 0);

                info!("receiving data");
                assert_eq!(recv.as_mut().poll_next(&mut cx), Poll::Ready(Some(1)));
                assert_eq!(waker.take_flags(false), 1);
                assert_eq!(recv.as_mut().poll_next(&mut cx), Poll::Ready(Some(2)));
                assert_eq!(waker.take_flags(false), 0);
                assert_eq!(recv.as_mut().poll_next(&mut cx), Poll::Pending);
                assert_eq!(waker.take_flags(false), 0);

                info!("closing sender");
                assert_matches!(send.as_mut().poll_close(&mut cx), Poll::Ready(Ok(())));
                assert_eq!(waker.take_flags(false), 1);
                assert_eq!(recv.as_mut().poll_next(&mut cx), Poll::Ready(None));
                assert_eq!(waker.take_flags(false), 0);
            }

            assert_eq!(get_drop_cnt(), 2, "drop count mismatch");
        }

        run_test(test);
    }

    #[test]
    fn test_mpsc_send_many_sender() {
        #[instrument]
        fn test() {
            reset_drop_cnt();

            let waker = MultiWaker::new(Selector::default());

            {
                let w = waker.make_waker(0);
                let mut cx = Context::from_waker(&w);
                let w = waker.make_waker(1);
                let mut cx2 = Context::from_waker(&w);
                let w = waker.make_waker(2);
                let mut cx3 = Context::from_waker(&w);
                let (send, recv) = make_channel::<u32>(2);
                let mut send2 = pin!(send.clone());
                let mut send = pin!(send);
                let mut recv = pin!(recv);

                info!("sending data");
                assert_eq!(waker.take_flags(false), 0);
                assert_matches!(send.as_mut().poll_ready(&mut cx), Poll::Ready(Ok(())));
                assert_eq!(waker.take_flags(false), 0);
                assert_matches!(send.as_mut().start_send(1), Ok(()));
                assert_matches!(send2.as_mut().poll_ready(&mut cx2), Poll::Ready(Ok(())));
                assert_eq!(waker.take_flags(false), 0);
                assert_matches!(send2.as_mut().start_send(2), Ok(()));
                assert_matches!(send.as_mut().poll_ready(&mut cx), Poll::Ready(Ok(())));
                assert_eq!(waker.take_flags(false), 0);
                assert_matches!(send.as_mut().start_send(3), Ok(()));
                assert_matches!(send.as_mut().poll_ready(&mut cx), Poll::Pending);
                assert_eq!(waker.take_flags(false), 0);
                assert_matches!(send2.as_mut().poll_ready(&mut cx2), Poll::Ready(Ok(())));
                assert_eq!(waker.take_flags(false), 0);
                assert_matches!(send2.as_mut().start_send(4), Ok(()));
                assert_matches!(send2.as_mut().poll_ready(&mut cx2), Poll::Pending);
                assert_eq!(waker.take_flags(false), 0);

                info!("receiving data");
                assert_eq!(recv.as_mut().poll_next(&mut cx3), Poll::Ready(Some(1)));
                assert_eq!(waker.take_flags(false), 1);
                assert_eq!(recv.as_mut().poll_next(&mut cx3), Poll::Ready(Some(2)));
                assert_eq!(waker.take_flags(false), 2);
                assert_eq!(recv.as_mut().poll_next(&mut cx3), Poll::Ready(Some(3)));
                assert_eq!(waker.take_flags(false), 0);
                assert_eq!(recv.as_mut().poll_next(&mut cx3), Poll::Ready(Some(4)));
                assert_eq!(waker.take_flags(false), 0);
                assert_eq!(recv.as_mut().poll_next(&mut cx3), Poll::Pending);
                assert_eq!(waker.take_flags(false), 0);

                info!("closing sender");
                assert_matches!(send.as_mut().poll_close(&mut cx), Poll::Ready(Ok(())));
                assert_matches!(send2.as_mut().poll_close(&mut cx2), Poll::Ready(Ok(())));
                assert_eq!(waker.take_flags(false), 4);
                assert_eq!(recv.as_mut().poll_next(&mut cx), Poll::Ready(None));
                assert_eq!(waker.take_flags(false), 0);
            }

            assert_eq!(get_drop_cnt(), 3, "drop count mismatch");
        }

        run_test(test);
    }

    #[test]
    fn test_mpsc_send_async() {
        #[instrument]
        fn test(register_send_first: bool) {
            reset_drop_cnt();

            let mut executor = Executor::builder().build();
            let rt = executor.runtime();
            let (send, recv) = make_channel::<u32>(1);

            #[instrument]
            async fn send_task(send: Sender<u32>) {
                let mut send = pin!(send);
                info!("sending data");
                send.feed(1).await.unwrap();
                info!("closing sender");
                send.close().await.unwrap();
            }

            #[instrument]
            async fn recv_task(recv: Receiver<u32>) {
                let mut recv = pin!(recv);
                info!("receiving data");
                assert_eq!(recv.next().await, Some(1));
                assert_eq!(recv.next().await, None);
            }

            if register_send_first {
                rt.spawn(send_task(send));
                rt.spawn(recv_task(recv));
            } else {
                rt.spawn(recv_task(recv));
                rt.spawn(send_task(send));
            }

            executor.run();

            assert_eq!(get_drop_cnt(), 4, "drop count mismatch");
        }

        run_test(|| {
            test(false);
            test(true);
        });
    }

    #[test]
    fn test_mpsc_send_many_async() {
        #[instrument]
        fn test(register_send_first: bool) {
            reset_drop_cnt();

            let mut executor = Executor::builder().build();
            let rt = executor.runtime();
            let (send, recv) = make_channel::<u32>(4);

            #[instrument(skip_all)]
            async fn send_task(send: Sender<u32>) {
                let mut send = pin!(send);
                info!("sending data");
                for i in 0..10 {
                    send.feed(i).await.unwrap();
                }
                info!("closing sender");
                send.close().await.unwrap();
            }

            #[instrument(skip_all)]
            async fn recv_task(recv: Receiver<u32>) {
                let mut recv = pin!(recv);
                info!("receiving data");
                for i in 0..10 {
                    assert_eq!(recv.next().await, Some(i));
                }
                assert_eq!(recv.next().await, None);
            }

            if register_send_first {
                rt.spawn(send_task(send));
                rt.spawn(recv_task(recv));
            } else {
                rt.spawn(recv_task(recv));
                rt.spawn(send_task(send));
            }

            executor.run();

            assert_eq!(get_drop_cnt(), 4, "drop count mismatch");
        }

        run_test(|| {
            test(false);
            test(true);
        });
    }

    #[test]
    fn test_mpsc_send_many_sender_async() {
        #[instrument]
        fn test() {
            reset_drop_cnt();

            let mut executor = Executor::builder().build();
            let rt = executor.runtime();
            let (send, recv) = make_channel::<(usize, u32)>(4);

            #[instrument(skip(send))]
            async fn send_task(send: Sender<(usize, u32)>, index: usize) {
                let mut send = pin!(send);
                info!("sending data");
                for i in 0..10 {
                    info!("sending ({index}, {i})");
                    send.feed((index, i)).await.unwrap();
                }
                info!("closing sender");
                send.close().await.unwrap();
            }

            #[instrument(skip_all)]
            async fn recv_task(recv: Receiver<(usize, u32)>) {
                let mut recv = pin!(recv);
                let mut v = vec![0; 10];
                info!("receiving data");
                while !v.iter().all(|t| *t >= 10) {
                    let (i, r) = recv.next().await.expect("sender should not be closed");
                    info!("received ({i}, {r})");
                    assert_eq!(r, v[i], "mismatch at index {i}");
                    v[i] += 1;
                }
                assert_eq!(recv.next().await, None);
            }

            for i in 0..10 {
                rt.spawn(send_task(send.clone(), i));
            }
            rt.spawn(recv_task(recv));
            drop(send);

            executor.run();

            assert_eq!(get_drop_cnt(), 23, "drop count mismatch");
        }

        run_test(test);
    }
}
