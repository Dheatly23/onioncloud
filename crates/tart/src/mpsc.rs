use std::alloc::{Layout, alloc, dealloc, handle_alloc_error};
use std::cell::UnsafeCell;
use std::error::Error;
use std::fmt::{Debug, Display, Formatter, Result as FmtResult};
use std::marker::{PhantomData, PhantomPinned};
use std::mem::{MaybeUninit, forget, take};
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

struct Inner<T: Sized> {
    buf: Box<[MaybeUninit<T>]>,
    off: usize,
    len: usize,
    ready_generation: u64,
    ready_wakers: Vec<Option<Waker>>,
    flush_generation: u64,
    flush_wakers: Vec<Option<Waker>>,
    recv_waker: Option<Waker>,
}

impl<T: Sized> Drop for Inner<T> {
    fn drop(&mut self) {
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

impl<T: Sized> Inner<T> {
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
}

struct Outer<T: Sized> {
    senders: AtomicUsize,
    lock: AtomicU8,
    inner: UnsafeCell<Inner<T>>,
    _pinned: PhantomPinned,
}

const SENDER_FLAG: u8 = 1;
const RECEIVER_FLAG: u8 = 4;
const LOCK_FLAG: u8 = 16;
const INIT_STATE: u8 = SENDER_FLAG | RECEIVER_FLAG | 2 | 8;

impl<T: Sized> Outer<T> {
    fn new(size: usize) -> NonNull<Self> {
        let inner = Inner {
            buf: Box::new_uninit_slice(size),
            off: 0,
            len: 0,
            ready_generation: 0,
            ready_wakers: Vec::new(),
            flush_generation: 0,
            flush_wakers: Vec::new(),
            recv_waker: None,
        };

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
                    inner: UnsafeCell::new(inner),
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

    fn try_lock(&self) -> Result<Guard<'_, T>, u8> {
        #[cfg(test)]
        {
            trace!(addr = ?(self as *const Self), "locking mpsc channel");
        }

        let Err(t) =
            self.lock
                .compare_exchange(INIT_STATE, INIT_STATE | LOCK_FLAG, Acquire, Relaxed)
        else {
            return Ok(Guard(self));
        };

        assert!(
            t & LOCK_FLAG == 0,
            "Trying to lock channel twice. Please do not use channel with multi-threaded runtime."
        );
        assert!(t & (2 | 8) == (2 | 8), "invalid lock state");

        Err(t)
    }

    fn lock(&self) -> Guard<'_, T> {
        #[cfg(test)]
        {
            trace!(addr = ?(self as *const Self), "locking mpsc channel");
        }

        let t = self.lock.fetch_or(LOCK_FLAG, Acquire);

        assert!(
            t & LOCK_FLAG == 0,
            "Trying to lock channel twice. Please do not use channel with multi-threaded runtime."
        );
        assert!(t & (2 | 8) == (2 | 8), "invalid lock state");

        Guard(self)
    }
}

unsafe fn drop_outer<T: Sized>(p: NonNull<Outer<T>>) {
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

struct Guard<'a, T: Sized>(&'a Outer<T>);

impl<T: Sized> Drop for Guard<'_, T> {
    fn drop(&mut self) {
        #[cfg(test)]
        {
            trace!(addr = ?(self.0 as *const Outer<T>), "unlocking mpsc channel");
        }

        let t = self.0.lock.fetch_sub(LOCK_FLAG, Release);
        debug_assert!(
            t & LOCK_FLAG != 0,
            "Flag {t:02x} does not contain lock flag. It's a double-free bug."
        );
    }
}

impl<T: Sized> Deref for Guard<'_, T> {
    type Target = Inner<T>;

    fn deref(&self) -> &Inner<T> {
        // SAFETY: We locked outer.
        unsafe { &*self.0.inner.get() }
    }
}

impl<T: Sized> DerefMut for Guard<'_, T> {
    fn deref_mut(&mut self) -> &mut Inner<T> {
        // SAFETY: We locked outer.
        unsafe { &mut *self.0.inner.get() }
    }
}

/// Sending half of SPSC channel.
#[must_use]
#[pin_project(PinnedDrop, project = SenderProj)]
pub struct Sender<T: Sized> {
    p: Option<NonNull<Outer<T>>>,
    inner: SenderInner,
    #[pin]
    _phantom: PhantomData<(*mut T, PhantomPinned)>,
}

#[derive(Clone, Copy)]
struct SenderInner {
    rt: u64,
    ri: usize,
    ft: u64,
    fi: usize,
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
            p: &mut Some(p),
            inner: &mut SenderInner { rt, ri, ft, fi },
            ..
        } = self.project()
        else {
            return;
        };
        // SAFETY: Pointer points to valid allocation of outer.
        let r = unsafe { p.as_ref() };

        #[cfg(test)]
        {
            trace!(addr = ?p.as_ptr(), "dropping sending half of mpsc channel");
        }

        let mut g = r.try_lock().ok();
        if let Some(g) = &mut g {
            if rt == g.ready_generation
                && let Some(w) = g.ready_wakers.get_mut(ri)
            {
                *w = None;
            }
            if ft == g.flush_generation
                && let Some(w) = g.flush_wakers.get_mut(fi)
            {
                *w = None;
            }
        }

        let t = r.senders.fetch_sub(1, Relaxed);
        assert!(t != 0, "Too many senders dropped. It's a double-free bug.");
        if t != 1 {
            return;
        }

        if let Some(g) = &mut g
            && let Some(w) = take(&mut g.recv_waker)
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
            unsafe { drop_outer(p) };
        }
    }
}

impl<T: Sized> Clone for Sender<T> {
    fn clone(&self) -> Self {
        if let Some(p) = self.p {
            // SAFETY: Pointer points to valid allocation of outer.
            let r = unsafe { p.as_ref() };
            let t = r.senders.fetch_add(1, Relaxed);
            assert!(t != usize::MAX, "reference count overflow");
        }

        Self {
            p: self.p,
            inner: SenderInner {
                rt: self.inner.rt,
                ri: usize::MAX,
                ft: self.inner.ft,
                fi: usize::MAX,
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
        let (mut g, inner) = self.lock().ok_or(SendError {})?;
        let r = &mut *g;

        if r.len < r.buf.len() {
            return Poll::Ready(Ok(()));
        }

        if inner.rt == r.ready_generation {
            match r.ready_wakers.get_mut(inner.ri) {
                Some(Some(w)) => w.clone_from(cx.waker()),
                Some(w @ None) => *w = Some(cx.waker().clone()),
                None => {
                    r.ready_wakers.push(Some(cx.waker().clone()));
                    inner.ri = r.ready_wakers.len();
                }
            }
        } else {
            r.ready_wakers.push(Some(cx.waker().clone()));
            inner.ri = r.ready_wakers.len();
            inner.rt = r.ready_generation;
        }

        Poll::Pending
    }

    #[cfg_attr(test, instrument(level = "trace", skip_all))]
    fn start_send(self: Pin<&mut Self>, item: T) -> Result<(), Self::Error> {
        let mut g = self.lock().ok_or(SendError {})?.0;
        let r = &mut *g;

        if r.push(item).is_err() {
            return Err(SendError {});
        } else if r.len == 1
            && let Some(w) = r.recv_waker.take()
        {
            w.wake();
        }
        Ok(())
    }

    #[cfg_attr(test, instrument(level = "trace", skip_all))]
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        let (mut g, inner) = self.lock().ok_or(SendError {})?;
        let r = &mut *g;

        if r.len == 0 {
            return Poll::Ready(Ok(()));
        }

        if inner.ft == r.flush_generation {
            match r.flush_wakers.get_mut(inner.fi) {
                Some(Some(w)) => w.clone_from(cx.waker()),
                Some(w @ None) => *w = Some(cx.waker().clone()),
                None => {
                    r.flush_wakers.push(Some(cx.waker().clone()));
                    inner.fi = r.flush_wakers.len();
                }
            }
        } else {
            r.flush_wakers.push(Some(cx.waker().clone()));
            inner.fi = r.flush_wakers.len();
            inner.ft = r.flush_generation;
        }

        Poll::Pending
    }

    /// Closing sender.
    ///
    /// Unlike other methods, this will always succeed.
    /// This is to preserve it's idempotence.
    #[cfg_attr(test, instrument(level = "trace", skip_all))]
    fn poll_close(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        let this = self.project();
        drop(Self {
            p: this.p.take(),
            inner: *this.inner,
            _phantom: PhantomData,
        });

        Poll::Ready(Ok(()))
    }
}

impl<T: Sized> Sender<T> {
    fn lock(self: Pin<&mut Self>) -> Option<(Guard<'_, T>, &mut SenderInner)> {
        let SenderProj { p: p_, inner, .. } = self.project();
        let p = (*p_)?;
        // SAFETY: Pointer points to valid allocation of outer.
        let o = unsafe { p.as_ref() };

        match o.try_lock() {
            Ok(v) => return Some((v, inner)),
            Err(t) if t & RECEIVER_FLAG != 0 => return None,
            Err(_) => (),
        }

        *p_ = None;

        let t = o.senders.fetch_sub(1, Relaxed);
        if t != 1 {
            return None;
        }

        let t = o.lock.fetch_sub(SENDER_FLAG, Release);
        assert!(
            t & RECEIVER_FLAG == 0,
            "Flag {t:02x} contains receiver flag. It's a double-free bug."
        );

        // SAFETY: Pointer points to valid allocation and we're exclusively owns it.
        unsafe { drop_outer(p) };

        None
    }

    /// Check if receiver has disconnected.
    ///
    /// Once receiver has disconnected, any further attempt at sending data will result in [`SendError`].
    /// Exception being [`Sender::poll_close`], which will always succeed.
    pub fn is_disconnected(&self) -> bool {
        let Some(p) = self.p else { return true };
        // SAFETY: Pointer points to valid allocation of outer.
        let r = unsafe { p.as_ref() };
        r.lock.load(Relaxed) & RECEIVER_FLAG == 0
    }
}

/// Receiving half of SPSC channel.
#[must_use]
#[pin_project(PinnedDrop)]
pub struct Receiver<T: Sized> {
    p: Option<NonNull<Outer<T>>>,
    #[pin]
    _phantom: PhantomData<(*mut T, PhantomPinned)>,
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
            g.ready_generation += 1;
            g.flush_generation += 1;
            g.recv_waker = None;
            while let Some(w) = g.ready_wakers.pop() {
                if let Some(w) = w {
                    w.wake();
                }
            }
            while let Some(w) = g.flush_wakers.pop() {
                if let Some(w) = w {
                    w.wake();
                }
            }
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
            unsafe { drop_outer(p) };
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

        if let ret @ Some(_) = r.pop() {
            if o.lock.load(Relaxed) & SENDER_FLAG != 0 {
                r.ready_generation += 1;
                while let Some(w) = r.ready_wakers.pop() {
                    if let Some(w) = w {
                        w.wake();
                    }
                }

                if r.len == 0 {
                    r.flush_generation += 1;
                    while let Some(w) = r.flush_wakers.pop() {
                        if let Some(w) = w {
                            w.wake();
                        }
                    }
                }
            }

            return Poll::Ready(ret);
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

        match r.recv_waker {
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

/// Create new SPSC channel.
///
/// NOTE: `size` cannot be zero.
#[cfg_attr(test, instrument(level = "trace"))]
pub fn make_channel<T: Sized>(size: usize) -> (Sender<T>, Receiver<T>) {
    assert!(size > 0, "size is 0");
    let p = Some(Outer::<T>::new(size));
    (
        Sender {
            p,
            inner: SenderInner {
                rt: 0,
                ri: usize::MAX,
                ft: 0,
                fi: usize::MAX,
            },
            _phantom: PhantomData,
        },
        Receiver {
            p,
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
            assert_eq!(get_drop_cnt(), 1, "drop count mismatch");
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
                assert_matches!(send.as_mut().poll_ready(&mut cx), Poll::Pending);
                assert_eq!(waker.take_flags(false), 0);

                info!("receiving data");
                assert_eq!(recv.as_mut().poll_next(&mut cx), Poll::Ready(Some(1)));
                assert_eq!(waker.take_flags(false), 1);
                assert_eq!(recv.as_mut().poll_next(&mut cx), Poll::Pending);
                assert_eq!(waker.take_flags(false), 0);

                info!("closing sender");
                assert_matches!(send.as_mut().poll_close(&mut cx), Poll::Ready(Ok(())));
                assert_eq!(waker.take_flags(false), 1);
                assert_eq!(recv.as_mut().poll_next(&mut cx), Poll::Ready(None));
                assert_eq!(waker.take_flags(false), 0);
            }

            assert_eq!(get_drop_cnt(), 1, "drop count mismatch");
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
                assert_matches!(send.as_mut().poll_ready(&mut cx), Poll::Pending);
                assert_eq!(waker.take_flags(false), 0);

                info!("closing sender");
                assert_eq!(send.is_disconnected(), false);
                assert_eq!(recv.is_disconnected(), false);
                assert_matches!(send.as_mut().poll_close(&mut cx), Poll::Ready(Ok(())));
                assert_eq!(waker.take_flags(false), 0);
                assert_eq!(send.is_disconnected(), true);
                assert_eq!(recv.is_disconnected(), true);

                info!("receiving data");
                assert_eq!(recv.as_mut().poll_next(&mut cx), Poll::Ready(Some(1)));
                assert_eq!(waker.take_flags(false), 0);
                assert_eq!(recv.as_mut().poll_next(&mut cx), Poll::Ready(None));
                assert_eq!(waker.take_flags(false), 0);
            }

            assert_eq!(get_drop_cnt(), 1, "drop count mismatch");
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

            assert_eq!(get_drop_cnt(), 1, "drop count mismatch");
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
                let (send, recv) = make_channel::<u32>(2);
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

            assert_eq!(get_drop_cnt(), 1, "drop count mismatch");
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

            assert_eq!(get_drop_cnt(), 3, "drop count mismatch");
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

            #[instrument]
            async fn send_task(send: Sender<u32>) {
                let mut send = pin!(send);
                info!("sending data");
                for i in 0..10 {
                    send.feed(i).await.unwrap();
                }
                info!("closing sender");
                send.close().await.unwrap();
            }

            #[instrument]
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

            assert_eq!(get_drop_cnt(), 3, "drop count mismatch");
        }

        run_test(|| {
            test(false);
            test(true);
        });
    }
}
