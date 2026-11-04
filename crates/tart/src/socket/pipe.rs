//! Simple FIFO pipes.

use std::alloc::{Layout, alloc, dealloc, handle_alloc_error};
use std::cell::UnsafeCell;
use std::cmp::Ordering::*;
use std::fmt::{Debug, Formatter, Result as FmtResult};
use std::io::{ErrorKind, IoSlice, IoSliceMut, Result as IoResult};
use std::marker::PhantomPinned;
use std::mem::{align_of, take};
use std::ops::{Deref, DerefMut};
use std::pin::Pin;
use std::ptr::{NonNull, drop_in_place, write};
use std::sync::atomic::{AtomicU8, Ordering::*, fence};
use std::task::Poll::*;
use std::task::{Context, Poll, Waker, ready};

use futures_util::{AsyncRead, AsyncWrite};
use tracing::{instrument, trace};

use crate::rt::Runtime;

struct InnerHalf {
    buf: [u8; 256],
    start: u8,
    end: u8,
    closed: bool,

    rw_waker: RWWaker,
    flush_waker: Option<Waker>,
}

#[derive(Default)]
enum RWWaker {
    #[default]
    None,
    Read(Waker),
    Write(Waker),
}

impl InnerHalf {
    const fn new() -> Self {
        Self {
            buf: [0; 256],
            start: 0,
            end: 0,
            closed: false,

            rw_waker: RWWaker::None,
            flush_waker: None,
        }
    }

    #[instrument(level = "trace", name = "InnerHalf::read", skip_all, fields(len = buf.len()))]
    fn read(&mut self, cx: &mut Context<'_>, buf: &mut [u8]) -> Poll<usize> {
        if buf.is_empty() {
            return Ready(0);
        }

        let n = match self.start.cmp(&self.end) {
            Equal if self.closed => return Ready(0),
            Equal => {
                trace!("Register read waker.");
                match &mut self.rw_waker {
                    RWWaker::Read(w) => w.clone_from(cx.waker()),
                    v => *v = RWWaker::Read(cx.waker().clone()),
                }
                return Pending;
            }
            Less => {
                let l = usize::from(self.end - self.start).min(buf.len());
                buf[..l].copy_from_slice(&self.buf[self.start as usize..self.start as usize + l]);
                self.start += l as u8;
                l
            }
            Greater => {
                let l1 = self.buf.len() - self.start as usize;
                if l1 >= buf.len() {
                    buf.copy_from_slice(
                        &self.buf[self.start as usize..self.start as usize + buf.len()],
                    );
                    self.start = self.start.wrapping_add(buf.len() as u8);
                    buf.len()
                } else {
                    let (a, b) = buf.split_at_mut(l1);
                    a.copy_from_slice(&self.buf[self.start as usize..]);
                    let l2 = usize::from(self.end).min(b.len());
                    b[..l2].copy_from_slice(&self.buf[..l2]);
                    self.start = l2 as u8;
                    l1 + l2
                }
            }
        };

        debug_assert!(n > 0, "read 0 bytes");
        trace!("Read {n} bytes.");

        if let RWWaker::Write(w) = take(&mut self.rw_waker) {
            trace!("Wake write waker.");
            w.wake();
        }
        if self.start == self.end
            && let Some(w) = self.flush_waker.take()
        {
            trace!("Wake flush waker.");
            w.wake();
        }

        Ready(n)
    }

    fn poll_read(&mut self, cx: &mut Context<'_>, buf: &mut [u8]) -> Poll<IoResult<usize>> {
        match self.read(cx, buf) {
            Pending => Pending,
            Ready(v) => Ready(Ok(v)),
        }
    }

    fn poll_read_vectored(
        &mut self,
        cx: &mut Context<'_>,
        bufs: &mut [IoSliceMut<'_>],
    ) -> Poll<IoResult<usize>> {
        let mut n = 0;
        for b in bufs {
            if b.is_empty() {
                continue;
            }
            n += ready!(self.read(cx, b));
            if self.start == self.end {
                break;
            }
        }
        Ready(Ok(n))
    }

    #[instrument(level = "trace", name = "InnerHalf::write", skip_all, fields(len = buf.len()))]
    fn write(&mut self, cx: &mut Context<'_>, buf: &[u8]) -> Poll<usize> {
        if buf.is_empty() {
            return Ready(0);
        }

        let start = self.start.wrapping_sub(1);
        let n = match start.cmp(&self.end) {
            Equal => {
                trace!("Register write waker.");
                match &mut self.rw_waker {
                    RWWaker::Write(w) => w.clone_from(cx.waker()),
                    v => *v = RWWaker::Write(cx.waker().clone()),
                }
                return Pending;
            }
            Greater => {
                let l = usize::from(start - self.end).min(buf.len());
                self.buf[self.end as usize..self.end as usize + l].copy_from_slice(&buf[..l]);
                self.end += l as u8;
                l
            }
            Less => {
                let l1 = self.buf.len() - self.end as usize;
                if l1 > buf.len() {
                    self.buf[self.end as usize..self.end as usize + buf.len()].copy_from_slice(buf);
                    self.end += buf.len() as u8;
                    buf.len()
                } else {
                    let (a, b) = buf.split_at(l1);
                    self.buf[self.end as usize..].copy_from_slice(a);
                    let l2 = usize::from(start).min(b.len());
                    self.buf[..l2].copy_from_slice(&b[..l2]);
                    self.end = l2 as u8;
                    l1 + l2
                }
            }
        };

        debug_assert!(n > 0, "written 0 bytes");
        trace!("Written {n} bytes.");

        if let RWWaker::Read(w) = take(&mut self.rw_waker) {
            trace!("Wake read waker.");
            w.wake();
        }

        Ready(n)
    }

    fn poll_write(&mut self, cx: &mut Context<'_>, buf: &[u8]) -> Poll<IoResult<usize>> {
        if self.closed {
            return Ready(Err(ErrorKind::BrokenPipe.into()));
        }
        match self.write(cx, buf) {
            Pending => Pending,
            Ready(v) => Ready(Ok(v)),
        }
    }

    #[instrument(level = "trace", name = "InnerHalf::poll_flush", skip_all)]
    fn poll_flush(&mut self, cx: &mut Context<'_>) -> Poll<IoResult<()>> {
        if self.closed {
            return Ready(Err(ErrorKind::BrokenPipe.into()));
        } else if self.end == self.start {
            return Ready(Ok(()));
        }

        trace!("Register flush waker.");
        match &mut self.flush_waker {
            Some(w) => w.clone_from(cx.waker()),
            v => *v = Some(cx.waker().clone()),
        }
        Pending
    }

    #[instrument(level = "trace", name = "InnerHalf::poll_close", skip_all)]
    fn poll_close(&mut self, _: &mut Context<'_>) -> Poll<IoResult<()>> {
        if !self.closed {
            self.closed = true;
            if let RWWaker::Read(w) = take(&mut self.rw_waker) {
                trace!("Wake read waker.");
                w.wake();
            }
        }
        Ready(Ok(()))
    }

    fn poll_write_vectored(
        &mut self,
        cx: &mut Context<'_>,
        bufs: &[IoSlice<'_>],
    ) -> Poll<IoResult<usize>> {
        if self.closed {
            return Ready(Err(ErrorKind::BrokenPipe.into()));
        }
        let mut n = 0;
        for b in bufs {
            if b.is_empty() {
                continue;
            }
            n += ready!(self.write(cx, b));
            if self.end == self.start.wrapping_sub(1) {
                break;
            }
        }
        Ready(Ok(n))
    }
}

struct Inner {
    server_client: InnerHalf,
    client_server: InnerHalf,
}

#[repr(align(2))]
struct Outer {
    state: AtomicU8,
    inner: UnsafeCell<Inner>,
    _pinned: PhantomPinned,
}

const COUNT_FLAG: u8 = 1;
const LOCK_FLAG: u8 = 1 << 7;
const MASK: usize = !(align_of::<Outer>() - 1);

// SAFETY: Outer is send and sync.
unsafe impl Send for Outer {}
// SAFETY: Outer is send and sync.
unsafe impl Sync for Outer {}

impl Outer {
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
                    state: AtomicU8::new((COUNT_FLAG * 2) | (LOCK_FLAG >> 1)),
                    inner: UnsafeCell::new(Inner {
                        server_client: InnerHalf::new(),
                        client_server: InnerHalf::new(),
                    }),
                    _pinned: PhantomPinned,
                },
            );
        }

        ret
    }

    unsafe fn dec(p: NonNull<Self>) {
        let p = p.as_ptr().map_addr(|a| a & MASK);
        debug_assert!(p.is_aligned(), "pointer {p:?} is not aligned");

        // SAFETY: Pointer points to valid allocation.
        let r = unsafe { (*p).state.fetch_sub(COUNT_FLAG, Release) };
        if r & (COUNT_FLAG * 3) == COUNT_FLAG {
            fence(Acquire);

            // SAFETY: Pointer points to valid allocation and we're about to drop it.
            unsafe {
                drop_in_place(p);
                dealloc(p.cast(), Layout::new::<Self>());
            }
        }
    }

    fn lock(&self) -> Guard<'_> {
        if self.state.fetch_add(LOCK_FLAG, Acquire) & LOCK_FLAG != 0 {
            panic!("acquiring pipe twice");
        }

        Guard(self)
    }
}

#[must_use]
struct Guard<'a>(&'a Outer);

impl Drop for Guard<'_> {
    fn drop(&mut self) {
        self.0.state.fetch_sub(LOCK_FLAG, Release);
    }
}

impl Deref for Guard<'_> {
    type Target = Inner;

    fn deref(&self) -> &Inner {
        // SAFETY: We locked the value.
        unsafe { &*self.0.inner.get() }
    }
}

impl DerefMut for Guard<'_> {
    fn deref_mut(&mut self) -> &mut Inner {
        // SAFETY: We locked the value.
        unsafe { &mut *self.0.inner.get() }
    }
}

/// One end of pipe.
///
/// Unlike typical pipe, if one end is dropped, the other **will not be** notified.
/// This is to ensure improper closure of pipe will cause it to deadlock.
///
/// **NOTE: Must only be used within a runtime. Any use outside will cause panics.**
#[must_use = "Pipe is useless without polling it"]
pub struct Pipe(NonNull<Outer>);

// SAFETY: Pipe is send and sync.
unsafe impl Send for Pipe {}
// SAFETY: Pipe is send and sync.
unsafe impl Sync for Pipe {}

impl Drop for Pipe {
    fn drop(&mut self) {
        // SAFETY: Pointer points to valid allocation.
        unsafe { Outer::dec(self.0) }
    }
}

impl Debug for Pipe {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        let (p, c) = self.get();
        f.debug_struct("Pipe")
            .field("ptr", &(p as *const Outer))
            .field("is_client", &c)
            .finish()
    }
}

impl Pipe {
    /// Returns `true` if `other` is on the other end of the pipe.
    #[must_use]
    pub fn is_same_pipe(&self, other: &Self) -> bool {
        self.0.as_ptr().addr() & MASK == other.0.as_ptr().addr() & MASK
    }

    fn get(&self) -> (&Outer, bool) {
        let p = self.0.as_ptr();
        let is_client = p.addr() & 1 != 0;
        // SAFETY: Pointer points to valid allocation.
        (
            unsafe { &*p.cast_const().map_addr(|a| a & MASK) },
            is_client,
        )
    }

    fn inner<R>(&self, flip: bool, f: impl FnOnce(&mut InnerHalf) -> R) -> R {
        let (o, c) = self.get();
        let mut g = o.lock();
        let i = if c ^ flip {
            &mut g.client_server
        } else {
            &mut g.server_client
        };
        f(i)
    }
}

impl AsyncRead for Pipe {
    #[instrument(level = "trace", name = "Pipe::poll_read", skip_all)]
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<IoResult<usize>> {
        Pin::into_inner(self).inner(false, |i| i.poll_read(cx, buf))
    }

    #[instrument(level = "trace", name = "Pipe::poll_read_vectored", skip_all)]
    fn poll_read_vectored(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &mut [IoSliceMut<'_>],
    ) -> Poll<IoResult<usize>> {
        Pin::into_inner(self).inner(false, |i| i.poll_read_vectored(cx, bufs))
    }
}

impl AsyncWrite for Pipe {
    #[instrument(level = "trace", name = "Pipe::poll_write", skip_all)]
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<IoResult<usize>> {
        Pin::into_inner(self).inner(true, |i| i.poll_write(cx, buf))
    }

    #[instrument(level = "trace", name = "Pipe::poll_flush", skip_all)]
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<IoResult<()>> {
        Pin::into_inner(self).inner(true, |i| i.poll_flush(cx))
    }

    #[instrument(level = "trace", name = "Pipe::poll_close", skip_all)]
    fn poll_close(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<IoResult<()>> {
        Pin::into_inner(self).inner(true, |i| i.poll_close(cx))
    }

    #[instrument(level = "trace", name = "Pipe::poll_write_vectored", skip_all)]
    fn poll_write_vectored(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[IoSlice<'_>],
    ) -> Poll<IoResult<usize>> {
        Pin::into_inner(self).inner(true, |i| i.poll_write_vectored(cx, bufs))
    }
}

/// Creates a pair of [`Pipe`].
#[instrument(level = "trace", skip_all)]
pub fn make_pipe(rt: &Runtime) -> (Pipe, Pipe) {
    let _ = rt;
    let s = Outer::new();
    let c = s.map_addr(|a| a | 1);
    (Pipe(s), Pipe(c))
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::pin::pin;

    use futures_util::{AsyncReadExt, AsyncWriteExt};
    use test_log::test;
    use tracing::info;

    use crate::rt::Executor;
    use crate::utils::run_test;

    static MSG: &[u8] = b"Hello from one pipe to another.";

    #[test]
    fn test_pipe_read_write() {
        #[instrument]
        fn test() {
            let mut executor = Executor::builder().build();

            let rt_ = executor.runtime();
            let rt = rt_.clone();
            rt_.spawn(async move {
                let (client, server) = make_pipe(&rt);

                rt.spawn(async move {
                    let mut pipe = pin!(server);

                    pipe.as_mut().write_all(MSG).await.unwrap();
                    pipe.as_mut().close().await.unwrap();
                });

                let mut pipe = pin!(client);

                let mut buf = [0; const { MSG.len() }];
                pipe.as_mut().read_exact(&mut buf).await.unwrap();
                assert_eq!(buf, MSG);
                assert_eq!(pipe.as_mut().read(&mut buf).await.unwrap(), 0);
            });

            executor.run();
        }

        run_test(test);
    }
}
