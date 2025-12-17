use std::collections::VecDeque;
use std::io::{ErrorKind, IoSlice, IoSliceMut, Read as _, Result as IoResult, Write as _};
use std::marker::{PhantomData, PhantomPinned};
use std::mem::forget;
use std::net::SocketAddr;
use std::ops::DerefMut;
use std::pin::Pin;
use std::ptr::NonNull;
use std::sync::{Arc, Weak};
use std::task::{Context, Poll, Waker};

use futures_io::{AsyncRead, AsyncWrite};
use parking_lot::{Mutex, MutexGuard};
use tracing::{info_span, instrument};

use crate::private::Sealed;
use crate::runtime::Stream;
use crate::util::set_option_waker;

/// Open socket configuration.
#[non_exhaustive]
pub struct OpenSocket {
    /// Initial send buffer data.
    pub send: VecDeque<u8>,
    /// Marks send buffer to no longer send any more data.
    pub send_eof: bool,
    /// Address associated with socket.
    pub addr: SocketAddr,
    /// Handler function.
    pub handle: HandleFn,
}

impl OpenSocket {
    /// Create new [`OpenSocket`].
    #[inline]
    pub fn new(addr: SocketAddr, handle: HandleFn) -> Self {
        Self {
            send: VecDeque::new(),
            send_eof: false,
            addr,
            handle,
        }
    }

    /// Sets initial data to be sent.
    #[inline]
    pub fn with_send(mut self, value: VecDeque<u8>) -> Self {
        self.send = value;
        self
    }

    /// Marks send buffer to be closed.
    #[inline]
    pub fn with_send_eof(mut self, value: bool) -> Self {
        self.send_eof = value;
        self
    }
}

pub type OpenHandleFn =
    Box<dyn Send + Sync + FnMut(&[SocketAddr]) -> Result<OpenSocket, ErrorKind>>;
pub type HandleFn = Box<dyn Send + Sync + FnMut(&mut SocketRef<'_>) -> Result<(), ErrorKind>>;

/// Handle for runtime sockets.
pub struct Sockets {
    handle: OpenHandleFn,
    sockets: Vec<Weak<Mutex<SocketInner>>>,
}

enum SocketInner {
    Open {
        inner: OpenSocketInner,
        handle: HandleFn,
        _pinned: PhantomPinned,
    },
    Error(ErrorKind),
}

struct OpenSocketInner {
    addr: SocketAddr,
    send: VecDeque<u8>,
    send_eof: bool,
    send_waker: Option<Waker>,
    recv: VecDeque<u8>,
    recv_eof: bool,
}

impl Sockets {
    #[inline]
    pub(super) fn new() -> Self {
        Self {
            sockets: Vec::new(),
            // Emulates network disconnection.
            handle: Box::new(|_| Err(ErrorKind::NetworkUnreachable)),
        }
    }

    pub fn set_handle(&mut self, f: OpenHandleFn) {
        self.handle = f;
    }

    /// Gets number of sockets (including pending).
    pub fn len(&self) -> usize {
        self.sockets.len()
    }

    /// Inner method to get value and handle.
    ///
    /// # Safety
    ///
    /// Handle must be dropped before [`SocketRef`] is dropped.
    unsafe fn get_inner(&mut self, ix: usize) -> Option<(SocketRef<'_>, &'_ mut HandleFn)> {
        let v = self.sockets.get(ix)?.upgrade()?;
        let mut guard = v.try_lock().expect("deadlock");

        let SocketInner::Open { inner, handle, .. } = &mut *guard else {
            return None;
        };
        let p = NonNull::from_mut(inner);
        // SAFETY: Value should be locked while handle reference is used.
        let h = unsafe { &mut *(&raw mut *handle) };
        forget(guard);
        Some((
            SocketRef {
                v,
                p,
                _p: PhantomData,
            },
            h,
        ))
    }

    /// Gets reference to socket.
    pub fn get(&mut self, ix: usize) -> Option<SocketRef<'_>> {
        // SAFETY: Handle is dropped and reference is returned.
        unsafe { self.get_inner(ix).map(|(v, _)| v) }
    }

    #[instrument(skip(self))]
    pub(super) fn create_socket(&mut self, addrs: &[SocketAddr]) -> IoResult<TestSocket> {
        let OpenSocket {
            addr,
            handle,
            send,
            send_eof,
        } = (self.handle)(addrs)?;
        let inner = Arc::new(Mutex::new(SocketInner::Open {
            inner: OpenSocketInner {
                addr,
                send,
                send_eof,
                send_waker: None,
                recv: VecDeque::new(),
                recv_eof: false,
            },
            handle,
            _pinned: PhantomPinned,
        }));
        self.sockets.push(Arc::downgrade(&inner));
        Ok(TestSocket {
            inner,
            _pinned: PhantomPinned,
        })
    }

    #[instrument(skip_all)]
    pub(super) fn handle_all(&mut self) {
        for i in 0..self.sockets.len() {
            let _g = info_span!("handle", i);

            // SAFETY: Handle will be dropped roughly at the same time as guard.
            let r = unsafe { self.get_inner(i) };
            let Some((mut g, h)) = r else { continue };
            if let Err(e) = (*h)(&mut g) {
                // SAFETY: Value is locked.
                unsafe {
                    *g.v.data_ptr() = SocketInner::Error(e);
                }
            }
        }
    }
}

/// Reference to a socket.
pub struct SocketRef<'a> {
    p: NonNull<OpenSocketInner>,
    v: Arc<Mutex<SocketInner>>,
    _p: PhantomData<&'a mut OpenSocketInner>,
}

unsafe impl Send for SocketRef<'_> {}
unsafe impl Sync for SocketRef<'_> {}

impl Drop for SocketRef<'_> {
    fn drop(&mut self) {
        // SAFETY: We lock the value.
        unsafe { self.v.force_unlock() }
    }
}

impl SocketRef<'_> {
    fn inner(&mut self) -> &mut OpenSocketInner {
        // SAFETY: Pointer points to locked value within.
        unsafe { self.p.as_mut() }
    }

    /// Get reference to send stream.
    ///
    /// Stream is [`Read`] by task.
    pub fn send_stream(&mut self) -> &mut VecDeque<u8> {
        &mut self.inner().send
    }

    /// Get reference to receive stream.
    ///
    /// Stream is [`Write`] by task.
    pub fn recv_stream(&mut self) -> &mut VecDeque<u8> {
        &mut self.inner().recv
    }

    /// Close sending half of pipe.
    pub fn close_send(&mut self) {
        self.inner().send_eof = true;
    }

    /// Close receiving half of pipe.
    pub fn close_recv(&mut self) {
        self.inner().recv_eof = true;
    }

    /// Wake send task.
    ///
    /// After pushing bytes using [`Self::send_stream`], call this to notify waker.
    pub fn wake_send(&mut self) {
        if let Some(w) = self.inner().send_waker.take() {
            w.wake();
        }
    }
}

/// A test socket.
#[must_use]
pub struct TestSocket {
    inner: Arc<Mutex<SocketInner>>,
    _pinned: PhantomPinned,
}

impl Sealed for TestSocket {}

impl TestSocket {
    fn inner(&self) -> IoResult<impl '_ + DerefMut<Target = OpenSocketInner>> {
        MutexGuard::try_map_or_err(self.inner.lock(), |v| match *v {
            SocketInner::Open { ref mut inner, .. } => Ok(inner),
            SocketInner::Error(e) => Err(e.into()),
        })
        .map_err(|(_, e)| e)
    }
}

impl AsyncRead for TestSocket {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<IoResult<usize>> {
        let mut g = self.inner()?;

        match g.send.read(buf) {
            Ok(0) if !g.send_eof && !buf.is_empty() => {
                set_option_waker(&mut g.send_waker, cx);
                Poll::Pending
            }
            r => Poll::Ready(r),
        }
    }

    fn poll_read_vectored(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &mut [IoSliceMut<'_>],
    ) -> Poll<IoResult<usize>> {
        let mut g = self.inner()?;

        match g.send.read_vectored(bufs) {
            Ok(0) if !g.send_eof && bufs.iter().any(|b| !b.is_empty()) => {
                set_option_waker(&mut g.send_waker, cx);
                Poll::Pending
            }
            r => Poll::Ready(r),
        }
    }
}

impl AsyncWrite for TestSocket {
    fn poll_write(self: Pin<&mut Self>, _: &mut Context<'_>, buf: &[u8]) -> Poll<IoResult<usize>> {
        let mut g = self.inner()?;

        if g.recv_eof {
            return Poll::Ready(Ok(0));
        }
        Poll::Ready(g.recv.write(buf))
    }

    fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<IoResult<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_close(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<IoResult<()>> {
        self.inner()?.recv_eof = true;
        Poll::Ready(Ok(()))
    }

    fn poll_write_vectored(
        self: Pin<&mut Self>,
        _: &mut Context<'_>,
        bufs: &[IoSlice<'_>],
    ) -> Poll<IoResult<usize>> {
        let mut g = self.inner()?;

        if g.recv_eof {
            return Poll::Ready(Ok(0));
        }
        Poll::Ready(g.recv.write_vectored(bufs))
    }
}

impl Stream for TestSocket {
    fn peer_addr(&self) -> IoResult<SocketAddr> {
        Ok(self.inner()?.addr)
    }
}
