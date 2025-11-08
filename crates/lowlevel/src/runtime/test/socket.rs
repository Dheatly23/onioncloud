use std::collections::VecDeque;
use std::future::Future;
use std::io::{ErrorKind, IoSlice, IoSliceMut, Read as _, Result as IoResult, Write as _};
use std::marker::PhantomPinned;
use std::net::SocketAddr;
use std::ops::DerefMut;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll, Waker};

use futures_core::ready;
use futures_io::{AsyncRead, AsyncWrite};
use parking_lot::{Mutex, MutexGuard};
use pin_project::pin_project;

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
}

impl OpenSocket {
    /// Create new [`OpenSocket`].
    #[inline]
    pub fn new(addr: SocketAddr) -> Self {
        Self {
            send: VecDeque::new(),
            send_eof: false,
            addr,
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

/// Handle for runtime sockets.
pub struct Sockets {
    sockets: Vec<SocketInner>,
}

enum SocketInner {
    Connect {
        addrs: Box<[SocketAddr]>,
        waker: Option<Waker>,
    },
    Open(OpenSocketInner),
    Closed,
    Error(ErrorKind),
}

struct OpenSocketInner {
    addr: SocketAddr,
    send: VecDeque<u8>,
    send_eof: bool,
    send_waker: Option<Waker>,
    recv: VecDeque<u8>,
    recv_eof: bool,

    closed: bool,
}

impl Sockets {
    #[inline]
    pub(super) fn new() -> Self {
        Self {
            sockets: Vec::new(),
        }
    }

    /// Handle pending sockets.
    ///
    /// # Parameters
    ///
    /// - `f` : Function that receives list of [`SocketAddr`] and returns either [`OpenSocket`] or error.
    pub fn handle_new_sockets(
        &mut self,
        mut f: impl FnMut(usize, &[SocketAddr]) -> Result<OpenSocket, ErrorKind>,
    ) {
        for (ix, i) in self.sockets.iter_mut().enumerate() {
            let SocketInner::Connect { addrs, waker } = i else {
                continue;
            };

            let res = f(ix, &addrs[..]);
            if let Some(w) = waker.take() {
                w.wake();
            }
            *i = match res {
                Ok(OpenSocket {
                    addr,
                    send,
                    send_eof,
                }) => SocketInner::Open(OpenSocketInner {
                    addr,
                    send,
                    recv: VecDeque::new(),
                    send_eof,
                    recv_eof: false,
                    send_waker: None,
                    closed: false,
                }),
                Err(e) => SocketInner::Error(e),
            };
        }
    }

    /// Gets number of sockets (including pending).
    pub fn len(&self) -> usize {
        self.sockets.len()
    }

    /// Gets reference to socket.
    pub fn get(&mut self, ix: usize) -> SocketRef<'_> {
        SocketRef(match &mut self.sockets[ix] {
            SocketInner::Open(v) => v,
            _ => unreachable!("socket is not open"),
        })
    }
}

/// Reference to a socket.
pub struct SocketRef<'a>(&'a mut OpenSocketInner);

impl SocketRef<'_> {
    /// Get reference to send stream.
    ///
    /// Stream is [`Read`] by task.
    pub fn send_stream(&mut self) -> &mut VecDeque<u8> {
        &mut self.0.send
    }

    /// Get reference to receive stream.
    ///
    /// Stream is [`Write`] by task.
    pub fn recv_stream(&mut self) -> &mut VecDeque<u8> {
        &mut self.0.recv
    }

    /// Close sending half of pipe.
    pub fn close_send(&mut self) {
        self.0.send_eof = true;
    }

    /// Close receiving half of pipe.
    pub fn close_recv(&mut self) {
        self.0.recv_eof = true;
    }

    /// Wake send task.
    ///
    /// After pushing bytes using [`Self::send_stream`], call this to notify waker.
    pub fn wake_send(&mut self) {
        if let Some(w) = self.0.send_waker.take() {
            w.wake();
        }
    }
}

/// A test socket.
pub struct TestSocket {
    ix: usize,
    sockets: Arc<Mutex<Sockets>>,
    _pinned: PhantomPinned,
}

impl Sealed for TestSocket {}

impl Drop for TestSocket {
    fn drop(&mut self) {
        match &mut self.sockets.lock().sockets[self.ix] {
            v @ SocketInner::Connect { .. } => *v = SocketInner::Closed,
            SocketInner::Open(OpenSocketInner { closed, .. }) => *closed = true,
            _ => (),
        }
    }
}

impl TestSocket {
    fn inner(
        &self,
        cx: &mut Context<'_>,
    ) -> Poll<IoResult<impl '_ + DerefMut<Target = OpenSocketInner>>> {
        let ret =
            MutexGuard::try_map_or_err(self.sockets.lock(), |v| match &mut v.sockets[self.ix] {
                SocketInner::Open(v) => Ok(v),
                &mut SocketInner::Error(e) => Err(Some(e.into())),
                SocketInner::Connect { waker, .. } => {
                    set_option_waker(waker, cx);
                    Err(None)
                }
                SocketInner::Closed => unreachable!("socket closed"),
            });
        match ret {
            Err((_, Some(e))) => Poll::Ready(Err(e)),
            Err((_, None)) => Poll::Pending,
            Ok(v) => Poll::Ready(Ok(v)),
        }
    }
}

impl AsyncRead for TestSocket {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<IoResult<usize>> {
        let mut inner = ready!(self.inner(cx))?;

        match inner.send.read(buf) {
            Ok(0) if !inner.send_eof && !buf.is_empty() => {
                set_option_waker(&mut inner.send_waker, cx);
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
        let mut inner = ready!(self.inner(cx))?;

        match inner.send.read_vectored(bufs) {
            Ok(0) if !inner.send_eof && bufs.iter().any(|b| !b.is_empty()) => {
                set_option_waker(&mut inner.send_waker, cx);
                Poll::Pending
            }
            r => Poll::Ready(r),
        }
    }
}

impl AsyncWrite for TestSocket {
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<IoResult<usize>> {
        let mut inner = ready!(self.inner(cx))?;

        if inner.recv_eof || inner.closed {
            return Poll::Ready(Ok(0));
        }
        Poll::Ready(inner.recv.write(buf))
    }

    fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<IoResult<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_close(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<IoResult<()>> {
        let mut inner = ready!(self.inner(cx))?;

        inner.closed = true;
        Poll::Ready(Ok(()))
    }

    fn poll_write_vectored(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[IoSlice<'_>],
    ) -> Poll<IoResult<usize>> {
        let mut inner = ready!(self.inner(cx))?;

        if inner.recv_eof || inner.closed {
            return Poll::Ready(Ok(0));
        }
        Poll::Ready(inner.recv.write_vectored(bufs))
    }
}

impl Stream for TestSocket {
    fn peer_addr(&self) -> IoResult<SocketAddr> {
        match self.sockets.lock().sockets[self.ix] {
            SocketInner::Open(OpenSocketInner { addr, .. }) => Ok(addr),
            SocketInner::Error(e) => Err(e.into()),
            _ => unreachable!("socket is not open"),
        }
    }
}

#[pin_project]
pub(super) struct SocketConnectFut(Option<TestSocket>);

impl From<TestSocket> for SocketConnectFut {
    fn from(v: TestSocket) -> Self {
        Self(Some(v))
    }
}

impl Future for SocketConnectFut {
    type Output = IoResult<TestSocket>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let Some(TestSocket {
            ix, ref sockets, ..
        }) = self.0
        else {
            panic!("future polled after finished")
        };
        let mut guard = sockets.lock();
        match &mut guard.sockets[ix] {
            &mut SocketInner::Error(e) => Poll::Ready(Err(e.into())),
            SocketInner::Connect { waker, .. } => {
                set_option_waker(waker, cx);
                Poll::Pending
            }
            _ => {
                drop(guard);
                Poll::Ready(Ok(self.project().0.take().unwrap()))
            }
        }
    }
}

pub(super) fn create_socket(this: &Arc<Mutex<Sockets>>, addrs: &[SocketAddr]) -> TestSocket {
    let mut guard = this.lock();
    let ix = guard.sockets.len();
    guard.sockets.push(SocketInner::Connect {
        addrs: addrs.into(),
        waker: None,
    });
    drop(guard);
    TestSocket {
        ix,
        sockets: this.clone(),
        _pinned: PhantomPinned,
    }
}
