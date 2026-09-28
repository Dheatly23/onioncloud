//! Stream trait definition and wrappers.

use std::borrow::Cow;
use std::io::{IoSlice, IoSliceMut, Result as IoResult};
use std::net::SocketAddr;
use std::pin::Pin;
use std::task::{Context, Poll};

use futures_io::{AsyncRead, AsyncWrite};
use onioncloud_runtime::Socket;
use pin_project::pin_project;

/// Network stream wrapper type.
pub trait Stream: AsyncRead + AsyncWrite {
    /// Gets peer address.
    fn peer_addr(&self) -> SocketAddr;

    /// Gets leaf certificate (if any).
    fn leaf_cert(&self) -> Option<Cow<'_, [u8]>>;

    /// Cheks if stream wants to be polled.
    ///
    /// If `true`, it indicates [`Self::poll_inner`] must be called in the future.
    fn wants_poll(&self) -> bool;

    /// Checks if stream is initializing.
    ///
    /// Stream may use this to signal that it's not ready to be used yet.
    /// It can use [`Self::poll_inner`] to drive itself to completion.
    fn is_init(&self) -> bool {
        false
    }

    /// Do internal works (flushing buffers, etc).
    ///
    /// If it returns `Poll:Ready(Ok(()))`, it indicates the stream has closed.
    ///
    /// Argument `is_same_poll` is used to indicate if the poll is in the same cycle.
    /// It's only an optimization flag.
    fn poll_inner(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        is_same_poll: bool,
    ) -> Poll<IoResult<()>>;
}

/// Wrapper for [`Socket`] without TLS.
#[pin_project]
#[derive(Debug)]
pub struct StreamNoTls<S> {
    peer_addr: SocketAddr,
    close_state: CloseState,
    #[pin]
    stream: S,
}

#[derive(Debug)]
enum CloseState {
    None,
    Closing,
    Closed,
}

impl<S: AsyncRead> AsyncRead for StreamNoTls<S> {
    #[inline]
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<IoResult<usize>> {
        self.project().stream.poll_read(cx, buf)
    }

    #[inline]
    fn poll_read_vectored(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &mut [IoSliceMut<'_>],
    ) -> Poll<IoResult<usize>> {
        self.project().stream.poll_read_vectored(cx, bufs)
    }
}

impl<S: AsyncWrite> AsyncWrite for StreamNoTls<S> {
    #[inline]
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<IoResult<usize>> {
        self.project().stream.poll_write(cx, buf)
    }

    #[inline]
    fn poll_write_vectored(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[IoSlice<'_>],
    ) -> Poll<IoResult<usize>> {
        self.project().stream.poll_write_vectored(cx, bufs)
    }

    #[inline]
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<IoResult<()>> {
        self.project().stream.poll_flush(cx)
    }

    #[inline]
    fn poll_close(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<IoResult<()>> {
        let this = self.project();
        if matches!(this.close_state, CloseState::Closed) {
            return Poll::Ready(Ok(()));
        }
        *this.close_state = CloseState::Closing;
        let ret = this.stream.poll_close(cx);
        if matches!(ret, Poll::Ready(Ok(()))) {
            *this.close_state = CloseState::Closed;
        }
        ret
    }
}

impl<S: Socket> Stream for StreamNoTls<S> {
    fn peer_addr(&self) -> SocketAddr {
        self.peer_addr
    }

    fn leaf_cert(&self) -> Option<Cow<'_, [u8]>> {
        None
    }

    fn wants_poll(&self) -> bool {
        false
    }

    fn poll_inner(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        is_same_poll: bool,
    ) -> Poll<IoResult<()>> {
        let this = self.project();
        match this.close_state {
            CloseState::Closing if !is_same_poll => {
                let ret = this.stream.poll_close(cx);
                if matches!(ret, Poll::Ready(Ok(()))) {
                    *this.close_state = CloseState::Closed;
                }
                ret
            }
            CloseState::Closed => Poll::Ready(Ok(())),
            _ => Poll::Pending,
        }
    }
}

impl<S: Socket> StreamNoTls<S> {
    /// Creates new stream.
    pub fn new(stream: S) -> IoResult<Self> {
        let peer_addr = stream.peer_addr()?;
        Ok(Self {
            peer_addr,
            close_state: CloseState::None,
            stream,
        })
    }
}
