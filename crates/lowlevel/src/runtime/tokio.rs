use std::future::Future;
use std::io::{IoSlice, IoSliceMut, Result as IoResult};
use std::net::SocketAddr;
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::Instant;

use futures_io::{AsyncRead, AsyncWrite};
use tokio::io::BufStream;
use tokio::net::TcpStream;
use tokio::task::{JoinHandle, spawn};
use tokio::time::{Instant as TokioInstant, Sleep, sleep_until};
use tokio_util::compat::{Compat, TokioAsyncReadCompatExt};

use super::{Runtime, Stream, Timer};
use crate::private::{SealWrap, Sealed};

type TokioStream = Compat<BufStream<TcpStream>>;

/// Tokio runtime.
#[derive(Default, Clone, Copy)]
pub struct TokioRuntime;

impl Sealed for TokioRuntime {}

impl Runtime for TokioRuntime {
    type Task<T: Send> = SealWrap<JoinHandle<T>>;
    type Timer = SealWrap<Sleep>;
    type Stream = SealWrap<TokioStream>;

    fn spawn<T, F>(&self, fut: F) -> Self::Task<T>
    where
        F: Future<Output = T> + Send + 'static,
        T: Send + 'static,
    {
        SealWrap(spawn(fut))
    }

    fn timer(&self, timeout: Instant) -> Self::Timer {
        SealWrap(sleep_until(timeout.into()))
    }

    async fn connect(&self, addrs: &[SocketAddr]) -> IoResult<Self::Stream> {
        TcpStream::connect(addrs)
            .await
            .map(|v| SealWrap(BufStream::new(v).compat()))
    }
}

impl Sealed for SealWrap<Sleep> {}

impl Future for SealWrap<Sleep> {
    type Output = ();

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<()> {
        self.project().poll(cx)
    }
}

impl Timer for SealWrap<Sleep> {
    fn reset(self: Pin<&mut Self>, timeout: Instant) {
        self.project().reset(TokioInstant::from(timeout));
    }
}

impl<T> Future for SealWrap<JoinHandle<T>> {
    type Output = T;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<T> {
        match self.project().poll(cx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(v) => Poll::Ready(v.unwrap()),
        }
    }
}

impl Sealed for SealWrap<TokioStream> {}

impl AsyncRead for SealWrap<TokioStream> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<IoResult<usize>> {
        self.project().poll_read(cx, buf)
    }

    fn poll_read_vectored(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &mut [IoSliceMut<'_>],
    ) -> Poll<IoResult<usize>> {
        self.project().poll_read_vectored(cx, bufs)
    }
}

impl AsyncWrite for SealWrap<TokioStream> {
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<IoResult<usize>> {
        self.project().poll_write(cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<IoResult<()>> {
        self.project().poll_flush(cx)
    }

    fn poll_close(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<IoResult<()>> {
        self.project().poll_close(cx)
    }

    fn poll_write_vectored(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[IoSlice<'_>],
    ) -> Poll<IoResult<usize>> {
        self.project().poll_write_vectored(cx, bufs)
    }
}

impl Stream for SealWrap<TokioStream> {
    fn peer_addr(&self) -> IoResult<SocketAddr> {
        self.0.get_ref().get_ref().peer_addr()
    }
}
