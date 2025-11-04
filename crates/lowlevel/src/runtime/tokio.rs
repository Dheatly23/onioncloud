use std::future::Future;
use std::io::{IoSlice, IoSliceMut, Result as IoResult};
use std::net::SocketAddr;
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::Instant;

use flume::r#async::{RecvStream, SendSink as FlumeSendSink};
use flume::{bounded, unbounded};
use futures_io::{AsyncRead, AsyncWrite};
use futures_sink::Sink;
use pin_project::pin_project;
use tokio::io::BufStream;
use tokio::net::TcpStream;
use tokio::task::{JoinHandle, spawn};
use tokio::time::{Instant as TokioInstant, Sleep, sleep_until};
use tokio_util::compat::{Compat, TokioAsyncReadCompatExt};
use tracing::{Instrument, Span, trace_span};

use super::{Runtime, SendError, Stream, Timer};
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
    type SPSCSender<T: 'static + Send> = SendSink<T>;
    type SPSCReceiver<T: 'static + Send> = RecvStream<'static, T>;
    type MPSCSender<T: 'static + Send> = SendSink<T>;
    type MPSCReceiver<T: 'static + Send> = RecvStream<'static, T>;

    fn spawn<F>(&self, fut: F) -> Self::Task<F::Output>
    where
        F: Future + Send + 'static,
        F::Output: Send + 'static,
    {
        let span = trace_span!("spawn");
        span.follows_from(Span::current());
        SealWrap(spawn(fut.instrument(span)))
    }

    fn timer(&self, timeout: Instant) -> Self::Timer {
        SealWrap(sleep_until(timeout.into()))
    }

    async fn connect(&self, addrs: &[SocketAddr]) -> IoResult<Self::Stream> {
        TcpStream::connect(addrs)
            .await
            .map(|v| SealWrap(BufStream::new(v).compat()))
    }

    fn spsc_make<T: 'static + Send>(
        &self,
        size: usize,
    ) -> (Self::SPSCSender<T>, Self::SPSCReceiver<T>) {
        let (send, recv) = if size == 0 {
            unbounded()
        } else {
            bounded(size)
        };
        (send.into_sink().into(), recv.into_stream())
    }

    fn mpsc_make<T: 'static + Send>(
        &self,
        size: usize,
    ) -> (Self::MPSCSender<T>, Self::MPSCReceiver<T>) {
        let (send, recv) = if size == 0 {
            unbounded()
        } else {
            bounded(size)
        };
        (send.into_sink().into(), recv.into_stream())
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

#[pin_project]
#[derive(Debug)]
pub struct SendSink<T: 'static + Send>(#[pin] pub FlumeSendSink<'static, T>);

impl<T: 'static + Send> Clone for SendSink<T> {
    fn clone(&self) -> Self {
        Self(self.0.clone())
    }

    fn clone_from(&mut self, src: &Self) {
        self.0.clone_from(&src.0);
    }
}

impl<T: 'static + Send> From<FlumeSendSink<'static, T>> for SendSink<T> {
    fn from(v: FlumeSendSink<'static, T>) -> Self {
        Self(v)
    }
}

impl<T: 'static + Send> From<SendSink<T>> for FlumeSendSink<'static, T> {
    fn from(v: SendSink<T>) -> Self {
        v.0
    }
}

impl<T: 'static + Send> Sink<T> for SendSink<T> {
    type Error = SendError<T>;

    fn poll_ready(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.project()
            .0
            .poll_ready(cx)
            .map_err(SendError::from_flume)
    }

    fn start_send(self: Pin<&mut Self>, item: T) -> Result<(), Self::Error> {
        self.project()
            .0
            .start_send(item)
            .map_err(SendError::from_flume)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.project()
            .0
            .poll_flush(cx)
            .map_err(SendError::from_flume)
    }

    fn poll_close(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.project()
            .0
            .poll_close(cx)
            .map_err(SendError::from_flume)
    }
}
