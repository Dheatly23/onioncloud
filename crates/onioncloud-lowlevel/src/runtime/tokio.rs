use std::future::Future;
use std::io::Result as IoResult;
use std::net::SocketAddr;
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::Instant;

use tokio::net::TcpStream;
use tokio::task::spawn;
use tokio::time::{Instant as TokioInstant, Sleep, sleep_until};
use tokio_util::compat::{Compat, TokioAsyncReadCompatExt};

use super::{Runtime, Timer};
use crate::private::SealWrap;

/// Tokio runtime.
#[derive(Default, Clone, Copy)]
pub struct TokioRuntime;

impl crate::private::Sealed for TokioRuntime {}

impl Runtime for TokioRuntime {
    type Timer = SealWrap<Sleep>;
    type Stream = Compat<TcpStream>;

    fn spawn<Fut>(&self, fut: Fut)
    where
        Fut: Future<Output = ()> + Send + 'static,
    {
        spawn(fut);
    }

    fn timer(&self, timeout: Instant) -> Self::Timer {
        SealWrap(sleep_until(timeout.into()))
    }

    async fn connect(&self, addrs: &[SocketAddr]) -> IoResult<Self::Stream> {
        TcpStream::connect(addrs).await.map(|v| v.compat())
    }
}

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
