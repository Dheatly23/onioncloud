#[cfg(feature = "tokio")]
pub mod tokio;

use std::future::Future;
use std::io::Result as IoResult;
use std::net::SocketAddr;
use std::pin::Pin;
use std::time::Instant;

use futures_io::{AsyncRead, AsyncWrite};

pub trait Runtime: crate::private::Sealed {
    type Timer: Timer;
    type Stream: AsyncRead + AsyncWrite + Send;

    fn spawn<Fut>(&self, fut: Fut)
    where
        Fut: Future<Output = ()> + Send + 'static;

    fn timer(&self, timeout: Instant) -> Self::Timer;

    fn connect(&self, addrs: &[SocketAddr]) -> impl Future<Output = IoResult<Self::Stream>> + Send;
}

pub trait Timer: Future<Output = ()> + Send + crate::private::Sealed {
    fn reset(self: Pin<&mut Self>, timeout: Instant);
}
