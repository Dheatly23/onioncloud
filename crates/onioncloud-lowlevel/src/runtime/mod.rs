#[cfg(feature = "tokio")]
pub mod tokio;

use std::future::Future;
use std::io::Result as IoResult;
use std::net::SocketAddr;
use std::pin::Pin;
use std::time::Instant;

use futures_io::{AsyncRead, AsyncWrite};

pub trait Runtime: crate::private::Sealed {
    type Task<T: Send>: Future<Output = T> + Send + Unpin;
    type Timer: Timer;
    type Stream: Stream;

    fn spawn<T, F>(&self, fut: F) -> impl Future<Output = T> + Send
    where
        F: Future<Output = T> + Send + 'static,
        T: Send + 'static;

    fn timer(&self, timeout: Instant) -> Self::Timer;

    fn connect(&self, addrs: &[SocketAddr]) -> impl Future<Output = IoResult<Self::Stream>> + Send;
}

pub trait Timer: Future<Output = ()> + Send + crate::private::Sealed {
    fn reset(self: Pin<&mut Self>, timeout: Instant);
}

pub trait Stream: AsyncRead + AsyncWrite + Send + crate::private::Sealed {
    fn peer_addr(&self) -> IoResult<SocketAddr>;
}
