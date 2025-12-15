pub mod test;
#[cfg(any(feature = "tokio", test))]
pub mod tokio;

use std::future::Future;
use std::io::Result as IoResult;
use std::net::SocketAddr;
use std::pin::Pin;
use std::time::Instant;

use futures_core::stream::Stream as FuturesStream;
use futures_io::{AsyncRead, AsyncWrite};
use futures_sink::Sink;

/// Trait for a runtime.
pub trait Runtime: crate::private::Sealed + Send + Sync {
    /// Handle for task.
    type Task<T: Send>: Future<Output = T> + Send;
    /// Timer type.
    type Timer: Timer;
    /// Socket stream type.
    type Stream: Stream;
    /// SPSC sender type.
    type SPSCSender<T: 'static + Send>: PipeSender<T>;
    /// SPSC receiver type.
    type SPSCReceiver<T: 'static + Send>: PipeReceiver<T>;
    /// MPSC sender type.
    type MPSCSender<T: 'static + Send>: PipeSender<T> + Clone;
    /// MPSC receiver type.
    type MPSCReceiver<T: 'static + Send>: PipeReceiver<T>;

    /// Get current time.
    fn get_time(&self) -> Instant {
        Instant::now()
    }

    /// Spawn a new task.
    fn spawn<F>(&self, fut: F) -> Self::Task<F::Output>
    where
        F: Future + Send + 'static,
        F::Output: Send + 'static;

    /// Creates a new timer.
    fn timer(&self, timeout: Instant) -> Self::Timer;

    /// Start TCP connection to address.
    fn connect(&self, addrs: &[SocketAddr]) -> impl Future<Output = IoResult<Self::Stream>> + Send;

    /// Make SPSC send/receive pair with bounded channel size.
    ///
    /// Implementation _may_ panic if size is zero. If not, it must be an unbounded channel.
    fn spsc_make<T: 'static + Send>(
        &self,
        size: usize,
    ) -> (Self::SPSCSender<T>, Self::SPSCReceiver<T>);

    /// Make MPSC send/receive pair with bounded channel size.
    ///
    /// Implementation _may_ panic if size is zero. If not, it must be an unbounded channel.
    fn mpsc_make<T: 'static + Send>(
        &self,
        size: usize,
    ) -> (Self::MPSCSender<T>, Self::MPSCReceiver<T>);
}

/// Trait for a timer.
pub trait Timer: Future<Output = ()> + Send + crate::private::Sealed {
    fn reset(self: Pin<&mut Self>, timeout: Instant);
}

/// Trait for a socket stream.
pub trait Stream: AsyncRead + AsyncWrite + Send + crate::private::Sealed {
    fn peer_addr(&self) -> IoResult<SocketAddr>;
}

/// Send error type.
///
/// Represent an error of diconnected receiver.
/// Contains the original value that can't be sent.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SendError<T>(pub T);

impl<T> SendError<T> {
    pub(crate) fn from_flume(v: flume::SendError<T>) -> Self {
        Self(v.0)
    }

    /// Unwraps into inner value.
    pub fn into_inner(self) -> T {
        self.0
    }
}

/// Try send error type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TrySendError<T> {
    /// Channel disconnected.
    Disconnected(T),
    /// Channel is not ready,
    NotReady(T),
}

impl<T> From<SendError<T>> for TrySendError<T> {
    fn from(v: SendError<T>) -> Self {
        Self::Disconnected(v.0)
    }
}

impl<T> TrySendError<T> {
    /// Unwraps into inner value.
    pub fn into_inner(self) -> T {
        match self {
            Self::Disconnected(v) => v,
            Self::NotReady(v) => v,
        }
    }
}

/// Trait for pipe sender.
pub trait PipeSender<T>: crate::private::Sealed + Send + Sink<T, Error = SendError<T>> {
    /// Checks if pipe is disconnected.
    fn is_disconnected(&self) -> bool;
}

/// Trait for pipe receiver.
pub trait PipeReceiver<T>: crate::private::Sealed + Send + FuturesStream<Item = T> {
    /// Checks if pipe is disconnected.
    fn is_disconnected(&self) -> bool;
}
