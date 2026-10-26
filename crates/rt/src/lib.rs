//! Runtime trait and implementation.

#[cfg(feature = "tart")]
pub mod tart;
#[cfg(feature = "tokio")]
pub mod tokio;

use std::future::Future;
use std::io::Result as IoResult;
use std::net::SocketAddr;
use std::pin::Pin;
use std::time::Instant;

use futures_core::{FusedFuture, Stream};
use futures_io::{AsyncRead, AsyncWrite};
use futures_sink::Sink;

/// A timer.
///
/// # Behavior On Poll
///
/// [`poll`](`Future::poll`) should always succeed when timer is finished.
/// This ensure expired timer will always fire.
///
/// # Fusing Behavior
///
/// Timer should always be available to be polled.
pub trait Timer: Future<Output = ()> + FusedFuture {
    /// Reset timer to always fire.
    fn reset(self: Pin<&mut Self>);

    /// Set timer to fire at specified time.
    fn set(self: Pin<&mut Self>, time: Instant);

    /// Get timeout epoch.
    ///
    /// If timer has ben reset, returns [`None`].
    #[must_use]
    fn get_timeout(&self) -> Option<Instant>;
}

/// Runtime that can make timer.
pub trait HasTimer {
    /// Timer type.
    type Timer: Send + Sync + Timer;

    /// Create a new timer.
    ///
    /// If `time` is [`None`], then it should always fire.
    #[must_use = "timer does nothing until polled"]
    fn make_timer(&self, time: Option<Instant>) -> Self::Timer;

    /// Gets current time.
    #[must_use]
    fn current_time(&self) -> Instant;
}

/// Runtime that can make SPSC channel pair.
pub trait HasSpsc {
    /// Sender type.
    type Sender<T: 'static + Send + Sync>: Send + Sync + Sink<T>;
    /// Receiver type.
    type Receiver<T: 'static + Send + Sync>: Send + Sync + Stream<Item = T>;

    /// Create SPSC channel pair.
    ///
    /// # Panics
    ///
    /// Setting `cap` to zero may panics.
    #[must_use]
    fn make_spsc<T: 'static + Send + Sync>(
        &self,
        cap: usize,
    ) -> (Self::Sender<T>, Self::Receiver<T>);
}

/// Runtime that can make MPSC channel pair.
pub trait HasMpsc {
    /// Sender type.
    type Sender<T: 'static + Send + Sync>: Send + Sync + Clone + Sink<T>;
    /// Receiver type.
    type Receiver<T: 'static + Send + Sync>: Send + Sync + Stream<Item = T>;

    /// Create MPSC channel pair.
    ///
    /// # Panics
    ///
    /// Setting `cap` to zero may panics.
    #[must_use]
    fn make_mpsc<T: 'static + Send + Sync>(
        &self,
        cap: usize,
    ) -> (Self::Sender<T>, Self::Receiver<T>);
}

/// A network socket.
pub trait Socket: AsyncRead + AsyncWrite {
    /// Gets peer address it connects to.
    ///
    /// # Errors
    ///
    /// It may error if it can't get the peer address.
    fn peer_addr(&self) -> IoResult<SocketAddr>;
}

/// Runtime that can open network socket.
pub trait HasNetwork {
    /// Socket type.
    type Socket: Send + Sync + Socket;

    /// Connect to address.
    #[must_use]
    fn connect<'a>(
        &'a self,
        addrs: &'a [SocketAddr],
    ) -> impl 'a + Send + Sync + Future<Output = IoResult<Self::Socket>>;
}

/// Runtime that can spawn new task.
pub trait CanSpawn {
    /// Handle for task.
    ///
    /// Task must continue even when handle is dropped.
    ///
    /// # Panics
    ///
    /// If task panics, it may panic when polled.
    type Handle<T: 'static + Send>: Send + Sync + Future<Output = T>;

    /// Spawns a new task.
    #[must_use = "handle must be polled or explicitly dropped"]
    fn spawn<T: 'static + Send>(
        &self,
        task: impl 'static + Send + Sync + Future<Output = T>,
    ) -> Self::Handle<T>;
}

/// Wrapper trait for runtime.
pub trait Runtime:
    Send + Sync + Clone + HasTimer + HasSpsc + HasMpsc + HasNetwork + CanSpawn
{
}
impl<T: Send + Sync + Clone + HasTimer + HasSpsc + HasMpsc + HasNetwork + CanSpawn> Runtime for T {}
