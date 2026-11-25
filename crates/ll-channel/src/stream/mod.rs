//! Stream trait definition and wrappers.

mod no_tls;
mod tls;

use std::borrow::Cow;
use std::io::{Read, Write};
use std::net::SocketAddr;
use std::pin::Pin;
use std::task::{Context, Poll};

use crate::error::ChannelError;
pub use no_tls::StreamNoTls;
#[cfg(feature = "test-dummy-tls")]
pub use tls::tls_dummy::{do_close, do_handshake, transform_server_message};

/// Wrapper for [`Socket`] with TLS (client).
pub type StreamTLSClient<S> = tls::StreamTLSInner<S, tls::tls_impl::RustlsWrapper>;

/// Dummy TLS client.
#[cfg(feature = "test-dummy-tls")]
pub type StreamDummyClient<S> = tls::StreamTLSInner<S, tls::tls_dummy::DummyWrapper>;

/// Network stream wrapper type.
pub trait Stream: Read + Write {
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
    ) -> Poll<Result<(), ChannelError>>;

    /// Request for shutdown.
    fn request_shutdown(self: Pin<&mut Self>);
}
