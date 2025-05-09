pub mod circ_map;
pub mod controller;
pub mod manager;

use std::borrow::Cow;
use std::io::{Read, Write};
use std::net::SocketAddr;
use std::time::Instant;

use crate::crypto::relay::{RelayId, RelayIdEd};

/// Trait for channel configuration.
pub trait ChannelConfig {
    /// Get peer relay ID.
    fn peer_id(&self) -> &RelayId;

    /// Get peer relay Ed25519 id.
    ///
    /// Default implementation returns [`None`].
    /// Implementors are encouraged to return [`RelayIdEd`] if possible.
    fn peer_id_ed(&self) -> Option<&RelayIdEd> {
        None
    }

    /// Get peer addresses.
    fn peer_addrs(&self) -> Cow<'_, [SocketAddr]>;
}

/// Reference to channel data.
pub struct ChannelInput<'a> {
    stream: &'a mut dyn Stream,
    time: Instant,
}

impl<'a> ChannelInput<'a> {
    pub(crate) fn new(stream: &'a mut dyn Stream, time: Instant) -> Self {
        Self { stream, time }
    }

    /// Get stream reader.
    pub fn reader(&mut self) -> &mut dyn Read {
        &mut self.stream
    }

    /// Get stream writer.
    pub fn writer(&mut self) -> &mut dyn Write {
        &mut self.stream
    }

    /// Get link certificate.
    ///
    /// The certificate returned is only leaf certificate.
    pub fn link_cert(&self) -> Option<&[u8]> {
        self.stream.link_cert()
    }

    /// Get peer address.
    pub fn peer_addr(&self) -> &SocketAddr {
        self.stream.peer_addr()
    }

    /// Get current time.
    pub fn time(&self) -> Instant {
        self.time
    }
}

/// Return value for [`controller::ChannelController`] handler.
pub struct ChannelOutput {
    pub(crate) timeout: Option<Instant>,
    pub(crate) shutdown: bool,
    pub(crate) cell_msg_pause: bool,
}

impl ChannelOutput {
    /// Create new [`ChannelOutput`].
    #[allow(clippy::new_without_default)]
    pub fn new() -> Self {
        Self {
            timeout: None,
            shutdown: false,
            cell_msg_pause: false,
        }
    }

    /// Set timeout to be notified.
    pub fn timeout(&mut self, timeout: Instant) -> &mut Self {
        self.timeout = Some(timeout);
        self
    }

    /// Start graceful shutdown sequence.
    pub fn shutdown(&mut self, value: bool) -> &mut Self {
        self.shutdown = value;
        self
    }

    /// Pauses cell message receiving. By default it's set to [`false`].
    pub fn cell_msg_pause(&mut self, value: CellMsgPause) -> &mut Self {
        self.cell_msg_pause = value.0;
        self
    }
}

/// Wrapper type for pausing cell messages.
///
/// Useful to stop controller from receiving excessive cell message before it's all transmitted.
///
/// # Example
///
/// ```
/// use onioncloud_lowlevel::channel::CellMsgPause;
///
/// // Pause cell message
/// CellMsgPause::from(true);
///
/// // Resume cell message
/// CellMsgPause::from(false);
/// ```
#[derive(Debug)]
pub struct CellMsgPause(pub(crate) bool);

impl From<bool> for CellMsgPause {
    fn from(v: bool) -> Self {
        Self(v)
    }
}

/// Internal trait for a TLS stream.
pub(crate) trait Stream: Read + Write {
    fn link_cert(&self) -> Option<&[u8]>;
    fn peer_addr(&self) -> &SocketAddr;
}
