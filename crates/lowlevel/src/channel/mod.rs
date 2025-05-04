pub mod circ_map;
pub mod controller;
pub mod manager;

use std::borrow::Cow;
use std::io::{Read, Write};
use std::net::SocketAddr;
use std::time::Instant;

use crate::crypto::relay::RelayId;

/// Trait for channel configuration.
pub trait ChannelConfig {
    /// Get peer relay ID.
    fn peer_id(&self) -> &RelayId;

    // Get peer Ed25519 public key.
    //fn peer_ed25519_id(&self)

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
}

impl ChannelOutput {
    /// Create new [`ChannelOutput`].
    #[allow(clippy::new_without_default)]
    pub fn new() -> Self {
        Self {
            timeout: None,
            shutdown: false,
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
}

/// Internal trait for a TLS stream.
pub(crate) trait Stream: Read + Write {
    fn link_cert(&self) -> Option<&[u8]>;
    fn peer_addr(&self) -> &SocketAddr;
}
