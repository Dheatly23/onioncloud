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

pub struct ChannelInput<'a> {
    stream: &'a mut dyn Stream,
    time: Instant,
    timeout: bool,
}

impl<'a> ChannelInput<'a> {
    pub(crate) fn new(
        stream: &'a mut dyn Stream,
        time: Instant,
        timeout: bool,
    ) -> Self {
        Self {
            stream,
            time,
            timeout,
        }
    }
}

impl ChannelInput<'_> {
    pub fn reader(&mut self) -> &mut dyn Read {
        &mut self.stream
    }

    pub fn writer(&mut self) -> &mut dyn Write {
        &mut self.stream
    }

    pub fn link_cert(&self) -> &[u8] {
        self.stream.link_cert()
    }

    pub fn time(&self) -> Instant {
        self.time
    }

    pub fn is_timeout(&self) -> bool {
        self.timeout
    }
}

pub struct ChannelOutput {
    pub(crate) timeout: Option<Instant>,
    pub(crate) shutdown: bool,
}

impl ChannelOutput {
    pub fn new() -> Self {
        Self { timeout: None, shutdown: false }
    }

    pub fn timeout(&mut self, timeout: Instant) -> &mut Self {
        self.timeout = Some(timeout);
        self
    }

    pub fn shutdown(&mut self, value: bool) -> &mut Self {
        self.shutdown = value;
        self
    }
}

/// Internal trait for a TLS stream.
pub(crate) trait Stream: Read + Write {
    fn link_cert(&self) -> &[u8];
}
