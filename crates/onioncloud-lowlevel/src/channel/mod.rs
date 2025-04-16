pub mod controller;
pub mod manager;

use std::borrow::Cow;
use std::io::{Read, Write};
use std::net::SocketAddr;

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
    closed: bool,
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

    pub fn is_closed(&self) -> bool {
        self.closed
    }
}

/// Internal trait for a TLS stream.
trait Stream: Read + Write {
    fn link_cert(&self) -> &[u8];
}
