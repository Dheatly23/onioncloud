pub mod controller;
pub mod manager;

use std::borrow::Cow;
use std::io::{Read, Write};
use std::net::SocketAddr;
use std::num::NonZeroU32;
use std::pin::Pin;
use std::task::Context;
use std::time::Instant;

use crate::crypto::relay::{RelayId, RelayIdEd};
use crate::runtime::Runtime;
use crate::util::cell_map::{CellMap, CellMapRef, NewHandler};
use crate::util::sans_io::CellMsgPause;

/// Type alias for circuit map.
pub type CircMap<R, C, M> = CellMap<NonZeroU32, R, C, M>;
/// Type alias for circuit map.
pub type CircMapRef<'a, 'b, R, C, M> = CellMapRef<'a, 'b, NonZeroU32, R, C, M>;

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
pub struct ChannelInput<'a, 'b, R: Runtime, C: 'static + Send, M> {
    stream: &'a mut dyn Stream,
    time: Instant,
    has_ready: bool,

    circ_map: Pin<&'a mut CircMap<R, C, M>>,
    cx: &'a mut Context<'b>,
    is_any_close: &'a mut bool,
}

impl<'a, 'b, R: Runtime, C: 'static + Send, M> ChannelInput<'a, 'b, R, C, M> {
    pub(crate) fn new(
        stream: &'a mut dyn Stream,
        time: Instant,
        has_ready: bool,
        cx: &'a mut Context<'b>,
        circ_map: Pin<&'a mut CircMap<R, C, M>>,
        is_any_close: &'a mut bool,
    ) -> Self {
        Self {
            stream,
            time,
            has_ready,
            cx,
            circ_map,
            is_any_close,
        }
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

    /// Returns `true` if any circuit in map is ready.
    pub fn has_ready(&self) -> bool {
        self.has_ready
    }

    /// Get circuit map.
    pub fn circ_map(&mut self) -> CircMapRef<'_, 'b, R, C, M> {
        CircMapRef::new(self.circ_map.as_mut(), self.cx, self.is_any_close)
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

/// Data for new circuit handler.
///
/// For channel controller, send it to circuit handler.
/// Once received, use destructuring let to get all the values.
#[derive(Debug)]
#[non_exhaustive]
pub struct NewCircuit<ID, R: Runtime, Cell: 'static + Send> {
    /// Handler data.
    pub inner: NewHandler<ID, R, Cell>,

    /// Link protocol version.
    pub linkver: u16,
}

impl<ID, R: Runtime, Cell: 'static + Send> NewCircuit<ID, R, Cell> {
    /// Create `NewCircuit`.
    pub fn new(handler: NewHandler<ID, R, Cell>) -> Self {
        Self {
            inner: handler,
            linkver: 0,
        }
    }

    pub fn with_linkver(self, linkver: u16) -> Self {
        Self { linkver, ..self }
    }
}

/// Internal trait for a TLS stream.
pub(crate) trait Stream: Read + Write {
    fn link_cert(&self) -> Option<&[u8]>;
    fn peer_addr(&self) -> &SocketAddr;
}
