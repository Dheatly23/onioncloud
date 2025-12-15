pub mod controller;
pub mod manager;

use std::num::{NonZeroU16, NonZeroU32};
use std::pin::Pin;
use std::task::Context;
use std::task::Poll::*;
use std::time::Instant;

use futures_sink::Sink;

use crate::cell::destroy::DestroyReason;
use crate::runtime::Runtime;
use crate::util::cell_map::{CellMap, CellMapRef, NewHandler};
use crate::util::sans_io::CellMsgPause;

/// Type alias for circuit map.
pub type StreamMap<R, C, M> = CellMap<NonZeroU16, R, C, M>;
/// Type alias for circuit map.
pub type StreamMapRef<'a, 'b, R, C, M> = CellMapRef<'a, 'b, NonZeroU16, R, C, M>;

pub(crate) enum SenderState {
    Start,
    Pending,
    Ready,
    Closed,
}

/// Circuit controller input.
///
/// `Cell` is the type of cells that controller receives/sends.
pub struct CircuitInput<'a, 'b, R: Runtime, S: 'static + Send, C: 'static + Send, M> {
    time: Instant,
    has_ready: bool,

    cx: &'a mut Context<'b>,
    stream_map: Pin<&'a mut StreamMap<R, S, M>>,
    is_any_close: &'a mut bool,
    sender: Pin<&'a mut R::MPSCSender<C>>,
    sender_state: &'a mut SenderState,
}

impl<'a, 'b, R: Runtime, S: 'static + Send, C: 'static + Send, M> CircuitInput<'a, 'b, R, S, C, M> {
    /// Create new [`CircuitInput`].
    pub(crate) fn new(
        time: Instant,
        has_ready: bool,
        cx: &'a mut Context<'b>,
        stream_map: Pin<&'a mut StreamMap<R, S, M>>,
        is_any_close: &'a mut bool,
        sender: Pin<&'a mut R::MPSCSender<C>>,
        sender_state: &'a mut SenderState,
    ) -> Self {
        Self {
            time,
            has_ready,
            cx,
            stream_map,
            is_any_close,
            sender,
            sender_state,
        }
    }

    /// Get current time.
    pub fn time(&self) -> Instant {
        self.time
    }

    /// Returns `true` if any circuit in map is ready.
    pub fn has_ready(&self) -> bool {
        self.has_ready
    }

    /// Get reference to stream map.
    pub fn stream_map(&mut self) -> StreamMapRef<'_, 'b, R, S, M> {
        StreamMapRef::new(self.stream_map.as_mut(), self.cx, self.is_any_close)
    }

    /// Checks if circuit is ready to send cell.
    pub fn is_ready(&mut self) -> bool {
        loop {
            match self.sender_state {
                SenderState::Ready => return true,
                SenderState::Closed | SenderState::Pending => return false,
                SenderState::Start => {
                    *self.sender_state = match self.sender.as_mut().poll_ready(self.cx) {
                        Ready(Ok(())) => SenderState::Ready,
                        Ready(Err(_)) => SenderState::Closed,
                        Pending => SenderState::Pending,
                    }
                }
            }
        }
    }

    /// Try to send cell.
    ///
    /// Returns `true` if cell got sent.
    pub fn try_send(&mut self, f: impl FnOnce() -> C) -> bool {
        let ret = self.is_ready();
        if ret {
            if self.sender.as_mut().start_send(f()).is_err() {
                *self.sender_state = SenderState::Closed;
            } else {
                self.is_ready();
            }
        }
        ret
    }
}

/// Circuit controller output.
pub struct CircuitOutput {
    pub(crate) timeout: Option<Instant>,
    pub(crate) shutdown: Option<DestroyReason>,
    pub(crate) parent_cell_msg_pause: bool,
    pub(crate) child_cell_msg_pause: bool,
}

impl CircuitOutput {
    /// Create new [`CircuitOutput`].
    #[allow(clippy::new_without_default)]
    pub fn new() -> Self {
        Self {
            timeout: None,
            shutdown: None,
            parent_cell_msg_pause: false,
            child_cell_msg_pause: false,
        }
    }

    /// Set timeout to be notified.
    pub fn timeout(&mut self, timeout: Instant) -> &mut Self {
        self.timeout = Some(timeout);
        self
    }

    /// Pause parent cell message receiving. By default it's set to [`false`].
    pub fn parent_cell_msg_pause(&mut self, value: CellMsgPause) -> &mut Self {
        self.parent_cell_msg_pause = value.0;
        self
    }

    /// Pause child cell message receiving. By default it's set to [`false`].
    pub fn child_cell_msg_pause(&mut self, value: CellMsgPause) -> &mut Self {
        self.child_cell_msg_pause = value.0;
        self
    }

    /// Shutdown circuit.
    ///
    /// Shut down circuit with a [`DestroyReason`].
    pub fn shutdown(&mut self, reason: DestroyReason) -> &mut Self {
        self.shutdown = Some(reason);
        self
    }
}

/// Data for new stream handler.
///
/// For circuit controller, send it to stream handler.
/// Once received, use destructuring let to get all the values.
#[derive(Debug)]
#[non_exhaustive]
pub struct NewStream<ID, R: Runtime, Cell: 'static + Send> {
    /// Handle data.
    ///
    /// ID here is stream ID.
    pub inner: NewHandler<ID, R, Cell>,

    /// Circuit ID.
    pub circ_id: NonZeroU32,
}

impl<ID, R: Runtime, Cell: 'static + Send> NewStream<ID, R, Cell> {
    /// Create `NewStream`.
    pub fn new(handle: NewHandler<ID, R, Cell>, circ_id: NonZeroU32) -> Self {
        Self {
            inner: handle,
            circ_id,
        }
    }
}
