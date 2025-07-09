pub mod controller;
pub mod manager;

use std::num::NonZeroU32;
use std::time::Instant;

use flume::{Sender, TrySendError};

use crate::cell::CellLike;
use crate::cell::destroy::DestroyReason;
use crate::util::cell_map::NewHandler;

/// Circuit controller input.
///
/// `Cell` is the type of cells that controller receives/sends.
pub struct CircuitInput<'a, Cell> {
    circ_id: NonZeroU32,
    time: Instant,
    agg_sender: &'a mut dyn AggSender<Cell>,
}

impl<'a, Cell> CircuitInput<'a, Cell> {
    /// Create new [`CircuitInput`].
    ///
    /// # Parameters
    ///
    /// - `circ_id` : Circuit ID.
    /// - `time` : Current time.
    /// - `agg_sender` : Aggregate sender.
    pub(crate) fn new(
        circ_id: NonZeroU32,
        time: Instant,
        agg_sender: &'a mut dyn AggSender<Cell>,
    ) -> Self {
        Self {
            circ_id,
            time,
            agg_sender,
        }
    }

    /// Get current time.
    pub fn time(&self) -> Instant {
        self.time
    }

    /// Get circuit ID.
    pub fn id(&self) -> NonZeroU32 {
        self.circ_id
    }

    /// Try to send cell unsafely.
    ///
    /// # Safety
    ///
    /// Cell circuit ID must match [`id`].
    pub unsafe fn try_send_unchecked(&mut self, cell: Cell) -> Result<(), TrySendError<Cell>> {
        self.agg_sender.try_send_unchecked(cell)
    }

    /// Try to send cell.
    ///
    /// Panics if cell circuit ID does not match [`id`].
    pub fn try_send(&mut self, cell: Cell) -> Result<(), TrySendError<Cell>>
    where
        Cell: CellLike,
    {
        assert_eq!(cell.circuit(), self.circ_id.into(), "circuit ID mismatch");
        // SAFETY: Circuit ID has been checked
        unsafe { self.try_send_unchecked(cell) }
    }
}

/// Circuit controller output.
pub struct CircuitOutput {
    pub(crate) timeout: Option<Instant>,
    pub(crate) shutdown: Option<DestroyReason>,
    pub(crate) cell_msg_pause: bool,
    pub(crate) stream_cell_msg_pause: bool,
}

impl CircuitOutput {
    /// Create new [`ChannelOutput`].
    pub fn new() -> Self {
        Self {
            timeout: None,
            shutdown: None,
            cell_msg_pause: false,
            stream_cell_msg_pause: false,
        }
    }

    /// Set timeout to be notified.
    pub fn timeout(&mut self, timeout: Instant) -> &mut Self {
        self.timeout = Some(timeout);
        self
    }

    /// Pause cell message receiving. By default it's set to [`false`].
    pub fn cell_msg_pause(&mut self, value: CellMsgPause) -> &mut Self {
        self.cell_msg_pause = value.0;
        self
    }

    /// Pause stream cell message receiving. By default it's set to [`false`].
    pub fn stream_cell_msg_pause(&mut self, value: CellMsgPause) -> &mut Self {
        self.stream_cell_msg_pause = value.0;
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

/// Marker type for circuit timeout.
#[derive(Debug, PartialEq, Eq)]
pub struct Timeout;

/// Wrapper struct for control message.
#[derive(Debug)]
pub struct ControlMsg<Msg>(pub Msg);

impl<M> ControlMsg<M> {
    /// Unwraps into inner value.
    pub fn into_inner(self) -> M {
        self.0
    }
}

/// Wrapper struct for cell message.
#[derive(Debug)]
pub struct CellMsg<Msg>(pub Msg);

impl<M> CellMsg<M> {
    /// Unwraps into inner value.
    pub fn into_inner(self) -> M {
        self.0
    }
}

/// Wrapper struct for stream cell message.
#[derive(Debug)]
pub struct StreamCellMsg<Msg>(pub Msg);

impl<M> StreamCellMsg<M> {
    /// Unwraps into inner value.
    pub fn into_inner(self) -> M {
        self.0
    }
}

/// Wrapper type for pausing cell messages.
///
/// Useful to stop controller from receiving excessive cell message before it's all transmitted.
///
/// # Example
///
/// ```
/// use onioncloud_lowlevel::circuit::CellMsgPause;
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

/// Data for new stream handler.
///
/// For circuit controller, send it to stream handler.
/// Once received, use destructuring let to get all the values.
#[derive(Debug)]
#[non_exhaustive]
pub struct NewStream<Cell> {
    pub inner: NewHandler<Cell>,
    pub circ_id: NonZeroU32,
}

impl<Cell> NewStream<Cell> {
    /// Create `NewStream`.
    pub fn new(handle: NewHandler<Cell>, input: &CircuitInput<'_, Cell>) -> Self {
        Self {
            inner: handle,
            circ_id: input.id(),
        }
    }
}

/// Internal trait for a aggregate sender.
pub(crate) trait AggSender<Cell> {
    fn try_send_unchecked(&mut self, cell: Cell) -> Result<(), TrySendError<Cell>>;
}

impl<Cell> AggSender<Cell> for Sender<Cell> {
    fn try_send_unchecked(&mut self, cell: Cell) -> Result<(), TrySendError<Cell>> {
        self.try_send(cell)
    }
}

impl<Cell> AggSender<Cell> for &Sender<Cell> {
    fn try_send_unchecked(&mut self, cell: Cell) -> Result<(), TrySendError<Cell>> {
        self.try_send(cell)
    }
}
