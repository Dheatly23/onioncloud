pub mod controller;
pub mod manager;

use std::num::NonZeroU32;
use std::time::Instant;

use flume::{Sender, TrySendError};

use crate::cell::CellLike;
use crate::cell::destroy::DestroyReason;
use crate::util::cell_map::NewHandler;
use crate::util::sans_io::CellMsgPause;

/// Circuit controller input.
///
/// `Cell` is the type of cells that controller receives/sends.
pub struct CircuitInput<'a, Cell> {
    circ_id: NonZeroU32,
    time: Instant,
    agg_sender: &'a mut dyn AggSender<Cell = Cell>,
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
        agg_sender: &'a mut dyn AggSender<Cell = Cell>,
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
pub struct NewStream<Cell> {
    /// Handle data.
    ///
    /// ID here is stream ID.
    pub inner: NewHandler<Cell>,

    /// Circuit ID.
    pub circ_id: NonZeroU32,
}

impl<Cell> NewStream<Cell> {
    /// Create `NewStream`.
    pub fn new<C>(handle: NewHandler<Cell>, input: &CircuitInput<'_, C>) -> Self {
        Self {
            inner: handle,
            circ_id: input.id(),
        }
    }
}

/// Internal trait for a aggregate sender.
pub(crate) trait AggSender {
    type Cell;

    fn try_send_unchecked(&mut self, cell: Self::Cell) -> Result<(), TrySendError<Self::Cell>>;
}

impl<Cell> AggSender for Sender<Cell> {
    type Cell = Cell;

    fn try_send_unchecked(&mut self, cell: Cell) -> Result<(), TrySendError<Cell>> {
        self.try_send(cell)
    }
}

impl<Cell> AggSender for &Sender<Cell> {
    type Cell = Cell;

    fn try_send_unchecked(&mut self, cell: Cell) -> Result<(), TrySendError<Cell>> {
        self.try_send(cell)
    }
}
