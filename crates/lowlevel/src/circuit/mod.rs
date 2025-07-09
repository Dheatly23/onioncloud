pub mod controller;
pub mod manager;

use std::num::NonZeroU32;
use std::ops::{Deref, DerefMut};
use std::time::Instant;

use flume::{Sender, TrySendError};

use crate::cache::{Cachable, Cached, CellCache};
use crate::cell::CellLike;
use crate::cell::destroy::DestroyReason;
use crate::util::cell_map::NewHandler;

/// A [`Sender`] wrapper with circuit ID checking.
#[derive(Debug, Clone)]
pub struct CheckedSender<Cell> {
    id: NonZeroU32,
    send: Sender<Cell>,
}

impl<Cell> CheckedSender<Cell> {
    /// Create new [`CheckedSender`].
    pub fn new(id: NonZeroU32, send: Sender<Cell>) -> Self {
        Self { id, send }
    }

    /// Get circuit ID.
    pub fn id(&self) -> NonZeroU32 {
        self.id
    }

    /// Get inner sender.
    ///
    /// # Safety
    ///
    /// Sender should ony be used to send cells with circuit ID matching [`id`].
    pub unsafe fn inner_sender(&self) -> &Sender<Cell> {
        &self.send
    }

    /// Try to send cell unsafely.
    ///
    /// # Safety
    ///
    /// Cell circuit ID must match [`id`].
    pub unsafe fn try_send_unchecked(&mut self, cell: Cell) -> Result<(), TrySendError<Cell>> {
        self.send.try_send(cell)
    }

    /// Try to send cell.
    ///
    /// Panics if cell circuit ID does not match [`id`].
    pub fn try_send(&mut self, cell: Cell) -> Result<(), TrySendError<Cell>>
    where
        Cell: CellLike,
    {
        assert_eq!(cell.circuit(), self.id.get(), "circuit ID mismatch");
        // SAFETY: Circuit ID has been checked
        unsafe { self.try_send_unchecked(cell) }
    }
}

/// Circuit controller input.
///
/// `Cell` is the type of cells that controller receives/sends.
pub struct CircuitInput<'a, Cell> {
    time: Instant,
    agg_sender: &'a mut CheckedSender<Cell>,
}

impl<'a, Cell> Deref for CircuitInput<'a, Cell> {
    type Target = CheckedSender<Cell>;

    fn deref(&self) -> &Self::Target {
        &*self.agg_sender
    }
}

impl<'a, Cell> DerefMut for CircuitInput<'a, Cell> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut *self.agg_sender
    }
}

impl<'a, Cell> CircuitInput<'a, Cell> {
    /// Create new [`CircuitInput`].
    ///
    /// # Parameters
    ///
    /// - `time` : Current time.
    /// - `agg_sender` : Aggregate sender.
    pub(crate) fn new(time: Instant, agg_sender: &'a mut CheckedSender<Cell>) -> Self {
        Self { time, agg_sender }
    }

    /// Get current time.
    pub fn time(&self) -> Instant {
        self.time
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
