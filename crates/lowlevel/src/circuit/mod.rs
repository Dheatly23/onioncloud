pub mod controller;
pub mod manager;

use std::marker::PhantomData;
use std::num::NonZeroU32;
use std::ops::{Deref, DerefMut};
use std::time::Instant;

use flume::{Sender, TrySendError};

use crate::cache::{Cachable, Cached, CellCache};
use crate::cell::CellLike;
use crate::cell::destroy::{Destroy, DestroyReason};

pub struct CircuitInput<'a, Cell> {
    id: NonZeroU32,
    time: Instant,
    chan_closed: bool,
    agg_send: &'a Sender<Cell>,

    _phantom: PhantomData<&'a mut ()>,
}

impl<'a, Cell> CircuitInput<'a, Cell> {
    pub(crate) fn new(
        id: NonZeroU32,
        time: Instant,
        chan_closed: bool,
        agg_send: &'a Sender<Cell>,
    ) -> Self {
        Self {
            id,
            time,
            chan_closed,
            agg_send,
            _phantom: PhantomData,
        }
    }

    /// Get current time.
    pub fn time(&self) -> Instant {
        self.time
    }

    /// Get circuit ID.
    pub fn id(&self) -> NonZeroU32 {
        self.id
    }

    /// Try to send cell unsafely.
    ///
    /// # Safety
    ///
    /// Cell circuit ID must match [`id`].
    pub unsafe fn try_send_unchecked(&self, cell: Cell) -> Result<(), TrySendError<Cell>> {
        self.agg_send.try_send(cell)
    }

    /// Try to send cell.
    ///
    /// Panics if cell circuit ID does not match [`id`].
    pub fn try_send(&self, cell: Cell) -> Result<(), TrySendError<Cell>>
    where
        Cell: CellLike,
    {
        assert_eq!(cell.circuit(), self.id.get(), "circuit ID mismatch");
        // SAFETY: Circuit ID has been checked
        unsafe { self.try_send_unchecked(cell) }
    }

    /// Create [`CircuitOutput`] from self.
    pub fn output(self) -> CircuitOutput<'a, Cell> {
        CircuitOutput::new(self)
    }
}

pub struct CircuitOutput<'a, Cell> {
    input: CircuitInput<'a, Cell>,
    pub(crate) timeout: Option<Instant>,
    pub(crate) shutdown: Option<Cell>,
    pub(crate) cell_msg_pause: bool,
}

impl<'a, Cell> Deref for CircuitOutput<'a, Cell> {
    type Target = CircuitInput<'a, Cell>;

    fn deref(&self) -> &Self::Target {
        &self.input
    }
}

impl<'a, Cell> DerefMut for CircuitOutput<'a, Cell> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.input
    }
}

impl<'a, Cell> CircuitOutput<'a, Cell> {
    /// Create new [`ChannelOutput`].
    pub fn new(input: CircuitInput<'a, Cell>) -> Self {
        Self {
            input,
            timeout: None,
            shutdown: None,
            cell_msg_pause: false,
        }
    }

    /// Shutdown circuit with cell (unchecked).
    ///
    /// # Safety
    ///
    /// Cell must be a DESTROY cell with correct circuit ID.
    pub unsafe fn shutdown_with_unchecked(&mut self, cell: Cell) -> &mut Self {
        self.shutdown = Some(cell);
        self
    }

    /// Shutdown circuit with supplied DESTROY cell.
    ///
    /// When returned, start graceful shutdown sequence:
    /// 1. Send DESTROY cell.
    /// 2. Receive cells until closed.
    ///
    /// The controller will no longer be used.
    ///
    /// # Panics
    ///
    /// Panics if cell is not a DESTROY cell with correct circuit ID.
    pub fn shutdown_with(&mut self, cell: Cell) -> &mut Self
    where
        Cell: CellLike,
    {
        assert_eq!(cell.circuit(), self.input.id().get(), "circuit ID mismatch");
        assert_eq!(cell.command(), Destroy::ID, "cell is not DESTROY");

        // SAFETY: Cell has been checked
        unsafe { self.shutdown_with_unchecked(cell) }
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
}

impl<Cell, Cache> CircuitOutput<'_, Cached<Cell, Cache>>
where
    Cell: Cachable + From<Destroy> + CellLike,
    Cache: CellCache,
{
    /// Shutdown circuit.
    ///
    /// Shut down circuit with a [`DestroyReason`].
    ///
    /// See [`shutdown_with`] for shutdown sequence.
    ///
    /// # Panics
    ///
    /// It should _never_ panics, unless the `Cell` implementation is weird
    /// to not convert [`Destroy`] cell faithfully.
    pub fn shutdown(&mut self, cache: Cache, reason: DestroyReason) -> &mut Self {
        let cell = Destroy::new(cache.get_cached(), self.input.id(), reason);
        self.shutdown_with(Cached::new(cache, cell.into()))
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
