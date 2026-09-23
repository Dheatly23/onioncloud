//! Circuit handler trait definition.

use std::error::Error;
use std::marker::PhantomData;
use std::num::NonZeroU32;
use std::pin::Pin;
use std::task::Context;
use std::thread::panicking;
use std::time::Instant;

use onioncloud_ll_cell::cache::{Cachable, CellCache, CellCacheExt as _};
use onioncloud_ll_cell::cell::{Cell, CellHeader, CellTy};
use tracing::warn;

/// Circuit handler.
pub trait CircuitHandle {
    /// Error type.
    type Error: Error;

    /// General handle.
    ///
    /// It is guaranteed to be eventually called by channel controller after calling other methods.
    /// It will be called when channel controller is polled.
    /// It may be called multiple times within the same poll call,
    /// use [`Handle::is_same_poll`] to optimize it.
    fn handle(self: Pin<&mut Self>, args: Handle) -> Result<Return, Self::Error>;

    /// Returns [`true`] if handle is ready to receive cell.
    ///
    /// If it returns [`false`], it is guaranteed that the next [`Self::handle`] call will not contain cell.
    /// (AKA [`Handle::take_cell`] will return [`None`]).
    ///
    /// NOTE: Not receiving cell may blocks other handlers from receiving their cell.
    fn recv_ready(&self) -> bool;

    /// Sets circuit ID.
    ///
    /// This will be called when setting up circuit handle for the first time.
    fn set_circ_id(self: Pin<&mut Self>, circ_id: NonZeroU32) -> Result<(), Self::Error>;
}

#[derive(Debug)]
pub struct Handle<'a, 'b> {
    /// Context.
    pub(crate) ctx: &'a mut Context<'b>,

    /// Circuit ID.
    pub(crate) circ_id: NonZeroU32,

    /// Current time.
    pub(crate) time: Instant,

    /// `true` if in the same poll cycle.
    pub(crate) is_same_poll: bool,

    /// `true` if timeout has been reached.
    pub(crate) is_timeout: bool,

    /// `true` if controller is ready to send cell.
    pub(crate) send_ready: bool,

    /// Cell that is received.
    pub(crate) cell: Option<(CellTy, u8)>,

    pub(crate) _phantom: PhantomData<*mut u8>,
}

impl Drop for Handle<'_, '_> {
    fn drop(&mut self) {
        #[cfg(debug_assertions)]
        if !panicking() && self.cell.is_some() {
            warn!("Handle dropped before received cell is taken. This might be a bug.");
        }
    }
}

impl Cachable for Handle<'_, '_> {
    #[inline]
    fn cache<C: ?Sized + CellCache>(mut self, c: &C) {
        if let Some((t, _)) = self.cell.take() {
            c.discard(t);
        }
    }
}

impl<'a, 'b> Handle<'a, 'b> {
    /// Gets current async context.
    #[inline]
    pub fn ctx(&mut self) -> &mut Context<'b> {
        self.ctx
    }

    /// Gets circuit ID.
    ///
    /// It is guaranteed to be the same for the lifetime of [`CircuitHandle`].
    #[inline]
    pub fn circ_id(&self) -> NonZeroU32 {
        self.circ_id
    }

    /// Gets current time.
    ///
    /// Use this instead of checking global time [`Instant::now`] because runtime may do time emulation.
    #[inline]
    pub fn time(&self) -> Instant {
        self.time
    }

    /// Checks if timeout had fired.
    #[inline]
    pub fn is_timeout(&self) -> bool {
        self.is_timeout
    }

    /// Checks if handle is in the same polling cycle.
    ///
    /// # About Polling Cycle
    ///
    /// Channel controller may poll it's [`CircuitHandle`] multiple times within the same [`poll`](`std::future::Future::poll`) call.
    /// Implementers of [`CircuitHandle`] may do optimization (eg. not repolling channel) by using this flag.
    #[inline]
    pub fn is_same_poll(&self) -> bool {
        self.is_same_poll
    }

    /// Takes received cell destined to this handle.
    #[inline]
    pub fn take_cell(&mut self) -> Option<Cell> {
        let (cell, command) = self.cell.take()?;
        Some(Cell::new(
            CellHeader {
                command,
                circuit: self.circ_id.get(),
            },
            cell,
        ))
    }

    /// Checks if controller is ready to send cell.
    #[inline]
    pub fn send_ready(&self) -> bool {
        self.send_ready
    }
}

/// Builder for [`Handle`].
#[derive(Debug, Default)]
pub struct HandleBuilder<'a, 'b> {
    /// Context.
    ctx: Option<&'a mut Context<'b>>,

    /// Circuit ID.
    circ_id: Option<NonZeroU32>,

    /// Current time.
    time: Option<Instant>,

    /// `true` if in the same poll cycle.
    is_same_poll: bool,

    /// `true` if timeout has been reached.
    is_timeout: bool,

    /// `true` if controller is ready to send cell.
    send_ready: bool,

    /// Cell that is received.
    cell: Option<(CellTy, u8)>,
}

impl<'a, 'b> HandleBuilder<'a, 'b> {
    /// Sets async context. **REQUIRED**
    #[inline]
    pub fn ctx(&mut self, ctx: &'a mut Context<'b>) -> &mut Self {
        assert!(self.ctx.is_none(), "ctx has already been set");
        self.ctx = Some(ctx);
        self
    }

    /// Sets circuit ID. **REQUIRED**
    #[inline]
    pub fn circ_id(&mut self, circ_id: NonZeroU32) -> &mut Self {
        assert!(self.circ_id.is_none(), "circ_id has already been set");
        self.circ_id = Some(circ_id);
        self
    }

    /// Sets current time. **REQUIRED**
    #[inline]
    pub fn time(&mut self, time: Instant) -> &mut Self {
        assert!(self.time.is_none(), "time has already been set");
        self.time = Some(time);
        self
    }

    /// Marks in same poll cycle.
    #[inline]
    pub fn is_same_poll(&mut self, v: bool) -> &mut Self {
        self.is_same_poll = v;
        self
    }

    /// Marks timeout.
    #[inline]
    pub fn is_timeout(&mut self, v: bool) -> &mut Self {
        self.is_timeout = v;
        self
    }

    /// Marks ready to send cell.
    #[inline]
    pub fn send_ready(&mut self, v: bool) -> &mut Self {
        self.send_ready = v;
        self
    }

    /// Sets cell to be received.
    #[inline]
    pub fn cell(&mut self, cell: Cell) -> &mut Self {
        assert!(self.cell.is_none(), "cell has already been set");
        self.cell = Some((cell.data, cell.header.command));
        self
    }

    /// Builds [`Handle`].
    ///
    /// # Panics
    ///
    /// Panics if any of the required fields are not set.
    #[inline]
    #[must_use]
    pub fn build(&mut self) -> Handle<'a, 'b> {
        const REQ_NOT_SET: &str = "required field is not set";

        Handle {
            ctx: self.ctx.take().expect(REQ_NOT_SET),
            circ_id: self.circ_id.take().expect(REQ_NOT_SET),
            time: self.time.take().expect(REQ_NOT_SET),
            cell: self.cell.take(),
            is_same_poll: self.is_same_poll,
            is_timeout: self.is_timeout,
            send_ready: self.send_ready,
            _phantom: PhantomData,
        }
    }
}

/// Return value of [`CircuitHandle::handle`].
#[derive(Debug)]
#[must_use = "handle return value must be returned"]
pub struct Return {
    /// Set this to shut down handle.
    ///
    /// After shutdown, handle will be dropped.
    pub is_shutdown: bool,

    /// Set or reset timeout.
    ///
    /// If set to [`None`], it cancels the current timeout.
    /// Keep setting it to ensure timeout is not cancelled.
    pub timeout: Option<Instant>,

    /// Cell to be send.
    pub(crate) cell: Option<(CellTy, u8)>,

    #[cfg(debug_assertions)]
    circ_id: NonZeroU32,

    _phantom: PhantomData<*mut u8>,
}

impl Cachable for Return {
    #[inline]
    fn cache<C: ?Sized + CellCache>(mut self, c: &C) {
        if let Some((t, _)) = self.cell.take() {
            c.discard(t);
        }
    }
}

impl Return {
    /// Creates new [`Return`].
    #[inline]
    pub fn new(handle: &Handle) -> Self {
        let _ = handle;

        Self {
            is_shutdown: false,
            timeout: None,
            cell: None,
            #[cfg(debug_assertions)]
            circ_id: handle.circ_id,
            _phantom: PhantomData,
        }
    }

    /// Marks handler for shutdown.
    #[inline]
    pub fn shutdown(mut self) -> Self {
        self.is_shutdown = true;
        self
    }

    /// Sets timeout for handler.
    #[inline]
    pub fn with_timeout(mut self, timeout: Instant) -> Self {
        self.timeout = Some(timeout);
        self
    }

    /// Sets cell to be send.
    ///
    /// **NOTE: DO NOT** set this unless [`Handle::send_ready`] returns [`true`]!
    /// Sending cell when controller is not ready will cause warning and the cell will be dropped.
    #[inline]
    pub fn set_cell(&mut self, cell: Cell) {
        #[cfg(debug_assertions)]
        if cell.header.circuit != self.circ_id.into() {
            warn!(
                "Circuit ID to be send mismatch! This might be a bug. (expected: {}, got: {})",
                self.circ_id, cell.header.circuit
            );
        }

        self.cell = Some((cell.data, cell.header.command));
    }

    /// Sets cell to be send.
    ///
    /// This is a convenience method around [`Self::set_cell`].
    #[inline]
    pub fn with_cell(mut self, cell: Cell) -> Self {
        self.set_cell(cell);
        self
    }
}
