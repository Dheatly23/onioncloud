pub mod dir;

use std::fmt::{Debug, Display};
use std::num::NonZeroU32;
use std::sync::Arc;

use super::{CircuitInput, CircuitOutput};
use crate::cell::destroy::DestroyReason;
use crate::util::cell_map::CellMap;
use crate::util::sans_io::event::{ChildCellMsg, ControlMsg, ParentCellMsg, Timeout};
use crate::util::sans_io::{CellMsgPause, Handle};

/// Trait for a circuit controller.
///
/// # Implementers Note
///
/// Implementers _must_ implement [`Handle`]rs to handle incoming events. Values to be handled are:
/// - [`(CircuitInput<'a>, &'a mut CellMap<Self::StreamCell, Self::StreamMeta>)`]
///
///   Universal handler for circuit inputs and stream map. Will be called after all the other events.
///   Returns [`CircuitOutput`] to control things like shutdown, timer, and cell message handling.
///
/// - [`Timeout`]
///
///   Timeout handler.
///
/// - [`ControlMsg<Self::ControlMsg>`]
///
///   Control message handler.
///
/// - [`ParentCellMsg<Self::StreamCell>`]
///
///   Channel cell message handler. Returns [`CellMsgPause`] to pause next cell message handling.
///
/// - [`ChildCellMsg<Self::StreamCell>`]
///
///   Stream cell message handler. Returns [`CellMsgPause`] to pause next cell message handling.
pub trait CircuitController:
    Send
    + for<'a> Handle<
        (
            CircuitInput<'a, Self::Cell>,
            &'a mut CellMap<Self::StreamCell, Self::StreamMeta>,
        ),
        Return = Result<CircuitOutput, Self::Error>,
    > + Handle<Timeout, Return = Result<(), Self::Error>>
    + Handle<ControlMsg<Self::ControlMsg>, Return = Result<(), Self::Error>>
    + Handle<ChildCellMsg<Self::StreamCell>, Return = Result<CellMsgPause, Self::Error>>
    + Handle<ParentCellMsg<Self::Cell>, Return = Result<CellMsgPause, Self::Error>>
{
    /// Controller configuration.
    type Config: 'static + Send + Sync;
    /// Error type.
    type Error: 'static + Debug + Display + Send + Sync;
    /// Control message.
    type ControlMsg: 'static + Send;
    /// Cell type from channel controller.
    type Cell: 'static + Send;
    /// Cell type to stream controllers.
    type StreamCell: 'static + Send;
    /// Stream metadata.
    type StreamMeta: 'static + Send;

    /// Get circuit channel capacity.
    fn channel_cap(_config: &Self::Config) -> usize {
        256
    }

    /// Get circuit aggregation channel capacity.
    fn channel_aggregate_cap(_config: &Self::Config) -> usize {
        256
    }

    /// Create new [`CircuitController`].
    fn new(cfg: Arc<dyn Send + Sync + AsRef<Self::Config>>, circ_id: NonZeroU32) -> Self;

    /// Set link version.
    ///
    /// By default, it is ignored.
    /// Controller can use the value to inform which link protocol version is used.
    fn set_linkver(&mut self, linkver: u16) {
        let _ = linkver;
    }

    /// Get destroy reason from error value.
    ///
    /// Defaults to [`DestroyReason::Internal`].
    fn error_reason(err: Self::Error) -> DestroyReason {
        let _ = err;
        DestroyReason::Internal
    }

    /// Create DESTROY cell from reason.
    fn make_destroy_cell(&mut self, reason: DestroyReason) -> Self::Cell;
}
