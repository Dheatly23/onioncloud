pub mod dir;

use std::fmt::{Debug, Display};
use std::num::NonZeroU32;
use std::sync::Arc;

use super::{
    CellMsg, CellMsgPause, CircuitInput, CircuitOutput, ControlMsg, StreamCellMsg, Timeout,
};
use crate::cell::destroy::DestroyReason;
use crate::util::cell_map::CellMap;
use crate::util::sans_io::Handle;

pub trait CircuitController:
    Send
    + for<'a> Handle<
        (
            CircuitInput<'a, Self::Cell>,
            &'a mut CellMap<Self::Cell, Self::StreamMeta>,
        ),
        Return = Result<CircuitOutput, Self::Error>,
    > + Handle<Timeout, Return = Result<(), Self::Error>>
    + Handle<ControlMsg<Self::ControlMsg>, Return = Result<(), Self::Error>>
    + Handle<CellMsg<Self::Cell>, Return = Result<CellMsgPause, Self::Error>>
    + Handle<StreamCellMsg<Self::Cell>, Return = Result<CellMsgPause, Self::Error>>
{
    type Config: 'static + Send + Sync + Display;
    type Error: 'static + Debug + Display + Send + Sync;
    type ControlMsg: 'static + Send;
    type Cell: 'static + Send;
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
