pub mod dir;

use std::fmt::{Debug, Display};
use std::num::NonZeroU32;
use std::sync::Arc;

use super::{CellMsg, CellMsgPause, CircuitInput, CircuitOutput, ControlMsg, Timeout};
use crate::util::sans_io::Handle;

pub trait CircuitController:
    Send
    + for<'a> Handle<
        CircuitInput<'a, Self::Cell>,
        Return = Result<CircuitOutput<'a, Self::Cell>, Self::Error>,
    > + Handle<Timeout, Return = Result<(), Self::Error>>
    + Handle<ControlMsg<Self::ControlMsg>, Return = Result<(), Self::Error>>
    + Handle<CellMsg<Self::Cell>, Return = Result<CellMsgPause, Self::Error>>
{
    type Config: 'static + Send + Sync;
    type Error: 'static + Debug + Display + Send + Sync;
    type ControlMsg: 'static + Send;
    type Cell: 'static + Send;

    fn new(cfg: Arc<dyn Send + Sync + AsRef<Self::Config>>, circ_id: NonZeroU32) -> Self;
}
