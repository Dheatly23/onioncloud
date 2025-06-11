pub mod user;

use std::fmt::{Debug, Display};
use std::io::Error as IoError;
use std::sync::Arc;

use rustls::Error as RustlsError;

use super::{
    CellMsg, CellMsgPause, ChannelConfig, ChannelInput, ChannelOutput, ControlMsg, Timeout,
};
use crate::util::cell_map::CellMap;
use crate::util::sans_io::Handle;

pub use user::{UserConfig, UserControlMsg, UserController};

/// Trait for a channel controller.
///
/// # Implementers Note
///
/// Implementers _must_ implement [`Handle`]rs to handle incoming events. Values to be handled are:
/// - [`(ChannelInput<'a>, &'a mut CellMap<Self::Cell, Self::CircMeta>)`]
///
///   Universal handler for channel inputs and circuit map. Will be called after all the other events.
///   Returns [`ChannelOutput`] to control things like shutdown, timer, and cell message handling.
///
/// - [`Timeout`]
///
///   Timeout handler.
///
/// - [`ControlMsg<Self::ControlMsg>`]
///
///   Control message handler.
///
/// - [`CellMsg<Self::Cell>`]
///
///   Cell message handler. Returns [`CellMsgPause`] to pause next cell message handling.
pub trait ChannelController:
    Send
    + for<'a> Handle<
        (
            ChannelInput<'a>,
            &'a mut CellMap<Self::Cell, Self::CircMeta>,
        ),
        Return = Result<ChannelOutput, Self::Error>,
    > + Handle<ControlMsg<Self::ControlMsg>, Return = Result<(), Self::Error>>
    + Handle<CellMsg<Self::Cell>, Return = Result<CellMsgPause, Self::Error>>
    + Handle<Timeout, Return = Result<(), Self::Error>>
{
    /// Error type.
    type Error: 'static + Debug + Display + Send + Sync + From<IoError> + From<RustlsError>;
    /// Channel configuration.
    type Config: 'static + ChannelConfig + Send + Sync;
    /// Control message.
    type ControlMsg: 'static + Send;
    /// Cell type.
    type Cell: 'static + Send;
    /// Circuit metadata.
    type CircMeta: 'static + Send;

    /// Get circuit channel capacity.
    fn channel_cap(_config: &Self::Config) -> usize {
        256
    }

    /// Get circuit aggregation channel capacity.
    fn channel_aggregate_cap(_config: &Self::Config) -> usize {
        256
    }

    fn new(config: Arc<dyn Send + Sync + AsRef<Self::Config>>) -> Self;
}
