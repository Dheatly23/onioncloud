pub mod user_controller;

use std::fmt::{Debug, Display};
use std::io::Error as IoError;
use std::sync::Arc;

use rustls::Error as RustlsError;

use super::circ_map::CircuitMap;
use super::{CellMsgPause, ChannelConfig, ChannelInput, ChannelOutput};
use crate::util::sans_io::Handle;

pub use user_controller::UserController;

/// Marker type for channel timeout.
#[derive(Debug, PartialEq, Eq)]
pub struct Timeout;

/// Wrapper type for signalling a control message.
#[derive(Debug)]
pub struct ControlMsg<M>(pub M);

impl<M> ControlMsg<M> {
    /// Unwraps into inner value.
    pub fn into_inner(self) -> M {
        self.0
    }
}

/// Wrapper type for signalling a cell message.
#[derive(Debug)]
pub struct CellMsg<M>(pub M);

impl<M> CellMsg<M> {
    /// Unwraps into inner value.
    pub fn into_inner(self) -> M {
        self.0
    }
}

/// Trait for a channel controller.
///
/// # Implementers Note
///
/// Implementers _must_ implement [`Handle`]rs to handle incoming events. Values to be handled are:
/// - [`(ChannelInput<'a>, &'a mut CircuitMap<Self::Cell, Self::CircMeta>)`]
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
            &'a mut CircuitMap<Self::Cell, Self::CircMeta>,
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
