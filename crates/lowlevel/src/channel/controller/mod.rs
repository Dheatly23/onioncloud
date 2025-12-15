pub mod user;

use std::fmt::{Debug, Display};
use std::io::Error as IoError;
use std::num::NonZeroU32;

use rustls::Error as RustlsError;

use super::{ChannelConfig, ChannelInput, ChannelOutput};
use crate::runtime::Runtime;
use crate::util::sans_io::event::{ChannelClosed, ChildCellMsg, ControlMsg, Timeout};
use crate::util::sans_io::{CellMsgPause, Handle};

pub use user::{UserConfig, UserControlMsg, UserController};

/// Trait for a channel controller.
///
/// # Implementers Note
///
/// Implementers _must_ implement [`Handle`]rs to handle incoming events. Values to be handled are:
/// - `(ChannelInput<'a>, CellMapRef<'a, 'b, Self::Runtime, Self::Cell, Self::CircMeta>)`
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
/// - [`ChildCellMsg<Self::Cell>`]
///
///   Cell message handler. Returns [`CellMsgPause`] to pause next cell message handling.
pub trait ChannelController:
    Send
    + for<'a, 'b> Handle<
        (
            &'a Self::Runtime,
            ChannelInput<'a, 'b, Self::Runtime, Self::Cell, Self::CircMeta>,
        ),
        Return = Result<ChannelOutput, Self::Error>,
    > + Handle<ControlMsg<Self::ControlMsg>, Return = Result<(), Self::Error>>
    + Handle<ChildCellMsg<Self::Cell>, Return = Result<CellMsgPause, Self::Error>>
    + for<'a> Handle<
        ChannelClosed<'a, NonZeroU32, Self::Cell, Self::CircMeta>,
        Return = Result<(), Self::Error>,
    > + Handle<Timeout, Return = Result<(), Self::Error>>
{
    /// Runtime.
    type Runtime: 'static + Runtime;
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
    fn channel_cap(cfg: &Self::Config) -> usize {
        // Discard configuration
        let _ = cfg;
        256
    }

    /// Get circuit aggregation channel capacity.
    fn channel_aggregate_cap(cfg: &Self::Config) -> usize {
        // Discard configuration
        let _ = cfg;
        256
    }

    fn new(rt: &Self::Runtime, cfg: Self::Config) -> Self;
}
