use std::error::Error;
use std::io::Error as IoError;

use rustls::Error as RustlsError;

use super::{ChannelConfig, ChannelInput, ChannelOutput};
use crate::util::sans_io::Handle;

/// Marker type for channel timeout.
#[derive(Debug, PartialEq, Eq)]
pub struct Timeout;

/// Wrapper type for signalling a control message.
pub struct ControlMsg<M>(pub M);

impl<M> ControlMsg<M> {
    /// Unwraps into inner value.
    pub fn into_inner(self) -> M {
        self.0
    }
}

/// Trait for a channel controller.
pub trait ChannelController:
    Send
    + for<'a, 'b> Handle<
        ChannelInput<'a, 'b, Self::Cell, Self::CircMeta>,
        Return = Result<ChannelOutput, Self::Error>,
    > + for<'a, 'b> Handle<
        (
            ControlMsg<Self::ControlMsg>,
            ChannelInput<'a, 'b, Self::Cell, Self::CircMeta>,
        ),
        Return = Result<ChannelOutput, Self::Error>,
    > + for<'a, 'b> Handle<
        (Timeout, ChannelInput<'a, 'b, Self::Cell, Self::CircMeta>),
        Return = Result<ChannelOutput, Self::Error>,
    >
{
    /// Error type.
    type Error: 'static + Error + Send + Sync + From<IoError> + From<RustlsError>;
    /// Channel configuration.
    type Config: ChannelConfig + Send + Sync;
    /// Control message.
    type ControlMsg: 'static + Send;
    /// Cell type.
    type Cell: 'static + Send;
    /// Circuit metadata.
    type CircMeta: Send;

    fn new(config: &Self::Config) -> Self;
}
