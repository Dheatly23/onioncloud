use std::error::Error;
use std::io::Error as IoError;

use rustls::Error as RustlsError;

use super::{ChannelConfig, ChannelInput, ChannelOutput, Timeout};
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
    for<'a> Handle<ChannelInput<'a, Self::Cell, Self::CircMeta>, Return = Result<ChannelOutput, Self::Error>>
    + Handle<(ControlMsg<Self::ControlMsg>, ChannelInput<'a, Self::Cell, Self::CircMeta>), Return = Result<Self::Error>>
    + Handle<(Timeout, ChannelInput<'a, Self::Cell, Self::CircMeta>), Return = Result<Self::Error>>
{
    /// Error type.
    type Error: Error + From<IoError> + From<RustlsError>;
    /// Channel configuration.
    type Config: ChannelConfig;
    /// Control message.
    type ControlMsg: Send;
    /// Cell type.
    type Cell: Send;
    /// Circuit metadata.
    type CircMeta: Send;

    fn new(config: &Self::Config) -> Self;
}
