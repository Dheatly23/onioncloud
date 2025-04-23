use std::error::Error;
use std::io::Error as IoError;

use rustls::Error as RustlsError;

use super::{ChannelConfig, ChannelInput, ChannelOutput};
use crate::util::sans_io::Handle;

/// Trait for a channel controller.
pub trait ChannelController:
    for<'a> Handle<ChannelInput<'a>, Return = Result<ChannelOutput, Self::Error>>
{
    type Error: Error + From<IoError> + From<RustlsError>;
    /// Configuration for channel.
    type Config: ChannelConfig;

    fn new(config: Self::Config) -> Self;
}
