use super::ChannelConfig;
use crate::util::sans_io::Handle;

/// Trait for a channel controller.
pub trait ChannelController {
    /// Configuration for channel.
    type Config: ChannelConfig;

    fn new(config: Self::Config) -> Self;
}
