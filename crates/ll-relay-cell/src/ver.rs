//! Versioned relay wrapper.

use onioncloud_ll_cell::fixed::FixedCell;

use crate::traits::DynRelayVersion;
use crate::v0::V0;
use crate::v1::V1;

/// Versioned relay type.
///
/// Useful if you protocol version is defined at runtime.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord)]
#[non_exhaustive]
pub enum Ver {
    /// V0
    #[default]
    V0,
    /// V1
    V1,
}

impl DynRelayVersion for Ver {
    #[inline]
    fn command(&self, cell: &FixedCell) -> u8 {
        match self {
            Self::V0 => V0.command(cell),
            Self::V1 => V1.command(cell),
        }
    }

    #[inline]
    fn stream_id(&self, cell: &FixedCell) -> u16 {
        match self {
            Self::V0 => V0.stream_id(cell),
            Self::V1 => V1.stream_id(cell),
        }
    }

    #[inline]
    fn len(&self, cell: &FixedCell) -> u16 {
        match self {
            Self::V0 => V0.len(cell),
            Self::V1 => V1.len(cell),
        }
    }

    #[inline]
    fn data_padding<'a>(&self, cell: &'a FixedCell) -> &'a [u8] {
        match self {
            Self::V0 => V0.data_padding(cell),
            Self::V1 => V1.data_padding(cell),
        }
    }

    #[inline]
    fn set_command(&self, cell: &mut FixedCell, command: u8) {
        match self {
            Self::V0 => V0.set_command(cell, command),
            Self::V1 => V1.set_command(cell, command),
        }
    }

    #[inline]
    fn set_stream_id(&self, cell: &mut FixedCell, stream_id: u16) {
        match self {
            Self::V0 => V0.set_stream_id(cell, stream_id),
            Self::V1 => V1.set_stream_id(cell, stream_id),
        }
    }

    #[inline]
    fn set_len(&self, cell: &mut FixedCell, len: u16) {
        match self {
            Self::V0 => V0.set_len(cell, len),
            Self::V1 => V1.set_len(cell, len),
        }
    }

    #[inline]
    fn data_padding_mut<'a>(&self, cell: &'a mut FixedCell) -> &'a mut [u8] {
        match self {
            Self::V0 => V0.data_padding_mut(cell),
            Self::V1 => V1.data_padding_mut(cell),
        }
    }
}
