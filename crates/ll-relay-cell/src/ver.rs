//! Versioned relay wrapper.

use std::ops::{Deref, DerefMut};

use onioncloud_ll_cell::fixed::FixedCell;

use crate::traits::{DynRelayWrapper, DynRelayWrapperRef, IntoRelayWrapper};
use crate::v0::V0Wrapper;
use crate::v1::V1Wrapper;

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

impl IntoRelayWrapper for Ver {
    type RefWrapperTarget<'a> = dyn DynRelayWrapperRef + 'a;
    type RefWrapper<'a> = &'a (dyn DynRelayWrapperRef + 'a);
    type MutWrapperTarget<'a> = dyn DynRelayWrapper + 'a;
    type MutWrapper<'a> = &'a mut (dyn DynRelayWrapper + 'a);

    fn wrap<'a>(&self, cell: &'a FixedCell) -> Self::RefWrapper<'a> {
        match self {
            Self::V0 => <&V0Wrapper>::from(cell),
            Self::V1 => <&V1Wrapper>::from(cell),
        }
    }

    fn wrap_mut<'a>(&self, cell: &'a mut FixedCell) -> Self::MutWrapper<'a> {
        match self {
            Self::V0 => <&mut V0Wrapper>::from(cell),
            Self::V1 => <&mut V1Wrapper>::from(cell),
        }
    }
}
