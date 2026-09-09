//! Lowlevel relay cell type definitions and processing.

use std::fmt::{Debug, Formatter, Result as FmtResult};
use std::mem::ManuallyDrop;

use onioncloud_ll_cell::fixed::FixedCell;

pub mod error;
mod traits;
pub mod v0;
pub mod v1;
pub mod ver;

pub use traits::*;

/// Cell auto-return type.
///
/// Automatically returns cell on drop.
/// Useful to implement [`TryFromRelay`].
pub struct AutoReturnCell<'a> {
    p: &'a mut Option<FixedCell>,
    c: ManuallyDrop<FixedCell>,
}

impl Drop for AutoReturnCell<'_> {
    fn drop(&mut self) {
        // SAFETY: cell will not be used again.
        unsafe { *self.p = Some(ManuallyDrop::take(&mut self.c)) }
    }
}

impl Debug for AutoReturnCell<'_> {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        f.debug_struct("AutoReturnCell")
            .field("cell", &*self.c)
            .finish_non_exhaustive()
    }
}

impl<'a> AutoReturnCell<'a> {
    #[inline]
    pub fn new(cell: &'a mut Option<FixedCell>) -> Option<Self> {
        Some(Self {
            c: ManuallyDrop::new(cell.take()?),
            p: cell,
        })
    }

    #[inline]
    pub fn cell(&self) -> &FixedCell {
        &self.c
    }

    #[inline]
    pub fn into_inner(self) -> FixedCell {
        let mut this = ManuallyDrop::new(self);
        // SAFETY: cell will not be used again.
        unsafe { ManuallyDrop::take(&mut this.c) }
    }
}
