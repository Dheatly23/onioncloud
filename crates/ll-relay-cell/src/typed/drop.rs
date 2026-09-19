//! `DROP` relay cell.

use onioncloud_ll_cell::fixed::FixedCell;

use crate::AutoReturnCell;
use crate::error::{CellCastError, CellFormatError, NonZeroStreamID};
use crate::traits::{DynRelayVersion, TryFromRelay};
use crate::v0::V0;
use crate::v1::V1;

/// `DROP` relay cell.
pub struct Drop<V = V0> {
    cell: FixedCell,
    version: V,
}

impl<V: DynRelayVersion> TryFromRelay<V> for Drop<V> {
    type Error = CellCastError;

    fn try_from_relay_versioned(
        version: V,
        cell: &mut Option<FixedCell>,
    ) -> Result<Option<Self>, Self::Error> {
        let Some(cell) = AutoReturnCell::new(cell) else {
            return Ok(None);
        };
        let c = cell.cell();
        if version.command(c) != Self::ID {
            return Ok(None);
        }
        if version.stream_id(c) != 0 {
            return Err(NonZeroStreamID.into());
        }
        version
            .data_checked(c)
            .ok_or_else(CellFormatError::default)?;
        Ok(Some(Self {
            cell: cell.into_inner(),
            version,
        }))
    }
}

impl<V> From<Drop<V>> for FixedCell {
    #[inline]
    fn from(v: Drop<V>) -> FixedCell {
        v.into_inner()
    }
}

impl Drop<V0> {
    /// Create new [`Drop`] with relay version 0.
    #[inline]
    #[must_use]
    pub fn new_v0(cell: FixedCell) -> Self {
        Self::new(cell, V0)
    }
}

impl Drop<V1> {
    /// Create new [`Drop`] with relay version 1.
    #[inline]
    #[must_use]
    pub fn new_v1(cell: FixedCell) -> Self {
        Self::new(cell, V1)
    }
}

impl<V: DynRelayVersion> Drop<V> {
    /// Create new [`Drop`].
    #[must_use]
    pub fn new(mut cell: FixedCell, version: V) -> Self {
        version.set_len(&mut cell, 0);
        version.set_command(&mut cell, Self::ID);
        version.set_stream_id(&mut cell, 0);
        Self { cell, version }
    }
}

impl<V> Drop<V> {
    /// `DROP` relay ID.
    pub const ID: u8 = 10;

    /// Gets reference to relay version.
    #[inline]
    #[must_use]
    pub fn version(&self) -> &V {
        &self.version
    }

    /// Unwraps into inner cell.
    #[inline]
    #[must_use]
    pub fn into_inner(self) -> FixedCell {
        self.cell
    }
}
