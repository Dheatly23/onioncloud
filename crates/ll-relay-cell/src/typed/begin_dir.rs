//! `BEGIN_DIR` relay cell.

use std::ops::{Deref, DerefMut};
use std::mem::size_of;
use std::num::NonZeroU16;

use onioncloud_ll_cell::fixed::FixedCell;

use crate::traits::{RelayVersion, DynRelayVersion};
use crate::v0::V0;
use crate::v1::V1;
use crate::AutoReturnCell;
use crate::error::{CellCastError, ZeroStreamID, CellFormatError};

/// `BEGIN_DIR` relay ID.
pub const ID: u8 = 13;

/// `BEGIN_DIR` relay cell.
pub struct BeginDir<V = V0> {
    stream_id: NonZeroU16,
    cell: FixedCell,
    version: V,
}

impl<V: DynRelayVersion> TryFromRelay<V> for BeginDir<V> {
    type Error = CellCastError;

    fn try_from_relay_versioned(version: V, cell: &mut Option<FixedCell>) -> Result<Option<Self>, Self::Error> {
        let Some(cell) = AutoReturnCell(cell) else { return Ok(None) };
        let c = cell.cell();
        if version.command(c) != ID {
            return Ok(None);
        }
        let stream_id = NonZeroU16::new(version.stream_id(cell)).ok_or(ZeroStreamID)?;
        version.data_checked(c).ok_or(CellFormatError)?;
        let mut cell = cell.into_inner();
        version.set_len(&mut cell, 0);
        Ok(Some(Self {
            stream_id,
            cell,
            version,
        }))
    }
}

impl<V> From<BeginDir<V>> for FixedCell {
    #[inline]
    fn from(v: BeginDir<V>) -> FixedCell {
        v.into_inner()
    }
}

impl BeginDir<V0> {
    /// Create new [`BeginDir`] with relay version 0.
    #[inline]
    #[must_use]
    pub fn new_v0(mut cell: FixedCell, stream_id: NonZeroU16) -> Self {
        assert!(data.len() <= size_of::<<V0 as RelayVersion>::Data>(), "data is too long");
        Self::new(cell, V0, stream_id)
    }
}

impl BeginDir<V1> {
    /// Create new [`BeginDir`] with relay version 1.
    #[inline]
    #[must_use]
    pub fn new_v1(mut cell: FixedCell, stream_id: NonZeroU16) -> Self {
        assert!(data.len() <= size_of::<<V1 as RelayVersion>::Data>(), "data is too long");
        Self::new(cell, V1, stream_id)
    }
}

impl<V: DynRelayVersion> BeginDir<V> {
    /// Create new [`BeginDir`].
    #[must_use]
    pub fn new(mut cell: FixedCell, version: V, stream_id: NonZeroU16) -> Self {
        version.set_len(&mut cell, 0);
        version.set_command(&mut cell, ID);
        version.set_stream_id(&mut cell, stream_id.into());
        Self { stream_id, cell, version }
    }

    /// Gets stream ID.
    #[inline]
    #[must_use]
    pub fn stream_id(&self) -> NonZeroU16 {
        self.stream_id
    }

    /// Sets stream ID.
    #[inline]
    pub fn set_stream_id(&mut self, stream_id: NonZeroU16) {
        self.stream_id = stream_id;
        self.version.set_stream_id(&mut self.cell, stream_id.into());
    }
}

impl<V> BeginDir<V> {
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
