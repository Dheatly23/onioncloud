//! `DATA` relay cell.

use std::fmt::{Debug, Formatter, Result as FmtResult};
use std::mem::size_of;
use std::num::NonZeroU16;

use onioncloud_ll_cell::fixed::FixedCell;

use crate::AutoReturnCell;
use crate::error::{CellCastError, CellFormatError, ZeroStreamID};
use crate::traits::{DynRelayVersion, RelayVersion, TryFromRelay};
use crate::utils::base64u_encode;
use crate::v0::V0;
use crate::v1::V1;

/// `DATA` relay cell.
pub struct Data<V = V0> {
    stream_id: NonZeroU16,
    cell: FixedCell,
    version: V,
}

impl<V: Debug + DynRelayVersion> Debug for Data<V> {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        let data = base64u_encode(self.data());
        f.debug_struct("Data")
            .field("version", &self.version)
            .field("stream_id", &self.stream_id)
            .field("data", &data)
            .finish()
    }
}

impl<V: DynRelayVersion> TryFromRelay<V> for Data<V> {
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
        let stream_id = NonZeroU16::new(version.stream_id(c)).ok_or(ZeroStreamID)?;
        version
            .data_checked(c)
            .ok_or_else(CellFormatError::default)?;
        Ok(Some(Self {
            stream_id,
            cell: cell.into_inner(),
            version,
        }))
    }
}

impl<V> From<Data<V>> for FixedCell {
    #[inline]
    fn from(v: Data<V>) -> FixedCell {
        v.into_inner()
    }
}

impl Data<V0> {
    /// Create new [`Data`] with relay version 0.
    ///
    /// # Panics
    ///
    /// Panics if data does not fit cell.
    #[inline]
    #[must_use]
    pub fn new_v0(cell: FixedCell, stream_id: NonZeroU16, data: &[u8]) -> Self {
        assert!(
            data.len() <= size_of::<<V0 as RelayVersion>::Data>(),
            "data is too long"
        );
        Self::new(cell, V0, stream_id, data)
    }
}

impl Data<V1> {
    /// Create new [`Data`] with relay version 1.
    ///
    /// # Panics
    ///
    /// Panics if data does not fit cell.
    #[inline]
    #[must_use]
    pub fn new_v1(cell: FixedCell, stream_id: NonZeroU16, data: &[u8]) -> Self {
        assert!(
            data.len() <= size_of::<<V1 as RelayVersion>::Data>(),
            "data is too long"
        );
        Self::new(cell, V1, stream_id, data)
    }
}

impl<V: DynRelayVersion> Data<V> {
    /// Create new [`Data`].
    ///
    /// # Panics
    ///
    /// Panics if data does not fit cell.
    #[must_use]
    pub fn new(mut cell: FixedCell, version: V, stream_id: NonZeroU16, data: &[u8]) -> Self {
        let l = u16::try_from(data.len()).expect("data is too long");
        version
            .data_padding_mut(&mut cell)
            .get_mut(..data.len())
            .expect("data is too long")
            .copy_from_slice(data);
        version.set_len(&mut cell, l);
        version.set_command(&mut cell, Self::ID);
        version.set_stream_id(&mut cell, stream_id.into());
        Self {
            stream_id,
            cell,
            version,
        }
    }

    /// Gets reference to data.
    #[inline]
    #[must_use]
    pub fn data(&self) -> &[u8] {
        self.version.data(&self.cell)
    }

    /// Gets mutable reference to data.
    #[inline]
    #[must_use]
    pub fn data_mut(&mut self) -> &mut [u8] {
        self.version.data_mut(&mut self.cell)
    }

    /// Gets reference to data and padding.
    #[inline]
    #[must_use]
    pub fn data_padding_dyn(&self) -> &[u8] {
        self.version.data_padding(&self.cell)
    }

    /// Gets mutable reference to data and padding.
    #[inline]
    #[must_use]
    pub fn data_padding_mut_dyn(&mut self) -> &mut [u8] {
        self.version.data_padding_mut(&mut self.cell)
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

impl<V: RelayVersion> Data<V> {
    /// Gets reference to data and padding.
    #[inline]
    #[must_use]
    pub fn data_padding(&self) -> &V::Data {
        self.version.data_padding(&self.cell)
    }

    /// Gets mutable reference to data and padding.
    #[inline]
    #[must_use]
    pub fn data_padding_mut(&mut self) -> &mut V::Data {
        self.version.data_padding_mut(&mut self.cell)
    }
}

impl<V> Data<V> {
    /// `DATA` relay ID.
    pub const ID: u8 = 2;

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
