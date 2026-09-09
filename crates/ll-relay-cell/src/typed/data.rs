//! `DATA` relay cell.

use std::ops::{Deref, DerefMut};
use std::mem::size_of;

use onioncloud_ll_cell::fixed::FixedCell;

use crate::traits::{RelayVersion, DynRelayVersion};
use crate::v0::V0;
use crate::v1::V1;

/// `DATA` relay cell.
pub struct Data<V = V0> {
    cell: FixedCell,
    wrapper: V,
}

impl<V> From<Data<V>> for FixedCell {
    fn from(v: Data<V>) -> FixedCell {
        v.cell
    }
}

impl Data<V0> {
    /// Create new [`Data`] with relay version 0.
    ///
    /// # Panics
    ///
    /// Panics if data does not fit cell.
    #[inline]
    pub fn new_v0(mut cell: FixedCell, data: &[u8]) -> Self {
        assert!(data.len() <= size_of::<<V0 as RelayVersion>::Data>(), "data is too long");
        Self::new(cell, V0, data)
    }
}

impl Data<V1> {
    /// Create new [`Data`] with relay version 1.
    ///
    /// # Panics
    ///
    /// Panics if data does not fit cell.
    #[inline]
    pub fn new_v1(mut cell: FixedCell, data: &[u8]) -> Self {
        assert!(data.len() <= size_of::<<V1 as RelayVersion>::Data>(), "data is too long");
        Self::new(cell, V1, data)
    }
}

impl<V: DynRelayVersion> Data<V> {
    /// Create new [`Data`].
    ///
    /// # Panics
    ///
    /// Panics if data does not fit cell.
    pub fn new(mut cell: FixedCell, wrapper: V, data: &[u8]) -> Self {
        let l = u16::try_from(data.len()).expect("data is too long");
        wrapper.data_padding_mut(&mut cell).get_mut(..data.len()).expect("data is too long").copy_from_slice(data);
        wrapper.set_len(&mut cell, l);
        Self { cell, wrapper }
    }

    /// Gets reference to data.
    #[inline]
    pub fn data(&self) -> &[u8] {
        self.wrapper.data(&self.cell)
    }

    /// Gets mutable reference to data.
    #[inline]
    pub fn data_mut(&mut self) -> &mut [u8] {
        self.wrapper.data_mut(&mut self.cell)
    }

    /// Gets reference to data and padding.
    #[inline]
    pub fn data_padding_dyn(&self) -> &[u8] {
        self.wrapper.data_padding(&self.cell)
    }

    /// Gets mutable reference to data and padding.
    #[inline]
    pub fn data_padding_mut_dyn(&mut self) -> &mut [u8] {
        self.wrapper.data_padding_mut(&mut self.cell)
    }
}

impl<V: RelayVersion> Data<V> {
    /// Gets reference to data and padding.
    #[inline]
    pub fn data_padding(&self) -> &V::Data {
        self.wrapper.data_padding(&self.cell)
    }

    /// Gets mutable reference to data and padding.
    #[inline]
    pub fn data_padding_mut(&mut self) -> &mut V::Data {
        self.wrapper.data_padding_mut(&mut self.cell)
    }
}
