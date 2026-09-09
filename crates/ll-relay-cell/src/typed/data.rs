//! `DATA` relay cell.

use std::ops::{Deref, DerefMut};
use std::mem::size_of;

use onioncloud_ll_cell::fixed::FixedCell;

use crate::traits::{IntoRelayWrapper, DynRelayWrapper, DynRelayWrapperRef};
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
        assert!(data.len() <= size_of::<<V0 as IntoRelayWrapper>::Data>(), "data is too long");
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
        assert!(data.len() <= size_of::<<V1 as IntoRelayWrapper>::Data>(), "data is too long");
        Self::new(cell, V1, data)
    }
}

impl<V: IntoRelayWrapper> Data<V> {
    /// Create new [`Data`].
    ///
    /// # Panics
    ///
    /// Panics if data does not fit cell.
    pub fn new(mut cell: FixedCell, wrapper: V, data: &[u8]) -> Self {
        let mut p = wrapper.wrap_mut(&mut cell);
        let l = u16::try_from(data.len()).expect("data is too long");
        p.data_padding_mut().get_mut(..data.len()).expect("data is too long").copy_from_slice(data);
        p.set_len(l);
        Self { cell, wrapper }
    }

    /// Gets reference to data.
    #[inline]
    pub fn data(&self) -> impl '_ + Deref<Target = [u8]> {
        DataView(self.wrapper.wrap(&self.cell))
    }

    /// Gets mutable reference to data.
    #[inline]
    pub fn data_mut(&mut self) -> impl '_ + DerefMut<Target = [u8]> {
        DataView(self.wrapper.wrap(&self.cell))
    }

    /// Gets reference to data and padding.
    #[inline]
    pub fn data_padding(&self) -> impl '_ + Deref<Target = [u8]> {
        DataPaddingView(self.wrapper.wrap(&self.cell))
    }

    /// Gets mutable reference to data and padding.
    #[inline]
    pub fn data_padding_mut(&mut self) -> impl '_ + DerefMut<Target = [u8]> {
        DataPaddingView(self.wrapper.wrap(&self.cell))
    }

    /// Gets reference to data and padding.
    #[inline]
    pub fn data_padding_static(&self) -> impl '_ + Deref<Target = V::RefWrapperTarget::Data> where V::RefWrapperTarget: RelayWrapperRef {
        StaticDataPaddingView(self.wrapper.wrap(&self.cell))
    }

    /// Gets mutable reference to data and padding.
    #[inline]
    pub fn data_padding_static_mut(&mut self) -> impl '_ + DerefMut<Target = V::MutWrapperTarget::Data> where V::MutWrapperTarget: RelayWrapper {
        StaticDataPaddingView(self.wrapper.wrap(&self.cell))
    }
}

impl<V> Data<V> {
    pub fn wrapper(&self) -> &V {
        &self.wrapper
    }

    pub fn into_inner(self) -> FixedCell {
        self.cell
    }
}

struct DataView<T>(T);

impl<T> Deref for DataView<T> where T: Deref, T::Target: DynRelayWrapperRef {
    type Target = [u8];

    fn deref(&self) -> &[u8] {
        self.0.data()
    }
}

impl<T> DerefMut for DataView<T> where T: DerefMut, T::Target: DynRelayWrapper {
    fn deref_mut(&mut self) -> &mut [u8] {
        self.0.data_mut()
    }
}

struct DataPaddingView<T>(T);

impl<T> Deref for DataPaddingView<T> where T: Deref, T::Target: DynRelayWrapperRef {
    type Target = [u8];

    fn deref(&self) -> &[u8] {
        self.0.data_padding()
    }
}

impl<T> DerefMut for DataPaddingView<T> where T: DerefMut, T::Target: DynRelayWrapper {
    fn deref_mut(&mut self) -> &mut [u8] {
        self.0.data_padding_mut()
    }
}

struct StaticDataPaddingView<T>(T);

impl<T> Deref for StaticDataPaddingView<T> where T: Deref, T::Target: RelayWrapperRef {
    type Target = T::Target::Data;

    fn deref(&self) -> &Self::Target {
        self.0.data_padding()
    }
}

impl<T> DerefMut for StaticDataPaddingView<T> where T: DerefMut, T::Target: RelayWrapper {
    fn deref_mut(&mut self) -> &mut Self::Target {
        self.0.data_padding_mut()
    }
}
