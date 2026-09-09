//! Traits defining relay cell and operations on it.

use std::borrow::{Borrow, BorrowMut};
use std::hash::Hash;
use std::ops::Deref;

use onioncloud_ll_cell::fixed::FixedCell;
use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout, Unaligned};

/// Trait sealing.
mod private {
    pub trait Sealed {}

    impl<const N: usize> Sealed for [u8; N] {}
}

/// Trait for byte array and byte array only.
///
/// NOTE: (Workaround due to associated constant limitations).
pub trait ArrayLike:
    private::Sealed
    + Sized
    + Send
    + Sync
    + Copy
    + PartialEq
    + Eq
    + Hash
    + AsRef<[u8]>
    + AsMut<[u8]>
    + Borrow<[u8]>
    + BorrowMut<[u8]>
    + FromBytes
    + IntoBytes
    + Immutable
    + KnownLayout
    + Unaligned
{
}

impl<const N: usize> ArrayLike for [u8; N] {}

/// Trait for relay versioning.
pub trait RelayVersion {
    /// Type of payload.
    ///
    /// Should be an array.
    ///
    /// NOTE: (Workaround due to associated constant limitations).
    type Data: 'static + ArrayLike;

    /// Gets relay command.
    fn command(&self, cell: &FixedCell) -> u8;

    /// Sets relay command.
    fn set_command(&self, cell: &mut FixedCell, command: u8);

    /// Gets stream ID.
    fn stream_id(&self, cell: &FixedCell) -> u16;

    /// Sets stream ID.
    fn set_stream_id(&self, cell: &mut FixedCell, stream_id: u16);

    /// Gets payload length.
    fn len(&self, cell: &FixedCell) -> u16;

    /// Sets payload length.
    ///
    /// # Panics
    ///
    /// Panics if length is greater than `size_of::<Self::Data>`.
    fn set_len(&self, cell: &mut FixedCell, len: u16);

    /// Gets reference to payload and padding.
    fn data_padding<'a>(&self, cell: &'a FixedCell) -> &'a Self::Data;

    /// Gets mutable reference to payload and padding.
    fn data_padding_mut<'a>(&self, cell: &'a mut FixedCell) -> &'a mut Self::Data;

    /// Gets reference to payload.
    ///
    /// # Panics
    ///
    /// Panics if [`len`] is invalid.
    #[inline]
    fn data<'a>(&self, cell: &'a FixedCell) -> &'a [u8] {
        let len = self.len(cell) as usize;
        &self.data_padding(cell).borrow()[..len]
    }

    /// Gets reference to payload.
    ///
    /// Returns [`None`] if [`len`] is invalid.
    #[inline]
    fn data_checked<'a>(&self, cell: &'a FixedCell) -> Option<&'a [u8]> {
        let len = self.len(cell) as usize;
        self.data_padding(cell).borrow().get(..len)
    }

    /// Gets mutable reference to payload.
    ///
    /// # Panics
    ///
    /// Panics if [`len`] is invalid.
    #[inline]
    fn data_mut<'a>(&self, cell: &'a mut FixedCell) -> &'a mut [u8] {
        let len = self.len(cell) as usize;
        &mut self.data_padding_mut(cell).borrow_mut()[..len]
    }

    /// Gets mutable reference to payload.
    ///
    /// Returns [`None`] if [`len`] is invalid.
    #[inline]
    fn data_mut_checked<'a>(&self, cell: &'a mut FixedCell) -> Option<&'a mut [u8]> {
        let len = self.len(cell) as usize;
        self.data_padding_mut(cell).borrow_mut().get_mut(..len)
    }
}

impl<T> RelayVersion for T
where
    T: Deref,
    T::Target: RelayVersion,
{
    type Data = <T::Target as RelayVersion>::Data;

    #[inline]
    fn command(&self, cell: &FixedCell) -> u8 {
        <T::Target as RelayVersion>::command(&**self, cell)
    }

    #[inline]
    fn set_command(&self, cell: &mut FixedCell, command: u8) {
        <T::Target as RelayVersion>::set_command(&**self, cell, command);
    }

    #[inline]
    fn stream_id(&self, cell: &FixedCell) -> u16 {
        <T::Target as RelayVersion>::stream_id(&**self, cell)
    }

    #[inline]
    fn set_stream_id(&self, cell: &mut FixedCell, stream_id: u16) {
        <T::Target as RelayVersion>::set_stream_id(&**self, cell, stream_id);
    }

    #[inline]
    fn len(&self, cell: &FixedCell) -> u16 {
        <T::Target as RelayVersion>::len(&**self, cell)
    }

    #[inline]
    fn set_len(&self, cell: &mut FixedCell, len: u16) {
        <T::Target as RelayVersion>::set_len(&**self, cell, len);
    }

    #[inline]
    fn data_padding<'a>(&self, cell: &'a FixedCell) -> &'a Self::Data {
        <T::Target as RelayVersion>::data_padding(&**self, cell)
    }

    #[inline]
    fn data_padding_mut<'a>(&self, cell: &'a mut FixedCell) -> &'a mut Self::Data {
        <T::Target as RelayVersion>::data_padding_mut(&**self, cell)
    }

    #[inline]
    fn data<'a>(&self, cell: &'a FixedCell) -> &'a [u8] {
        <T::Target as RelayVersion>::data(&**self, cell)
    }

    #[inline]
    fn data_checked<'a>(&self, cell: &'a FixedCell) -> Option<&'a [u8]> {
        <T::Target as RelayVersion>::data_checked(&**self, cell)
    }

    #[inline]
    fn data_mut<'a>(&self, cell: &'a mut FixedCell) -> &'a mut [u8] {
        <T::Target as RelayVersion>::data_mut(&**self, cell)
    }

    #[inline]
    fn data_mut_checked<'a>(&self, cell: &'a mut FixedCell) -> Option<&'a mut [u8]> {
        <T::Target as RelayVersion>::data_mut_checked(&**self, cell)
    }
}

/// Trait for relay versioning (dyn-safe).
pub trait DynRelayVersion {
    /// Gets relay command.
    fn command(&self, cell: &FixedCell) -> u8;

    /// Sets relay command.
    fn set_command(&self, cell: &mut FixedCell, command: u8);

    /// Gets stream ID.
    fn stream_id(&self, cell: &FixedCell) -> u16;

    /// Sets stream ID.
    fn set_stream_id(&self, cell: &mut FixedCell, stream_id: u16);

    /// Gets payload length.
    fn len(&self, cell: &FixedCell) -> u16;

    /// Sets payload length.
    ///
    /// # Panics
    ///
    /// Panics if length is greater than `size_of::<Self::Data>`.
    fn set_len(&self, cell: &mut FixedCell, len: u16);

    /// Gets reference to payload and padding.
    fn data_padding<'a>(&self, cell: &'a FixedCell) -> &'a [u8];

    /// Gets mutable reference to payload and padding.
    fn data_padding_mut<'a>(&self, cell: &'a mut FixedCell) -> &'a mut [u8];

    /// Gets reference to payload.
    ///
    /// # Panics
    ///
    /// Panics if [`len`] is invalid.
    #[inline]
    fn data<'a>(&self, cell: &'a FixedCell) -> &'a [u8] {
        let len = self.len(cell) as usize;
        &self.data_padding(cell)[..len]
    }

    /// Gets reference to payload.
    ///
    /// Returns [`None`] if [`len`] is invalid.
    #[inline]
    fn data_checked<'a>(&self, cell: &'a FixedCell) -> Option<&'a [u8]> {
        let len = self.len(cell) as usize;
        self.data_padding(cell).get(..len)
    }

    /// Gets mutable reference to payload.
    ///
    /// # Panics
    ///
    /// Panics if [`len`] is invalid.
    #[inline]
    fn data_mut<'a>(&self, cell: &'a mut FixedCell) -> &'a mut [u8] {
        let len = self.len(cell) as usize;
        &mut self.data_padding_mut(cell)[..len]
    }

    /// Gets mutable reference to payload.
    ///
    /// Returns [`None`] if [`len`] is invalid.
    #[inline]
    fn data_mut_checked<'a>(&self, cell: &'a mut FixedCell) -> Option<&'a mut [u8]> {
        let len = self.len(cell) as usize;
        self.data_padding_mut(cell).get_mut(..len)
    }
}

impl<T: RelayVersion> DynRelayVersion for T {
    #[inline]
    fn command(&self, cell: &FixedCell) -> u8 {
        <T as RelayVersion>::command(self, cell)
    }

    #[inline]
    fn set_command(&self, cell: &mut FixedCell, command: u8) {
        <T as RelayVersion>::set_command(self, cell, command);
    }

    #[inline]
    fn stream_id(&self, cell: &FixedCell) -> u16 {
        <T as RelayVersion>::stream_id(self, cell)
    }

    #[inline]
    fn set_stream_id(&self, cell: &mut FixedCell, stream_id: u16) {
        <T as RelayVersion>::set_stream_id(self, cell, stream_id);
    }

    #[inline]
    fn len(&self, cell: &FixedCell) -> u16 {
        <T as RelayVersion>::len(self, cell)
    }

    #[inline]
    fn set_len(&self, cell: &mut FixedCell, len: u16) {
        <T as RelayVersion>::set_len(self, cell, len);
    }

    #[inline]
    fn data_padding<'a>(&self, cell: &'a FixedCell) -> &'a [u8] {
        <T as RelayVersion>::data_padding(self, cell).borrow()
    }

    #[inline]
    fn data_padding_mut<'a>(&self, cell: &'a mut FixedCell) -> &'a mut [u8] {
        <T as RelayVersion>::data_padding_mut(self, cell).borrow_mut()
    }

    #[inline]
    fn data<'a>(&self, cell: &'a FixedCell) -> &'a [u8] {
        <T as RelayVersion>::data(self, cell)
    }

    #[inline]
    fn data_checked<'a>(&self, cell: &'a FixedCell) -> Option<&'a [u8]> {
        <T as RelayVersion>::data_checked(self, cell)
    }

    #[inline]
    fn data_mut<'a>(&self, cell: &'a mut FixedCell) -> &'a mut [u8] {
        <T as RelayVersion>::data_mut(self, cell)
    }

    #[inline]
    fn data_mut_checked<'a>(&self, cell: &'a mut FixedCell) -> Option<&'a mut [u8]> {
        <T as RelayVersion>::data_mut_checked(self, cell)
    }
}
