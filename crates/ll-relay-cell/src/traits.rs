//! Traits defining relay cell and operations on it.

use std::borrow::{Borrow, BorrowMut};
use std::hash::Hash;

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

pub trait IntoRelayWrapper {
    /// Reference type.
    type RefWrapper<'a>: DynRelayWrapperRef;

    /// Mutable reference type.
    type MutWrapper<'a>: DynRelayWrapper;

    /// Wraps relay cell content.
    fn wrap<'a>(&self, cell: &'a FixedCell) -> Self::RefWrapper<'a>;

    /// Wraps relay cell content mutably.
    fn wrap_mut<'a>(&self, cell: &'a mut FixedCell) -> Self::MutWrapper<'a>;
}

/// Trait for immutably wrapping relay cell (`dyn`-safe).
#[expect(clippy::len_without_is_empty)]
pub trait RelayWrapperRef {
    /// Type of payload.
    ///
    /// Should be an array.
    ///
    /// NOTE: (Workaround due to associated constant limitations).
    type Data: ArrayLike;

    /// Gets underlying [`FixedCell`]
    fn as_fixed_cell(&self) -> &FixedCell;

    /// Gets relay command.
    fn command(&self) -> u8;

    /// Gets stream ID.
    fn stream_id(&self) -> u16;

    /// Gets payload length.
    fn len(&self) -> u16;

    /// Gets reference to payload and padding.
    fn data_padding(&self) -> &Self::Data;

    /// Gets reference to payload.
    ///
    /// # Panics
    ///
    /// Panics if [`len`] is invalid.
    fn data(&self) -> &[u8] {
        let len = self.len() as usize;
        &self.data_padding().borrow()[..len]
    }

    /// Gets reference to payload.
    ///
    /// Returns [`None`] if [`len`] is invalid.
    fn data_checked(&self) -> Option<&[u8]> {
        let len = self.len() as usize;
        self.data_padding().borrow().get(..len)
    }
}

impl<T: RelayWrapperRef> RelayWrapperRef for &T {
    type Data = T::Data;

    #[inline]
    fn as_fixed_cell(&self) -> &FixedCell {
        <T as RelayWrapperRef>::as_fixed_cell(*self)
    }

    #[inline]
    fn command(&self) -> u8 {
        <T as RelayWrapperRef>::command(*self)
    }

    #[inline]
    fn stream_id(&self) -> u16 {
        <T as RelayWrapperRef>::stream_id(*self)
    }

    #[inline]
    fn len(&self) -> u16 {
        <T as RelayWrapperRef>::len(*self)
    }

    #[inline]
    fn data_padding(&self) -> &Self::Data {
        <T as RelayWrapperRef>::data_padding(*self)
    }

    #[inline]
    fn data(&self) -> &[u8] {
        <T as RelayWrapperRef>::data(*self)
    }

    #[inline]
    fn data_checked(&self) -> Option<&[u8]> {
        <T as RelayWrapperRef>::data_checked(*self)
    }
}

impl<T: RelayWrapperRef> RelayWrapperRef for &mut T {
    type Data = T::Data;

    #[inline]
    fn as_fixed_cell(&self) -> &FixedCell {
        <T as RelayWrapperRef>::as_fixed_cell(*self)
    }

    #[inline]
    fn command(&self) -> u8 {
        <T as RelayWrapperRef>::command(*self)
    }

    #[inline]
    fn stream_id(&self) -> u16 {
        <T as RelayWrapperRef>::stream_id(*self)
    }

    #[inline]
    fn len(&self) -> u16 {
        <T as RelayWrapperRef>::len(*self)
    }

    #[inline]
    fn data_padding(&self) -> &Self::Data {
        <T as RelayWrapperRef>::data_padding(*self)
    }

    #[inline]
    fn data(&self) -> &[u8] {
        <T as RelayWrapperRef>::data(*self)
    }

    #[inline]
    fn data_checked(&self) -> Option<&[u8]> {
        <T as RelayWrapperRef>::data_checked(*self)
    }
}

/// Trait for wrapping relay cell (`dyn`-safe).
pub trait RelayWrapper: RelayWrapperRef {
    /// Gets underlying [`FixedCell`]
    fn as_fixed_cell_mut(&mut self) -> &mut FixedCell;

    /// Sets relay command.
    fn set_command(&mut self, command: u8);

    /// Sets stream ID.
    fn set_stream_id(&mut self, stream_id: u16);

    /// Sets payload length.
    ///
    /// # Panics
    ///
    /// Panics if length is greater than `size_of::<Self::Data>`.
    fn set_len(&mut self, len: u16);

    /// Gets mutable reference to payload and padding.
    fn data_padding_mut(&mut self) -> &mut Self::Data;

    /// Gets mutable reference to payload.
    ///
    /// # Panics
    ///
    /// Panics if [`len`] is invalid.
    fn data_mut(&mut self) -> &mut [u8] {
        let len = self.len() as usize;
        &mut self.data_padding_mut().borrow_mut()[..len]
    }

    /// Gets mutable reference to payload.
    ///
    /// Returns [`None`] if [`len`] is invalid.
    fn data_mut_checked(&mut self) -> Option<&mut [u8]> {
        let len = self.len() as usize;
        self.data_padding_mut().borrow_mut().get_mut(..len)
    }
}

impl<T: RelayWrapper> RelayWrapper for &mut T {
    #[inline]
    fn as_fixed_cell_mut(&mut self) -> &mut FixedCell {
        <T as RelayWrapper>::as_fixed_cell_mut(*self)
    }

    #[inline]
    fn set_command(&mut self, command: u8) {
        <T as RelayWrapper>::set_command(*self, command);
    }

    #[inline]
    fn set_stream_id(&mut self, stream_id: u16) {
        <T as RelayWrapper>::set_stream_id(*self, stream_id);
    }

    #[inline]
    fn set_len(&mut self, len: u16) {
        <T as RelayWrapper>::set_len(*self, len);
    }

    #[inline]
    fn data_padding_mut(&mut self) -> &mut Self::Data {
        <T as RelayWrapper>::data_padding_mut(*self)
    }

    #[inline]
    fn data_mut(&mut self) -> &mut [u8] {
        <T as RelayWrapper>::data_mut(*self)
    }

    #[inline]
    fn data_mut_checked(&mut self) -> Option<&mut [u8]> {
        <T as RelayWrapper>::data_mut_checked(*self)
    }
}

/// Trait for immutably wrapping relay cell (`dyn`-safe).
#[expect(clippy::len_without_is_empty)]
pub trait DynRelayWrapperRef {
    /// Gets underlying [`FixedCell`]
    fn as_fixed_cell(&self) -> &FixedCell;

    /// Gets relay command.
    fn command(&self) -> u8;

    /// Gets stream ID.
    fn stream_id(&self) -> u16;

    /// Gets payload length.
    fn len(&self) -> u16;

    /// Gets reference to payload and padding.
    fn data_padding(&self) -> &[u8];

    /// Gets reference to payload.
    ///
    /// # Panics
    ///
    /// Panics if [`len`] is invalid.
    fn data(&self) -> &[u8] {
        let len = self.len() as usize;
        &self.data_padding()[..len]
    }

    /// Gets reference to payload.
    ///
    /// Returns [`None`] if [`len`] is invalid.
    fn data_checked(&self) -> Option<&[u8]> {
        let len = self.len() as usize;
        self.data_padding().get(..len)
    }
}

/// Trait for wrapping relay cell (`dyn`-safe).
pub trait DynRelayWrapper: DynRelayWrapperRef {
    /// Gets underlying [`FixedCell`]
    fn as_fixed_cell_mut(&mut self) -> &mut FixedCell;

    /// Sets relay command.
    fn set_command(&mut self, command: u8);

    /// Sets stream ID.
    fn set_stream_id(&mut self, stream_id: u16);

    /// Sets payload length.
    ///
    /// # Panics
    ///
    /// Panics if length is invalid.
    fn set_len(&mut self, len: u16);

    /// Gets mutable reference to payload and padding.
    fn data_padding_mut(&mut self) -> &mut [u8];

    /// Gets mutable reference to payload.
    ///
    /// # Panics
    ///
    /// Panics if [`len`] is invalid.
    fn data_mut(&mut self) -> &mut [u8] {
        let len = self.len() as usize;
        &mut self.data_padding_mut()[..len]
    }

    /// Gets mutable reference to payload.
    ///
    /// Returns [`None`] if [`len`] is invalid.
    fn data_mut_checked(&mut self) -> Option<&mut [u8]> {
        let len = self.len() as usize;
        self.data_padding_mut().get_mut(..len)
    }
}

impl<T: RelayWrapperRef> DynRelayWrapperRef for T {
    #[inline]
    fn as_fixed_cell(&self) -> &FixedCell {
        <Self as RelayWrapperRef>::as_fixed_cell(self)
    }

    #[inline]
    fn command(&self) -> u8 {
        <Self as RelayWrapperRef>::command(self)
    }

    #[inline]
    fn stream_id(&self) -> u16 {
        <Self as RelayWrapperRef>::stream_id(self)
    }

    #[inline]
    fn len(&self) -> u16 {
        <Self as RelayWrapperRef>::len(self)
    }

    #[inline]
    fn data_padding(&self) -> &[u8] {
        <Self as RelayWrapperRef>::data_padding(self).borrow()
    }

    #[inline]
    fn data(&self) -> &[u8] {
        <Self as RelayWrapperRef>::data(self)
    }

    #[inline]
    fn data_checked(&self) -> Option<&[u8]> {
        <Self as RelayWrapperRef>::data_checked(self)
    }
}

impl<T: RelayWrapper> DynRelayWrapper for T {
    #[inline]
    fn as_fixed_cell_mut(&mut self) -> &mut FixedCell {
        <Self as RelayWrapper>::as_fixed_cell_mut(self)
    }

    #[inline]
    fn set_command(&mut self, command: u8) {
        <Self as RelayWrapper>::set_command(self, command);
    }

    #[inline]
    fn set_stream_id(&mut self, stream_id: u16) {
        <Self as RelayWrapper>::set_stream_id(self, stream_id);
    }

    #[inline]
    fn set_len(&mut self, len: u16) {
        <Self as RelayWrapper>::set_len(self, len);
    }

    #[inline]
    fn data_padding_mut(&mut self) -> &mut [u8] {
        <Self as RelayWrapper>::data_padding_mut(self).borrow_mut()
    }

    #[inline]
    fn data_mut(&mut self) -> &mut [u8] {
        <Self as RelayWrapper>::data_mut(self)
    }

    #[inline]
    fn data_mut_checked(&mut self) -> Option<&mut [u8]> {
        <Self as RelayWrapper>::data_mut_checked(self)
    }
}
