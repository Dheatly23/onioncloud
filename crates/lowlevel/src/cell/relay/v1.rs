//! V1 relay cell format.
//!
//! The proposed relay cell format for counter galois mode.

use std::mem::size_of;

use rand::prelude::*;
use zerocopy::byteorder::big_endian::U16;
use zerocopy::{
    FromBytes, Immutable, IntoBytes, KnownLayout, Unaligned, transmute_mut, transmute_ref,
};

use super::v0;
use super::{RelayLike, RelayV001};
use crate::cell::FIXED_CELL_SIZE;
use crate::errors::CellLengthOverflowError;

/// RELAY and RELAY_EARLY cell header.
#[derive(FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned, Debug, PartialEq, Eq)]
#[repr(C)]
pub(crate) struct RelayHeader {
    /// Authentication tag.
    pub(crate) tag: [u8; 16],

    /// Relay command.
    pub(crate) command: u8,

    /// Stream ID.
    pub(crate) stream: U16,

    /// Message length.
    pub(crate) len: U16,
}

/// Maximum length of RELAY payload.
pub const RELAY_DATA_LENGTH: usize = FIXED_CELL_SIZE - size_of::<RelayHeader>();

/// RELAY and RELAY_EARLY cell content.
#[derive(FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned)]
#[repr(C)]
pub(crate) struct RelayCell {
    /// Relay header.
    pub(crate) header: RelayHeader,

    /// Message payload + padding.
    pub(crate) data: [u8; RELAY_DATA_LENGTH],
}

/// Extension trait for [`RelayLike`].
pub trait RelayExt: RelayLike {
    /// Gets authentication tag.
    fn tag(&self) -> &[u8; 16] {
        &cast_cell(self).header.tag
    }

    /// Gets authentication tag mutably.
    fn tag_mut(&mut self) -> &mut [u8; 16] {
        &mut cast_cell_mut(self).header.tag
    }

    /// Gets command.
    fn command(&self) -> u8 {
        cast_cell(self).header.command
    }

    /// Sets command.
    fn set_command(&mut self, value: u8) {
        cast_cell_mut(self).header.command = value;
    }

    /// Gets stream ID.
    fn stream(&self) -> u16 {
        cast_cell(self).header.stream.get()
    }

    /// Sets stream ID.
    fn set_stream(&mut self, value: u16) {
        cast_cell_mut(self).header.stream.set(value);
    }

    /// Gets length.
    fn len(&self) -> u16 {
        cast_cell(self).header.len.get()
    }

    /// Returns [`true`] if length is 0.
    fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Set length.
    ///
    /// # SAFETY
    ///
    /// Length must be shorter than [`RELAY_DATA_LENGTH`].
    unsafe fn set_len(&mut self, len: u16) {
        debug_assert!(len as usize <= RELAY_DATA_LENGTH);
        cast_cell_mut(self).header.len.set(len)
    }

    /// Get payload.
    ///
    /// # Panics
    ///
    /// Panics if length field is invalid. This can happen if the cell content is encrypted.
    fn data(&self) -> &[u8] {
        let cell = cast_cell(self);
        &cell.data[..usize::from(cell.header.len.get())]
    }

    /// Get payload mutably.
    ///
    /// # Panics
    ///
    /// Panics if length field is invalid. This can happen if the cell content is encrypted.
    fn data_mut(&mut self) -> &mut [u8] {
        let cell = cast_cell_mut(self);
        &mut cell.data[..usize::from(cell.header.len.get())]
    }

    /// Set payload.
    ///
    /// # Panics
    ///
    /// Panics if `data` is longer than [`RELAY_DATA_LENGTH`].
    fn set_data(&mut self, data: &[u8]) {
        let cell = cast_cell_mut(self);
        assert!(
            data.len() <= cell.data.len(),
            "data is too long ({} > {})",
            data.len(),
            cell.data.len()
        );
        cell.data[..data.len()].copy_from_slice(data);
        cell.header
            .len
            .set(data.len().try_into().expect("data must fit cell"));
    }

    /// Get data and padding.
    fn data_padding(&self) -> &[u8; RELAY_DATA_LENGTH] {
        &cast_cell(self).data
    }

    /// Get data and padding mutably.
    fn data_padding_mut(&mut self) -> &mut [u8; RELAY_DATA_LENGTH] {
        &mut cast_cell_mut(self).data
    }

    /// Fill padding bytes in accordance to spec.
    fn fill_padding(&mut self) {
        let cell = cast_cell_mut(self);
        let padding = &mut cell.data[usize::from(cell.header.len.get())..];
        if let [_, _, _, _, padding @ ..] = padding {
            ThreadRng::default().fill_bytes(padding)
        }
    }
}

fn cast_cell<T: ?Sized + RelayLike>(this: &T) -> &RelayCell {
    transmute_ref!(this.as_ref())
}

fn cast_cell_mut<T: ?Sized + RelayLike>(this: &mut T) -> &mut RelayCell {
    transmute_mut!(this.as_mut())
}

impl<T: ?Sized + RelayLike> RelayExt for T {}

/// Convert to v0 format
pub(crate) fn to_v1(cell: &mut impl RelayLike) -> Result<(), CellLengthOverflowError> {
    let cell = cell.as_mut();
    let p: &RelayV001 = transmute_ref!(cell);
    let len = p.len.get();
    if usize::from(len) > RELAY_DATA_LENGTH {
        return Err(CellLengthOverflowError);
    }

    cell.copy_within(..RELAY_DATA_LENGTH, size_of::<RelayHeader>());
    let p: &mut RelayCell = transmute_mut!(cell);
    p.header.len.set(len);
    Ok(())
}

/// Convert v0 format to v1 format.
///
/// **NOTE: Only length and data is preserved. The rest of the fields are mangled.**
pub(crate) fn v0_to_v1(cell: &mut impl RelayLike) -> Result<(), CellLengthOverflowError> {
    let cell = cell.as_mut();
    let p: &v0::RelayCell = transmute_ref!(&*cell);
    let len = p.header.len.get() as usize;
    debug_assert!(
        len <= v0::RELAY_DATA_LENGTH,
        "length overflow: {len} > {}",
        v0::RELAY_DATA_LENGTH
    );
    if len > RELAY_DATA_LENGTH {
        return Err(CellLengthOverflowError);
    }

    const ST: usize = size_of::<v0::RelayHeader>();
    cell.copy_within(ST..ST + RELAY_DATA_LENGTH, size_of::<RelayHeader>());
    let p: &mut RelayCell = transmute_mut!(cell);
    p.header.len.set(len as _);
    Ok(())
}

/// Convert v1 format to v0 format.
///
/// **NOTE: Only length and data is preserved. The rest of the fields are mangled.**
pub(crate) fn v1_to_v0(cell: &mut impl RelayLike) -> Result<(), CellLengthOverflowError> {
    let cell = cell.as_mut();
    let p: &RelayCell = transmute_ref!(&*cell);
    let len = p.header.len.get() as usize;
    debug_assert!(
        len <= RELAY_DATA_LENGTH,
        "length overflow: {len} > {}",
        RELAY_DATA_LENGTH
    );
    assert!(RELAY_DATA_LENGTH <= v0::RELAY_DATA_LENGTH);
    if len > RELAY_DATA_LENGTH {
        return Err(CellLengthOverflowError);
    }

    const ST: usize = size_of::<RelayHeader>();
    cell.copy_within(ST..ST + RELAY_DATA_LENGTH, size_of::<v0::RelayHeader>());
    let p: &mut v0::RelayCell = transmute_mut!(cell);
    p.header.len.set(len as _);
    Ok(())
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    #[track_caller]
    pub(crate) fn assert_relay_eq(a: &impl RelayLike, b: &impl RelayLike) {
        let a = cast_cell(a);
        let b = cast_cell(b);

        assert_eq!(a.header, b.header);

        let a_data = &a.data[..usize::from(a.header.len.get())];
        let b_data = &b.data[..usize::from(b.header.len.get())];
        assert_eq!(a_data, b_data);
    }
}
