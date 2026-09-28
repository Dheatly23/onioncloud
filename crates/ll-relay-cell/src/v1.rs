//! Version 1 relay format.
//!
//! Used for CGO relay protocol.
//!
//! See also: [proposal spec](https://spec.torproject.org/proposals/359-cgo-redux.html).

use onioncloud_ll_cell::fixed::{FIXED_CELL_SIZE, FixedCell};
use zerocopy::byteorder::big_endian::U16;
use zerocopy::{
    FromBytes, Immutable, IntoBytes, KnownLayout, Unaligned, transmute_mut, transmute_ref,
};

use crate::traits::RelayVersion;

const DATA_SIZE: usize = FIXED_CELL_SIZE - 16 - 1 - 2 - 2;

#[derive(FromBytes, IntoBytes, Immutable, KnownLayout, Unaligned)]
#[repr(C)]
struct Data {
    tag: [u8; 16],
    command: u8,
    len: U16,
    stream_id: U16,
    #[expect(clippy::struct_field_names)]
    data: [u8; DATA_SIZE],
}

/// V1 relay type.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
pub struct V1;

impl RelayVersion for V1 {
    type Data = [u8; DATA_SIZE];

    #[inline]
    fn command(&self, cell: &FixedCell) -> u8 {
        Self::get_ref(cell).command
    }

    #[inline]
    fn stream_id(&self, cell: &FixedCell) -> u16 {
        Self::get_ref(cell).stream_id.get()
    }

    #[inline]
    fn len(&self, cell: &FixedCell) -> u16 {
        Self::get_ref(cell).len.get()
    }

    #[inline]
    fn data_padding<'a>(&self, cell: &'a FixedCell) -> &'a Self::Data {
        &Self::get_ref(cell).data
    }

    #[inline]
    fn set_command(&self, cell: &mut FixedCell, command: u8) {
        Self::get_mut(cell).command = command;
    }

    #[inline]
    fn set_stream_id(&self, cell: &mut FixedCell, stream_id: u16) {
        Self::get_mut(cell).stream_id.set(stream_id);
    }

    #[inline]
    fn set_len(&self, cell: &mut FixedCell, len: u16) {
        assert!((len as usize) <= DATA_SIZE, "{len} > {DATA_SIZE}");
        Self::get_mut(cell).len.set(len);
    }

    #[inline]
    fn data_padding_mut<'a>(&self, cell: &'a mut FixedCell) -> &'a mut Self::Data {
        &mut Self::get_mut(cell).data
    }
}

impl V1 {
    fn get_ref(cell: &FixedCell) -> &Data {
        transmute_ref!(cell.data())
    }

    fn get_mut(cell: &mut FixedCell) -> &mut Data {
        transmute_mut!(cell.data_mut())
    }

    /// Gets reference to tag field.
    #[inline]
    #[must_use]
    pub fn tag<'a>(&self, cell: &'a FixedCell) -> &'a [u8; 16] {
        &Self::get_ref(cell).tag
    }

    /// Gets mutable reference to tag field.
    #[inline]
    #[must_use]
    pub fn tag_mut<'a>(&self, cell: &'a mut FixedCell) -> &'a mut [u8; 16] {
        &mut Self::get_mut(cell).tag
    }
}
