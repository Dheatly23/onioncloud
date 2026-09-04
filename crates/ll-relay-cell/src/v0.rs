//! Version 0 relay format (default).

use std::ptr::{from_mut, from_ref};

use onioncloud_ll_cell::fixed::{FIXED_CELL_SIZE, FixedCell};
use zerocopy::byteorder::big_endian::U16;
use zerocopy::{
    FromBytes, Immutable, IntoBytes, KnownLayout, Unaligned, transmute_mut, transmute_ref,
};

use crate::traits::{IntoRelayWrapper, RelayWrapper, RelayWrapperRef};

const DATA_SIZE: usize = FIXED_CELL_SIZE - 11;

#[derive(FromBytes, IntoBytes, Immutable, KnownLayout, Unaligned)]
#[repr(C)]
struct Data {
    command: u8,
    recognized: [u8; 2],
    stream_id: U16,
    digest: [u8; 4],
    len: U16,
    #[expect(clippy::struct_field_names)]
    data: [u8; DATA_SIZE],
}

/// Wrapper for relay cell.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[repr(transparent)]
pub struct V0Wrapper(FixedCell);

impl From<FixedCell> for V0Wrapper {
    #[inline]
    fn from(v: FixedCell) -> Self {
        Self(v)
    }
}

impl From<V0Wrapper> for FixedCell {
    #[inline]
    fn from(v: V0Wrapper) -> Self {
        v.0
    }
}

impl<'a> From<&'a FixedCell> for &'a V0Wrapper {
    #[inline]
    fn from(v: &'a FixedCell) -> Self {
        // SAFETY: V0Wrapper is repr(transparent) to FixedCell.
        unsafe { &*from_ref(v).cast() }
    }
}

impl<'a> From<&'a V0Wrapper> for &'a FixedCell {
    #[inline]
    fn from(v: &'a V0Wrapper) -> Self {
        // SAFETY: V0Wrapper is repr(transparent) to FixedCell.
        unsafe { &*from_ref(v).cast() }
    }
}

impl<'a> From<&'a mut FixedCell> for &'a mut V0Wrapper {
    #[inline]
    fn from(v: &'a mut FixedCell) -> Self {
        // SAFETY: V0Wrapper is repr(transparent) to FixedCell.
        unsafe { &mut *from_mut(v).cast() }
    }
}

impl<'a> From<&'a mut V0Wrapper> for &'a mut FixedCell {
    #[inline]
    fn from(v: &'a mut V0Wrapper) -> Self {
        // SAFETY: V0Wrapper is repr(transparent) to FixedCell.
        unsafe { &mut *from_mut(v).cast() }
    }
}

impl AsRef<FixedCell> for V0Wrapper {
    #[inline]
    fn as_ref(&self) -> &FixedCell {
        self.into()
    }
}

impl AsMut<FixedCell> for V0Wrapper {
    #[inline]
    fn as_mut(&mut self) -> &mut FixedCell {
        self.into()
    }
}

impl RelayWrapperRef for V0Wrapper {
    type Data = [u8; DATA_SIZE];

    fn as_fixed_cell(&self) -> &FixedCell {
        self.into()
    }

    fn command(&self) -> u8 {
        self.get_ref().command
    }

    fn stream_id(&self) -> u16 {
        self.get_ref().stream_id.get()
    }

    fn len(&self) -> u16 {
        self.get_ref().len.get()
    }

    fn data_padding(&self) -> &Self::Data {
        &self.get_ref().data
    }
}

impl RelayWrapper for V0Wrapper {
    fn as_fixed_cell_mut(&mut self) -> &mut FixedCell {
        self.into()
    }

    fn set_command(&mut self, command: u8) {
        self.get_mut().command = command;
    }

    fn set_stream_id(&mut self, stream_id: u16) {
        self.get_mut().stream_id.set(stream_id);
    }

    fn set_len(&mut self, len: u16) {
        assert!((len as usize) <= DATA_SIZE, "{len} > {DATA_SIZE}");
        self.get_mut().len.set(len);
    }

    fn data_padding_mut(&mut self) -> &mut Self::Data {
        &mut self.get_mut().data
    }
}

impl V0Wrapper {
    fn get_ref(&self) -> &Data {
        transmute_ref!(self.0.data())
    }

    fn get_mut(&mut self) -> &mut Data {
        transmute_mut!(self.0.data_mut())
    }

    /// Gets digest field.
    #[inline]
    #[must_use]
    pub fn digest(&self) -> [u8; 4] {
        self.get_ref().digest
    }

    /// Sets digest field.
    #[inline]
    pub fn set_digest(&mut self, digest: [u8; 4]) {
        self.get_mut().digest = digest;
    }

    /// Gets recognized field.
    #[inline]
    #[must_use]
    pub fn recognized(&self) -> [u8; 2] {
        self.get_ref().recognized
    }

    /// Sets recognized field.
    #[inline]
    pub fn set_recognized(&mut self, value: [u8; 2]) {
        self.get_mut().recognized = value;
    }
}

/// V0 relay type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct V0;

impl IntoRelayWrapper for V0 {
    type RefWrapperTarget<'a> = V0Wrapper;
    type RefWrapper<'a> = &'a V0Wrapper;
    type MutWrapperTarget<'a> = V0Wrapper;
    type MutWrapper<'a> = &'a mut V0Wrapper;

    fn wrap<'a>(&self, cell: &'a FixedCell) -> Self::RefWrapper<'a> {
        cell.into()
    }

    fn wrap_mut<'a>(&self, cell: &'a mut FixedCell) -> Self::MutWrapper<'a> {
        cell.into()
    }
}
