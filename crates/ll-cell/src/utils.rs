//! Utilities

use zerocopy::byteorder::big_endian::{U16, U32};
use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout, Unaligned};

use crate::fixed::FIXED_CELL_SIZE;

#[derive(FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned, Debug, Default)]
#[repr(C)]
pub(crate) struct HeaderSmall {
    pub(crate) circuit: U16,
    pub(crate) command: u8,
}

#[derive(FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned, Debug, Default)]
#[repr(C)]
pub(crate) struct HeaderLarge {
    pub(crate) circuit: U32,
    pub(crate) command: u8,
}

#[derive(FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned, Debug, Default)]
#[repr(C)]
pub(crate) struct HeaderSmallVariable {
    pub(crate) header: HeaderSmall,
    pub(crate) len: U16,
}

#[derive(FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned, Debug, Default)]
#[repr(C)]
pub(crate) struct HeaderLargeVariable {
    pub(crate) header: HeaderLarge,
    pub(crate) len: U16,
}

#[derive(FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned)]
#[repr(C)]
pub(crate) struct PrefixedFixedCell {
    pub(crate) v: U16,
    pub(crate) rest: [u8; const { FIXED_CELL_SIZE - 2 }],
}

pub(crate) const fn encoded_len(l: usize) -> usize {
    ((l * 4) / 3) + !(l * 4).is_multiple_of(3) as usize
}
