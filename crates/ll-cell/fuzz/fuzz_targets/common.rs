#![allow(unused)]

use std::mem::size_of;

use arbitrary::{Arbitrary, Result as ArbResult, Unstructured};
use onioncloud_ll_cell::cell::{Cell, CellHeader};
use onioncloud_ll_cell::fixed::FIXED_CELL_SIZE;
use zerocopy::byteorder::big_endian::{U16, U32};
use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout, Unaligned};

#[derive(Debug, Clone, Copy)]
pub(crate) struct LimitedBytes<'a, const MAX: usize>(pub(crate) &'a [u8]);

impl<'a, const MAX: usize> Arbitrary<'a> for LimitedBytes<'a, MAX> {
    fn arbitrary(u: &mut Unstructured<'a>) -> ArbResult<Self> {
        Ok(Self(u.bytes(u.len().min(MAX))?))
    }

    fn arbitrary_take_rest(u: Unstructured<'a>) -> ArbResult<Self> {
        let b = u.take_rest();
        Ok(Self(&b[..b.len().min(MAX)]))
    }

    fn size_hint(_: usize) -> (usize, Option<usize>) {
        (0, Some(MAX))
    }
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct FromBytesWrapper<T>(pub(crate) T);

impl<T: Sized + FromBytes + IntoBytes> Arbitrary<'_> for FromBytesWrapper<T> {
    fn arbitrary(u: &mut Unstructured<'_>) -> ArbResult<Self> {
        let mut t = T::new_zeroed();
        let b = u.bytes(u.len().min(size_of_val(&t)))?;
        t.as_mut_bytes()[..b.len()].copy_from_slice(b);
        Ok(Self(t))
    }

    fn arbitrary_take_rest(u: Unstructured<'_>) -> ArbResult<Self> {
        let b = u.take_rest();
        let mut t = T::new_zeroed();
        let l = b.len().min(size_of_val(&t));
        t.as_mut_bytes()[..l].copy_from_slice(&b[..l]);
        Ok(Self(t))
    }

    fn size_hint(_: usize) -> (usize, Option<usize>) {
        (size_of::<T>(), Some(size_of::<T>()))
    }
}

#[derive(Debug, Clone, Copy, FromBytes, IntoBytes, Immutable, KnownLayout, Unaligned)]
#[repr(C)]
pub(crate) struct FixedCellInnerData {
    pub(crate) circuit: U32,
    pub(crate) command: u8,
    pub(crate) data: [u8; FIXED_CELL_SIZE],
}

pub(crate) type FixedCellData = FromBytesWrapper<FixedCellInnerData>;

impl From<FixedCellData> for Cell {
    fn from(v: FixedCellData) -> Cell {
        Cell::from_fixed(
            CellHeader {
                command: v.0.command,
                circuit: v.0.circuit.get(),
            },
            v.0.data.into(),
        )
    }
}

#[derive(Debug, Clone, Copy, FromBytes, IntoBytes, Immutable, KnownLayout, Unaligned)]
#[repr(C)]
pub(crate) struct VariableCellHeader {
    pub(crate) circuit: U32,
    pub(crate) command: u8,
    pub(crate) len: U16,
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct VariableCellData<'a> {
    pub(crate) header: VariableCellHeader,
    pub(crate) data: &'a [u8],
}

impl<'a> Arbitrary<'a> for VariableCellData<'a> {
    fn arbitrary(u: &mut Unstructured<'a>) -> ArbResult<Self> {
        let header = u.arbitrary::<FromBytesWrapper<VariableCellHeader>>()?.0;
        let len = header.len.get() as usize;
        let data = u.bytes(u.len().min(len))?;
        Ok(Self { header, data })
    }

    fn arbitrary_take_rest(mut u: Unstructured<'a>) -> ArbResult<Self> {
        let header = u.arbitrary::<FromBytesWrapper<VariableCellHeader>>()?.0;
        let len = header.len.get() as usize;
        let data = u.take_rest();
        Ok(Self {
            header,
            data: &data[..data.len().min(len)],
        })
    }

    fn size_hint(_: usize) -> (usize, Option<usize>) {
        (
            size_of::<VariableCellHeader>(),
            Some(size_of::<VariableCellHeader>() + u16::MAX as usize),
        )
    }
}

impl<'a> From<VariableCellData<'a>> for Cell {
    fn from(v: VariableCellData<'a>) -> Cell {
        let len = v.header.len.get() as usize;
        let mut data = vec![0; len].into_boxed_slice();
        data[..v.data.len()].copy_from_slice(v.data);
        Cell::from_variable(
            CellHeader {
                command: v.header.command,
                circuit: v.header.circuit.get(),
            },
            data.try_into().unwrap(),
        )
    }
}
