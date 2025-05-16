use std::mem::size_of;
use std::num::NonZeroU32;

use zerocopy::byteorder::big_endian::U16;
use zerocopy::{
    FromBytes, Immutable, IntoBytes, KnownLayout, Unaligned, transmute_mut, transmute_ref,
};

use super::{
    Cell, CellHeader, CellLike, CellRef, FIXED_CELL_SIZE, FixedCell, TryFromCell, to_fixed_with,
};
use crate::errors;

/// CREATE2 cell header.
#[derive(FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned)]
#[repr(C)]
struct Create2Header {
    /// Handshake type.
    ty: U16,

    /// Handshake length.
    len: U16,
}

/// CREATE2 cell.
#[derive(FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned)]
#[repr(C)]
struct Create2Cell {
    /// Header.
    header: Create2Header,

    /// Handshake data + trailing bytes.
    data: [u8; const { FIXED_CELL_SIZE - size_of::<Create2Header>() }],
}

/// CREATED2 cell header.
#[derive(FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned)]
#[repr(C)]
struct Created2Header {
    /// Handshake length.
    len: U16,
}

/// CREATED2 cell.
#[derive(FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned)]
#[repr(C)]
struct Created2Cell {
    /// Header.
    header: Created2Header,

    /// Handshake data + trailing bytes.
    data: [u8; const { FIXED_CELL_SIZE - size_of::<Created2Header>() }],
}

/// Represents a CREATE2 cell.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Create2 {
    pub circuit: NonZeroU32,
    cell: FixedCell,
}

impl From<Create2> for Cell {
    fn from(v: Create2) -> Cell {
        Cell::from_fixed(
            CellHeader::new(v.circuit.get(), Create2::ID),
            v.into_inner(),
        )
    }
}

impl From<Create2> for FixedCell {
    fn from(v: Create2) -> FixedCell {
        v.into_inner()
    }
}

impl TryFromCell for Create2 {
    fn try_from_cell(cell: &mut Option<Cell>) -> Result<Option<Self>, errors::CellFormatError> {
        let Some(Cell {
            circuit: cid,
            command: Self::ID,
            ..
        }) = *cell
        else {
            return Ok(None);
        };
        let cid = NonZeroU32::new(cid).ok_or(errors::CellFormatError)?;
        to_fixed_with(cell, Self::check).map(|v| v.map(|v| unsafe { Self::from_cell(cid, v) }))
    }
}

impl CellLike for Create2 {
    fn circuit(&self) -> u32 {
        self.circuit.get()
    }

    fn command(&self) -> u8 {
        Self::ID
    }

    fn cell(&self) -> CellRef<'_> {
        CellRef::Fixed(&self.cell)
    }
}

impl Create2 {
    /// CREATE2 command ID.
    pub const ID: u8 = 10;

    /// Creates new CREATE2 cell from existing [`FixedCell`].
    ///
    /// # Safety
    ///
    /// Data must be a valid CREATE2 cell.
    pub unsafe fn from_cell(circuit: NonZeroU32, data: FixedCell) -> Self {
        debug_assert!(Self::check(data.data()));
        Self {
            circuit,
            cell: data,
        }
    }

    /// Creates new CREATE2 cell.
    ///
    /// # Parameters
    ///
    /// - `cell` : Cached [`FixedCell`].
    /// - `circuit` : Circuit ID.
    /// - `ty` : Handshake type.
    /// - `data` : Handshake data.
    ///
    /// # Panics
    ///
    /// Panics if data does not fit the cell.
    pub fn new(mut cell: FixedCell, circuit: NonZeroU32, ty: u16, data: &[u8]) -> Self {
        let Create2Cell { header, data: out } = transmute_mut!(cell.data_mut());
        out[..data.len()].copy_from_slice(data);
        header.ty.set(ty);
        header
            .len
            .set(data.len().try_into().expect("data must fit cell"));

        // SAFETY: Data is valid
        unsafe { Self::from_cell(circuit, cell) }
    }

    /// Gets handshake type.
    pub fn handshake_type(&self) -> u16 {
        let Create2Cell { header, .. } = transmute_ref!(self.cell.data());
        header.ty.get()
    }

    /// Gets handshake length.
    pub fn len(&self) -> u16 {
        let Create2Cell { header, .. } = transmute_ref!(self.cell.data());
        header.len.get()
    }

    /// Checks if there is no payload.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Gets handshake data.
    pub fn data(&self) -> &[u8] {
        let Create2Cell { header, data } = transmute_ref!(self.cell.data());
        &data[..header.len.get().into()]
    }

    /// Unwraps into inner [`FixedCell`].
    pub fn into_inner(self) -> FixedCell {
        self.cell
    }

    fn check(data: &[u8; FIXED_CELL_SIZE]) -> bool {
        let Create2Cell { header, data } = transmute_ref!(data);
        usize::from(header.len.get()) <= data.len()
    }
}

/// Represents a CREATED2 cell.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Created2 {
    pub circuit: NonZeroU32,
    cell: FixedCell,
}

impl From<Created2> for Cell {
    fn from(v: Created2) -> Cell {
        Cell::from_fixed(
            CellHeader::new(v.circuit.get(), Created2::ID),
            v.into_inner(),
        )
    }
}

impl From<Created2> for FixedCell {
    fn from(v: Created2) -> FixedCell {
        v.into_inner()
    }
}

impl TryFromCell for Created2 {
    fn try_from_cell(cell: &mut Option<Cell>) -> Result<Option<Self>, errors::CellFormatError> {
        let Some(Cell {
            circuit: cid,
            command: Self::ID,
            ..
        }) = *cell
        else {
            return Ok(None);
        };
        let cid = NonZeroU32::new(cid).ok_or(errors::CellFormatError)?;
        to_fixed_with(cell, Self::check).map(|v| v.map(|v| unsafe { Self::from_cell(cid, v) }))
    }
}

impl CellLike for Created2 {
    fn circuit(&self) -> u32 {
        self.circuit.get()
    }

    fn command(&self) -> u8 {
        Self::ID
    }

    fn cell(&self) -> CellRef<'_> {
        CellRef::Fixed(&self.cell)
    }
}

impl Created2 {
    /// CREATED2 command ID.
    pub const ID: u8 = 11;

    /// Creates new CREATED2 cell from existing [`FixedCell`].
    ///
    /// # Safety
    ///
    /// Data must be a valid CREATED2 cell.
    pub unsafe fn from_cell(circuit: NonZeroU32, data: FixedCell) -> Self {
        debug_assert!(Self::check(data.data()));
        Self {
            circuit,
            cell: data,
        }
    }

    /// Creates new CREATED2 cell.
    ///
    /// # Parameters
    ///
    /// - `cell` : Cached [`FixedCell`].
    /// - `circuit` : Circuit ID.
    /// - `data` : Handshake data.
    ///
    /// # Panics
    ///
    /// Panics if data does not fit the cell.
    pub fn new(mut cell: FixedCell, circuit: NonZeroU32, data: &[u8]) -> Self {
        let Created2Cell { header, data: out } = transmute_mut!(cell.data_mut());
        out[..data.len()].copy_from_slice(data);
        header
            .len
            .set(data.len().try_into().expect("data must fit cell"));

        // SAFETY: Data is valid
        unsafe { Self::from_cell(circuit, cell) }
    }

    /// Gets handshake length.
    pub fn len(&self) -> u16 {
        let Created2Cell { header, .. } = transmute_ref!(self.cell.data());
        header.len.get()
    }

    /// Checks if there is no payload.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Gets handshake data.
    pub fn data(&self) -> &[u8] {
        let Created2Cell { header, data } = transmute_ref!(self.cell.data());
        &data[..header.len.get().into()]
    }

    /// Unwraps into inner [`FixedCell`].
    pub fn into_inner(self) -> FixedCell {
        self.cell
    }

    fn check(data: &[u8; FIXED_CELL_SIZE]) -> bool {
        let Created2Cell { header, data } = transmute_ref!(data);
        usize::from(header.len.get()) <= data.len()
    }
}
