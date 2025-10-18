use std::mem::size_of;
use std::num::NonZeroU32;

use zerocopy::byteorder::big_endian::U16;
use zerocopy::{
    FromBytes, Immutable, IntoBytes, KnownLayout, Unaligned, transmute_mut, transmute_ref,
};

use super::{
    Cell, CellHeader, CellLike, CellRef, FIXED_CELL_SIZE, FixedCell, TryFromCell, to_fixed,
    to_fixed_with,
};
use crate::crypto::Sha1Output;
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

impl AsRef<[u8]> for Create2 {
    fn as_ref(&self) -> &[u8] {
        self.data()
    }
}

impl AsMut<[u8]> for Create2 {
    fn as_mut(&mut self) -> &mut [u8] {
        self.data_mut()
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
    /// # Error
    ///
    /// Errors if data does not fit the cell.
    pub fn new(
        mut cell: FixedCell,
        circuit: NonZeroU32,
        ty: u16,
        data: &[u8],
    ) -> Result<Self, errors::CellLengthOverflowError> {
        let Create2Cell { header, data: out } = transmute_mut!(cell.data_mut());
        out.get_mut(..data.len())
            .ok_or(errors::CellLengthOverflowError)?
            .copy_from_slice(data);
        header.ty.set(ty);
        header.len.set(
            data.len()
                .try_into()
                .map_err(|_| errors::CellLengthOverflowError)?,
        );

        // SAFETY: Data is valid
        unsafe { Ok(Self::from_cell(circuit, cell)) }
    }

    /// Creates new CREATE2 cell with multipart data.
    ///
    /// # Parameters
    ///
    /// - `cell` : Cached [`FixedCell`].
    /// - `circuit` : Circuit ID.
    /// - `ty` : Handshake type.
    /// - `data` : Handshake data in multiple byte slices.
    ///
    /// # Error
    ///
    /// Errors if data does not fit the cell.
    pub fn new_multipart<T: AsRef<[u8]>>(
        mut cell: FixedCell,
        circuit: NonZeroU32,
        ty: u16,
        data: impl IntoIterator<Item = T>,
    ) -> Result<Self, errors::CellLengthOverflowError> {
        let Create2Cell { header, data: out } = transmute_mut!(cell.data_mut());

        let mut o = &mut out[..];
        for v in data {
            let v = v.as_ref();
            let s;
            (s, o) = o
                .split_at_mut_checked(v.len())
                .ok_or(errors::CellLengthOverflowError)?;
            s.copy_from_slice(v);
        }
        let end = o.len();
        header.ty.set(ty);
        header.len.set(
            (out.len() - end)
                .try_into()
                .map_err(|_| errors::CellLengthOverflowError)?,
        );

        // SAFETY: Data is valid
        unsafe { Ok(Self::from_cell(circuit, cell)) }
    }

    /// Gets handshake type.
    pub fn handshake_type(&self) -> u16 {
        self.cast().header.ty.get()
    }

    /// Sets handshake type.
    pub fn set_handshake_type(&mut self, ty: u16) {
        self.cast_mut().header.ty.set(ty)
    }

    /// Gets handshake length.
    pub fn len(&self) -> u16 {
        self.cast().header.len.get()
    }

    /// Checks if there is no payload.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Gets handshake data.
    pub fn data(&self) -> &[u8] {
        let Create2Cell { header, data } = self.cast();
        &data[..header.len.get().into()]
    }

    /// Gets handshake data mutably.
    pub fn data_mut(&mut self) -> &mut [u8] {
        let Create2Cell { header, data } = self.cast_mut();
        &mut data[..header.len.get().into()]
    }

    /// Set handshake data.
    ///
    /// # Error
    ///
    /// Errors if data does not fit the cell.
    pub fn set_data(&mut self, data: &[u8]) -> Result<(), errors::CellLengthOverflowError> {
        let Create2Cell { header, data: out } = self.cast_mut();
        out.get_mut(..data.len())
            .ok_or(errors::CellLengthOverflowError)?
            .copy_from_slice(data);
        header.len.set(
            data.len()
                .try_into()
                .map_err(|_| errors::CellLengthOverflowError)?,
        );
        Ok(())
    }

    /// Set handshake data in multipart.
    ///
    /// # Error
    ///
    /// Errors if data does not fit the cell.
    pub fn set_data_multipart<T: AsRef<[u8]>>(
        &mut self,
        data: impl IntoIterator<Item = T>,
    ) -> Result<(), errors::CellLengthOverflowError> {
        let Create2Cell { header, data: out } = self.cast_mut();

        let mut o = &mut out[..];
        for v in data {
            let v = v.as_ref();
            let s;
            (s, o) = out.split_at_mut(v.len());
            s.copy_from_slice(v);
        }
        let end = o.len();
        let len = out.len() - end;

        header.len.set(
            len.try_into()
                .map_err(|_| errors::CellLengthOverflowError)?,
        );
        Ok(())
    }

    /// Unwraps into inner [`FixedCell`].
    pub fn into_inner(self) -> FixedCell {
        self.cell
    }

    fn check(data: &[u8; FIXED_CELL_SIZE]) -> bool {
        let Create2Cell { header, data } = transmute_ref!(data);
        usize::from(header.len.get()) <= data.len()
    }

    fn cast(&self) -> &Create2Cell {
        transmute_ref!(self.cell.data())
    }

    fn cast_mut(&mut self) -> &mut Create2Cell {
        transmute_mut!(self.cell.data_mut())
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
    /// # Error
    ///
    /// Errors if data does not fit the cell.
    pub fn new(
        mut cell: FixedCell,
        circuit: NonZeroU32,
        data: &[u8],
    ) -> Result<Self, errors::CellLengthOverflowError> {
        let Created2Cell { header, data: out } = transmute_mut!(cell.data_mut());
        out.get_mut(..data.len())
            .ok_or(errors::CellLengthOverflowError)?
            .copy_from_slice(data);
        header.len.set(
            data.len()
                .try_into()
                .map_err(|_| errors::CellLengthOverflowError)?,
        );

        // SAFETY: Data is valid
        unsafe { Ok(Self::from_cell(circuit, cell)) }
    }

    /// Creates new CREATED2 cell with multipart data.
    ///
    /// # Parameters
    ///
    /// - `cell` : Cached [`FixedCell`].
    /// - `circuit` : Circuit ID.
    /// - `data` : Handshake data in multiple byte slices.
    ///
    /// # Error
    ///
    /// Errors if data does not fit the cell.
    pub fn new_multipart<T: AsRef<[u8]>>(
        mut cell: FixedCell,
        circuit: NonZeroU32,
        data: impl IntoIterator<Item = T>,
    ) -> Result<Self, errors::CellLengthOverflowError> {
        let Created2Cell { header, data: out } = transmute_mut!(cell.data_mut());

        let mut o = &mut out[..];
        for v in data {
            let v = v.as_ref();
            let s;
            (s, o) = o
                .split_at_mut_checked(v.len())
                .ok_or(errors::CellLengthOverflowError)?;
            s.copy_from_slice(v);
        }
        let end = o.len();
        header.len.set(
            (out.len() - end)
                .try_into()
                .map_err(|_| errors::CellLengthOverflowError)?,
        );

        // SAFETY: Data is valid
        unsafe { Ok(Self::from_cell(circuit, cell)) }
    }

    /// Gets handshake length.
    pub fn len(&self) -> u16 {
        self.cast().header.len.get()
    }

    /// Checks if there is no payload.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Gets handshake data.
    pub fn data(&self) -> &[u8] {
        let Created2Cell { header, data } = self.cast();
        &data[..header.len.get().into()]
    }

    /// Gets handshake data mutably.
    pub fn data_mut(&mut self) -> &mut [u8] {
        let Created2Cell { header, data } = self.cast_mut();
        &mut data[..header.len.get().into()]
    }

    /// Set handshake data.
    ///
    /// # Panics
    ///
    /// Panics if data does not fit the cell.
    pub fn set_data(&mut self, data: &[u8]) {
        let Created2Cell { header, data: out } = self.cast_mut();
        out[..data.len()].copy_from_slice(data);
        header
            .len
            .set(data.len().try_into().expect("data must fit cell"));
    }

    /// Set handshake data in multipart.
    ///
    /// # Panics
    ///
    /// Panics if data does not fit the cell.
    pub fn set_data_multipart(&mut self, data: &[&[u8]]) {
        let Created2Cell { header, data: out } = self.cast_mut();

        let mut len = 0;
        let mut out = &mut out[..];
        for v in data {
            let (a, b) = out.split_at_mut(v.len());
            a.copy_from_slice(v);
            out = b;
            len += v.len();
        }

        header.len.set(len.try_into().expect("data must fit cell"));
    }

    /// Unwraps into inner [`FixedCell`].
    pub fn into_inner(self) -> FixedCell {
        self.cell
    }

    fn check(data: &[u8; FIXED_CELL_SIZE]) -> bool {
        let Created2Cell { header, data } = transmute_ref!(data);
        usize::from(header.len.get()) <= data.len()
    }

    fn cast(&self) -> &Created2Cell {
        transmute_ref!(self.cell.data())
    }

    fn cast_mut(&mut self) -> &mut Created2Cell {
        transmute_mut!(self.cell.data_mut())
    }
}

/// CREATE_FAST cell content.
#[derive(FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned)]
#[repr(C)]
struct CreateFastCell {
    /// Key material, first part.
    key_x: Sha1Output,

    /// Trailing data.
    trailing: [u8; const { FIXED_CELL_SIZE - size_of::<Sha1Output>() }],
}

/// Represents a CREATE_FAST cell.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct CreateFast {
    pub circuit: NonZeroU32,
    cell: FixedCell,
}

impl From<CreateFast> for Cell {
    fn from(v: CreateFast) -> Cell {
        Cell::from_fixed(
            CellHeader::new(v.circuit.get(), CreateFast::ID),
            v.into_inner(),
        )
    }
}

impl From<CreateFast> for FixedCell {
    fn from(v: CreateFast) -> FixedCell {
        v.into_inner()
    }
}

impl TryFromCell for CreateFast {
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
        to_fixed(cell).map(|v| v.map(|v| unsafe { Self::from_cell(cid, v) }))
    }
}

impl CellLike for CreateFast {
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

impl CreateFast {
    /// CREATE_FAST command ID.
    pub const ID: u8 = 5;

    /// Creates new CREATE_FAST cell from existing [`FixedCell`].
    ///
    /// # Safety
    ///
    /// Data must be a valid CREATE_FAST cell.
    pub unsafe fn from_cell(circuit: NonZeroU32, data: FixedCell) -> Self {
        Self {
            circuit,
            cell: data,
        }
    }

    /// Creates new CREATE_FAST cell.
    ///
    /// # Parameters
    ///
    /// - `cell` : Cached [`FixedCell`].
    /// - `circuit` : Circuit ID.
    /// - `key` : Key material.
    pub fn new(mut cell: FixedCell, circuit: NonZeroU32, key: Sha1Output) -> Self {
        let CreateFastCell { key_x, .. } = transmute_mut!(cell.data_mut());
        *key_x = key;

        // SAFETY: Data is valid
        unsafe { Self::from_cell(circuit, cell) }
    }

    /// Gets key material.
    pub fn key(&self) -> &Sha1Output {
        let CreateFastCell { key_x, .. } = transmute_ref!(self.cell.data());
        key_x
    }

    /// Unwraps into inner [`FixedCell`].
    pub fn into_inner(self) -> FixedCell {
        self.cell
    }
}

/// CREATED_FAST cell content.
#[derive(FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned)]
#[repr(C)]
struct CreatedFastCell {
    /// Key material, second part.
    key_y: Sha1Output,

    /// Derived key material. Used to verify key.
    derived: Sha1Output,

    /// Trailing data.
    trailing: [u8; const { FIXED_CELL_SIZE - size_of::<Sha1Output>() * 2 }],
}

/// Represents a CREATED_FAST cell.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct CreatedFast {
    pub circuit: NonZeroU32,
    cell: FixedCell,
}

impl From<CreatedFast> for Cell {
    fn from(v: CreatedFast) -> Cell {
        Cell::from_fixed(
            CellHeader::new(v.circuit.get(), CreatedFast::ID),
            v.into_inner(),
        )
    }
}

impl From<CreatedFast> for FixedCell {
    fn from(v: CreatedFast) -> FixedCell {
        v.into_inner()
    }
}

impl TryFromCell for CreatedFast {
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
        to_fixed(cell).map(|v| v.map(|v| unsafe { Self::from_cell(cid, v) }))
    }
}

impl CellLike for CreatedFast {
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

impl CreatedFast {
    /// CREATED_FAST command ID.
    pub const ID: u8 = 6;

    /// Creates new CREATED_FAST cell from existing [`FixedCell`].
    ///
    /// # Safety
    ///
    /// Data must be a valid CREATED_FAST cell.
    pub unsafe fn from_cell(circuit: NonZeroU32, data: FixedCell) -> Self {
        Self {
            circuit,
            cell: data,
        }
    }

    /// Creates new CREATED_FAST cell.
    ///
    /// # Parameters
    ///
    /// - `cell` : Cached [`FixedCell`].
    /// - `circuit` : Circuit ID.
    /// - `key` : Key material.
    /// - `derived` : Derived key material.
    pub fn new(
        mut cell: FixedCell,
        circuit: NonZeroU32,
        key: Sha1Output,
        derived: Sha1Output,
    ) -> Self {
        let CreatedFastCell {
            key_y, derived: d, ..
        } = transmute_mut!(cell.data_mut());
        *key_y = key;
        *d = derived;

        // SAFETY: Data is valid
        unsafe { Self::from_cell(circuit, cell) }
    }

    /// Gets key material.
    pub fn key(&self) -> &Sha1Output {
        let CreatedFastCell { key_y, .. } = transmute_ref!(self.cell.data());
        key_y
    }

    /// Gets derived key material.
    pub fn derived(&self) -> &Sha1Output {
        let CreatedFastCell { derived, .. } = transmute_ref!(self.cell.data());
        derived
    }

    /// Unwraps into inner [`FixedCell`].
    pub fn into_inner(self) -> FixedCell {
        self.cell
    }
}
