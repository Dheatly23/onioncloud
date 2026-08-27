//! Create cell types.

use std::num::NonZeroU32;

use zerocopy::byteorder::big_endian::U16;
use zerocopy::{
    FromBytes, Immutable, IntoBytes, KnownLayout, Unaligned, transmute_mut, transmute_ref,
};

use crate::cell::{AutoReturnFixed, Cell, CellHeader, TryFromCell};
use crate::error::{CellCastError, CellFormatError, ZeroCircID};
use crate::fixed::{FIXED_CELL_SIZE, FixedCell};

/// CREATE2 cell data.
#[derive(FromBytes, IntoBytes, Immutable, KnownLayout, Unaligned)]
#[repr(C)]
struct Create2Data {
    ty: U16,
    len: U16,
    data: [u8; const { FIXED_CELL_SIZE - 4 }],
}

/// CREATE2 cell.
#[derive(Debug)]
pub struct Create2 {
    /// Circuit ID.
    pub circuit: NonZeroU32,
    cell: FixedCell,
}

impl TryFromCell for Create2 {
    type Error = CellCastError;

    fn try_from_cell(cell: &mut Option<Cell>) -> Result<Option<Self>, Self::Error> {
        if let Some(cell) = AutoReturnFixed::new(cell)?
            && cell.header().command == Self::ID
        {
            let circuit = NonZeroU32::new(cell.header().circuit).ok_or(ZeroCircID)?;
            let data: &Create2Data = transmute_ref!(cell.data().data());
            if data.len.get() as usize <= FIXED_CELL_SIZE - 4 {
                Ok(Some(Self {
                    circuit,
                    cell: cell.into_inner().1,
                }))
            } else {
                Err(CellFormatError.into())
            }
        } else {
            return Ok(None);
        }
    }
}

impl From<Create2> for Cell {
    #[inline]
    fn from(cell: Create2) -> Self {
        Self::from_fixed(
            CellHeader {
                command: Create2::ID,
                circuit: cell.circuit.into(),
            },
            cell.into_inner(),
        )
    }
}

impl AsRef<FixedCell> for Create2 {
    #[inline]
    fn as_ref(&self) -> &FixedCell {
        self.inner()
    }
}

impl Create2 {
    /// Cell ID of CREATE2.
    pub const ID: u8 = 10;

    /// Creates new [`Create2`].
    ///
    /// Returns [`None`] if payload does not fit the cell.
    pub fn new(circuit: NonZeroU32, mut cell: FixedCell, ty: u16, data: &[u8]) -> Option<Self> {
        if data.len() > FIXED_CELL_SIZE - 4 {
            return None;
        }

        let p: &mut Create2Data = transmute_mut!(cell.data_mut());
        p.ty.set(ty);
        p.len.set(data.len() as u16);
        let (a, b) = p.data.split_at_mut(data.len());
        a.copy_from_slice(data);
        b.fill(0);

        Some(Self { circuit, cell })
    }

    /// Gets reference to inner.
    #[inline]
    pub fn inner(&self) -> &FixedCell {
        &self.cell
    }

    #[inline]
    fn get_ref(&self) -> &Create2Data {
        transmute_ref!(self.cell.data())
    }

    #[inline]
    fn get_mut(&mut self) -> &mut Create2Data {
        transmute_mut!(self.cell.data_mut())
    }

    /// Gets handshake type.
    #[inline]
    pub fn handshake_ty(&self) -> u16 {
        self.get_ref().ty.get()
    }

    /// Sets handshake type.
    #[inline]
    pub fn set_handshake_ty(&mut self, ty: u16) {
        self.get_mut().ty.set(ty);
    }

    /// Gets reference to payload.
    #[inline]
    pub fn payload(&self) -> &[u8] {
        let cell = self.get_ref();
        // SAFETY: Length field is validated.
        unsafe { cell.data.get_unchecked(..cell.len.get() as usize) }
    }

    /// Gets mutable reference to payload.
    #[inline]
    pub fn payload_mut(&mut self) -> &mut [u8] {
        let cell = self.get_mut();
        // SAFETY: Length field is validated.
        unsafe { cell.data.get_unchecked_mut(..cell.len.get() as usize) }
    }

    /// Gets payload length.
    ///
    /// Guaranteed to be < 65536 and equals to returned [`Self::payload`] slice length.
    #[inline]
    pub fn payload_len(&self) -> usize {
        self.get_ref().len.get().into()
    }

    /// Unwraps into inner.
    #[inline]
    pub fn into_inner(self) -> FixedCell {
        self.cell
    }
}
