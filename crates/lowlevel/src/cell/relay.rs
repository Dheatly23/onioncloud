use std::mem::size_of;
use std::num::NonZeroU32;

use zerocopy::byteorder::big_endian::U16;
use zerocopy::{
    FromBytes, Immutable, IntoBytes, KnownLayout, Unaligned, transmute_mut, transmute_ref,
};

use super::{
    Cell, CellHeader, CellLike, CellRef, FIXED_CELL_SIZE, FixedCell, TryFromCell, to_fixed,
};
use crate::errors;

/// RELAY and RELAY_EARLY cell header.
#[derive(FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned)]
#[repr(C)]
pub(crate) struct RelayHeader {
    /// Relay command.
    pub(crate) command: u8,

    /// Recognized field.
    pub(crate) recognized: [u8; 2],

    /// Stream ID.
    pub(crate) stream: U16,

    /// Cell digest.
    pub(crate) digest: [u8; 4],

    /// Message length.
    pub(crate) len: U16,
}

pub(crate) const RELAY_DATA_LENGTH: usize = FIXED_CELL_SIZE - size_of::<RelayHeader>();

/// RELAY and RELAY_EARLY cell content.
#[derive(FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned)]
#[repr(C)]
pub(crate) struct RelayCell {
    /// Relay header.
    pub(crate) header: RelayHeader,

    /// Message payload + padding.
    pub(crate) data: [u8; RELAY_DATA_LENGTH],
}

/// Common abstraction of RELAY and RELAY_EARLY.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct RelayInner(FixedCell);

impl RelayInner {
    /// Gets command.
    fn command(&self) -> u8 {
        self.cast().header.command
    }

    /// Sets command.
    fn set_command(&mut self, value: u8) {
        self.cast_mut().header.command = value;
    }

    /// Gets recognized.
    fn recognized(&self) -> [u8; 2] {
        self.cast().header.recognized
    }

    /// Sets recognized.
    fn set_recognized(&mut self, value: [u8; 2]) {
        self.cast_mut().header.recognized = value;
    }

    /// Gets stream ID.
    fn stream(&self) -> u16 {
        self.cast().header.stream.get()
    }

    /// Sets stream ID.
    fn set_stream(&mut self, value: u16) {
        self.cast_mut().header.stream.set(value);
    }

    /// Gets digest.
    fn digest(&self) -> [u8; 4] {
        self.cast().header.digest
    }

    /// Sets digest.
    fn set_digest(&mut self, value: [u8; 4]) {
        self.cast_mut().header.digest = value;
    }

    /// Gets length.
    fn len(&self) -> u16 {
        self.cast().header.len.get()
    }

    /// Get payload.
    ///
    /// # Panics
    ///
    /// Panics if length field is invalid. This can happen if the cell content is encrypted.
    fn data(&self) -> &[u8] {
        let cell = self.cast();
        &cell.data[..usize::from(cell.header.len.get())]
    }

    /// Set payload.
    ///
    /// # Panics
    ///
    /// Panics if `data` is longer than [`RELAY_DATA_LENGTH`].
    fn set_data(&mut self, data: &[u8]) {
        let cell = self.cast_mut();
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

    fn cast(&self) -> &RelayCell {
        transmute_ref!(self.0.data())
    }

    fn cast_mut(&mut self) -> &mut RelayCell {
        transmute_mut!(self.0.data_mut())
    }
}

/// Represents a RELAY cell.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Relay {
    pub circuit: NonZeroU32,
    cell: RelayInner,
}

impl AsRef<[u8; FIXED_CELL_SIZE]> for Relay {
    fn as_ref(&self) -> &[u8; FIXED_CELL_SIZE] {
        self.cell.0.data()
    }
}

impl AsMut<[u8; FIXED_CELL_SIZE]> for Relay {
    fn as_mut(&mut self) -> &mut [u8; FIXED_CELL_SIZE] {
        self.cell.0.data_mut()
    }
}

impl From<Relay> for Cell {
    fn from(v: Relay) -> Cell {
        Cell::from_fixed(CellHeader::new(v.circuit.get(), Relay::ID), v.into_inner())
    }
}

impl From<Relay> for FixedCell {
    fn from(v: Relay) -> FixedCell {
        v.into_inner()
    }
}

impl TryFromCell for Relay {
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
        to_fixed(cell).map(|v| v.map(|v| Self::from_cell(cid, v)))
    }
}

impl CellLike for Relay {
    fn circuit(&self) -> u32 {
        self.circuit.get()
    }

    fn command(&self) -> u8 {
        Self::ID
    }

    fn cell(&self) -> CellRef<'_> {
        CellRef::Fixed(&self.cell.0)
    }
}

impl Relay {
    /// RELAY command ID.
    pub const ID: u8 = 3;

    /// Creates new RELAY cell from existing [`FixedCell`].
    ///
    /// All cell values are valid because cell content is encrypted.
    pub fn from_cell(circuit: NonZeroU32, data: FixedCell) -> Self {
        Self {
            circuit,
            cell: RelayInner(data),
        }
    }

    /// Creates new RELAY cell.
    ///
    /// # Parameters
    ///
    /// - `cell` : Cached [`FixedCell`].
    /// - `circuit` : Circuit ID.
    /// - `command` : Relay command.
    /// - `stream` : Stream ID.
    /// - `data` : Message payload.
    ///
    /// # Panics
    ///
    /// Panics if `data` is longer than [`RELAY_DATA_LENGTH`].
    pub fn new(
        mut cell: FixedCell,
        circuit: NonZeroU32,
        command: u8,
        stream: u16,
        data: &[u8],
    ) -> Self {
        let RelayCell { header, data: out } = transmute_mut!(cell.data_mut());
        assert!(
            data.len() <= out.len(),
            "data is too long ({} > {})",
            data.len(),
            out.len()
        );
        out[..data.len()].copy_from_slice(data);
        header.command = command;
        header.recognized = [0; 2];
        header.stream.set(stream);
        header.digest = [0; 4];
        header
            .len
            .set(data.len().try_into().expect("data must fit cell"));

        Self::from_cell(circuit, cell)
    }

    /// Gets command.
    pub fn command(&self) -> u8 {
        self.cell.command()
    }

    /// Sets command.
    pub fn set_command(&mut self, value: u8) -> &mut Self {
        self.cell.set_command(value);
        self
    }

    /// Gets recognized.
    pub fn recognized(&self) -> [u8; 2] {
        self.cell.recognized()
    }

    /// Checks if cell is recognized.
    pub fn is_recognized(&self) -> bool {
        self.recognized() == [0; 2]
    }

    /// Sets recognized.
    pub fn set_recognized(&mut self, value: [u8; 2]) -> &mut Self {
        self.cell.set_recognized(value);
        self
    }

    /// Gets stream ID.
    pub fn stream(&self) -> u16 {
        self.cell.stream()
    }

    /// Sets stream ID.
    pub fn set_stream(&mut self, value: u16) -> &mut Self {
        self.cell.set_stream(value);
        self
    }

    /// Gets digest.
    pub fn digest(&self) -> [u8; 4] {
        self.cell.digest()
    }

    /// Sets digest.
    pub fn set_digest(&mut self, value: [u8; 4]) -> &mut Self {
        self.cell.set_digest(value);
        self
    }

    /// Gets length.
    pub fn len(&self) -> u16 {
        self.cell.len()
    }

    /// Get payload.
    ///
    /// # Panics
    ///
    /// Panics if length field is invalid. This can happen if the cell content is encrypted.
    pub fn data(&self) -> &[u8] {
        self.cell.data()
    }

    /// Set payload.
    ///
    /// # Panics
    ///
    /// Panics if `data` is longer than [`RELAY_DATA_LENGTH`].
    pub fn set_data(&mut self, data: &[u8]) -> &mut Self {
        self.cell.set_data(data);
        self
    }

    /// Unwraps into inner [`FixedCell`].
    pub fn into_inner(self) -> FixedCell {
        self.cell.0
    }
}

/// Represents a RELAY_EARLY cell.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct RelayEarly {
    pub circuit: NonZeroU32,
    cell: RelayInner,
}

impl AsRef<[u8; FIXED_CELL_SIZE]> for RelayEarly {
    fn as_ref(&self) -> &[u8; FIXED_CELL_SIZE] {
        self.cell.0.data()
    }
}

impl AsMut<[u8; FIXED_CELL_SIZE]> for RelayEarly {
    fn as_mut(&mut self) -> &mut [u8; FIXED_CELL_SIZE] {
        self.cell.0.data_mut()
    }
}

impl From<RelayEarly> for Cell {
    fn from(v: RelayEarly) -> Cell {
        Cell::from_fixed(
            CellHeader::new(v.circuit.get(), RelayEarly::ID),
            v.into_inner(),
        )
    }
}

impl From<RelayEarly> for FixedCell {
    fn from(v: RelayEarly) -> FixedCell {
        v.into_inner()
    }
}

impl TryFromCell for RelayEarly {
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
        to_fixed(cell).map(|v| v.map(|v| Self::from_cell(cid, v)))
    }
}

impl CellLike for RelayEarly {
    fn circuit(&self) -> u32 {
        self.circuit.get()
    }

    fn command(&self) -> u8 {
        Self::ID
    }

    fn cell(&self) -> CellRef<'_> {
        CellRef::Fixed(&self.cell.0)
    }
}

impl RelayEarly {
    /// RELAY_EARLY command ID.
    pub const ID: u8 = 9;

    /// Creates new RELAY_EARLY cell from existing [`FixedCell`].
    ///
    /// All cell values are valid because cell content is encrypted.
    pub fn from_cell(circuit: NonZeroU32, data: FixedCell) -> Self {
        Self {
            circuit,
            cell: RelayInner(data),
        }
    }

    /// Creates new RELAY_EARLY cell.
    ///
    /// # Parameters
    ///
    /// - `cell` : Cached [`FixedCell`].
    /// - `circuit` : Circuit ID.
    /// - `command` : Relay command.
    /// - `stream` : Stream ID.
    /// - `data` : Message payload.
    ///
    /// # Panics
    ///
    /// Panics if `data` is longer than [`RELAY_DATA_LENGTH`].
    pub fn new(
        mut cell: FixedCell,
        circuit: NonZeroU32,
        command: u8,
        stream: u16,
        data: &[u8],
    ) -> Self {
        let RelayCell { header, data: out } = transmute_mut!(cell.data_mut());
        assert!(
            data.len() <= out.len(),
            "data is too long ({} > {})",
            data.len(),
            out.len()
        );
        out[..data.len()].copy_from_slice(data);
        header.command = command;
        header.recognized = [0; 2];
        header.stream.set(stream);
        header.digest = [0; 4];
        header
            .len
            .set(data.len().try_into().expect("data must fit cell"));

        Self::from_cell(circuit, cell)
    }

    /// Gets command.
    pub fn command(&self) -> u8 {
        self.cell.command()
    }

    /// Sets command.
    pub fn set_command(&mut self, value: u8) -> &mut Self {
        self.cell.set_command(value);
        self
    }

    /// Gets recognized.
    pub fn recognized(&self) -> [u8; 2] {
        self.cell.recognized()
    }

    /// Checks if cell is recognized.
    pub fn is_recognized(&self) -> bool {
        self.recognized() == [0; 2]
    }

    /// Sets recognized.
    pub fn set_recognized(&mut self, value: [u8; 2]) -> &mut Self {
        self.cell.set_recognized(value);
        self
    }

    /// Gets stream ID.
    pub fn stream(&self) -> u16 {
        self.cell.stream()
    }

    /// Sets stream ID.
    pub fn set_stream(&mut self, value: u16) -> &mut Self {
        self.cell.set_stream(value);
        self
    }

    /// Gets digest.
    pub fn digest(&self) -> [u8; 4] {
        self.cell.digest()
    }

    /// Sets digest.
    pub fn set_digest(&mut self, value: [u8; 4]) -> &mut Self {
        self.cell.set_digest(value);
        self
    }

    /// Gets length.
    pub fn len(&self) -> u16 {
        self.cell.len()
    }

    /// Get payload.
    ///
    /// # Panics
    ///
    /// Panics if length field is invalid. This can happen if the cell content is encrypted.
    pub fn data(&self) -> &[u8] {
        self.cell.data()
    }

    /// Set payload.
    ///
    /// # Panics
    ///
    /// Panics if `data` is longer than [`RELAY_DATA_LENGTH`].
    pub fn set_data(&mut self, data: &[u8]) -> &mut Self {
        self.cell.set_data(data);
        self
    }

    /// Unwraps into inner [`FixedCell`].
    pub fn into_inner(self) -> FixedCell {
        self.cell.0
    }
}
