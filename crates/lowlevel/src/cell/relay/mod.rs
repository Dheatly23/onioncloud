pub mod begin;
pub mod begin_dir;
pub mod connected;
pub mod data;

use std::mem::{size_of, transmute};
use std::num::NonZeroU32;

use rand::prelude::*;
use zerocopy::byteorder::big_endian::U16;
use zerocopy::{
    FromBytes, Immutable, IntoBytes, KnownLayout, Unaligned, transmute_mut, transmute_ref,
};

use super::{
    Cell, CellHeader, CellLike, CellRef, FIXED_CELL_SIZE, FixedCell, TryFromCell, to_fixed,
};
use crate::cache::Cachable;
use crate::errors;
use crate::private::Sealed;

/// RELAY and RELAY_EARLY cell header.
#[derive(FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned, Debug, PartialEq, Eq)]
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

/// Common trait for [`Relay`] and [`RelayEarly`] cells.
pub trait RelayLike: Sealed + AsRef<[u8; FIXED_CELL_SIZE]> + AsMut<[u8; FIXED_CELL_SIZE]> {
    /// Gets command.
    fn command(&self) -> u8 {
        cast_cell(self).header.command
    }

    /// Sets command.
    fn set_command(&mut self, value: u8) {
        cast_cell_mut(self).header.command = value;
    }

    /// Gets recognized.
    fn recognized(&self) -> [u8; 2] {
        cast_cell(self).header.recognized
    }

    /// Sets recognized.
    fn set_recognized(&mut self, value: [u8; 2]) {
        cast_cell_mut(self).header.recognized = value;
    }

    /// Check if cell is recognized.
    fn is_recognized(&self) -> bool {
        self.recognized() == [0; 2]
    }

    /// Gets stream ID.
    fn stream(&self) -> u16 {
        cast_cell(self).header.stream.get()
    }

    /// Sets stream ID.
    fn set_stream(&mut self, value: u16) {
        cast_cell_mut(self).header.stream.set(value);
    }

    /// Gets digest.
    fn digest(&self) -> [u8; 4] {
        cast_cell(self).header.digest
    }

    /// Sets digest.
    fn set_digest(&mut self, value: [u8; 4]) {
        cast_cell_mut(self).header.digest = value;
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

/// Represents a RELAY cell.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Relay {
    pub circuit: NonZeroU32,
    cell: FixedCell,
}

impl Sealed for Relay {}
impl RelayLike for Relay {}

impl AsRef<FixedCell> for Relay {
    fn as_ref(&self) -> &FixedCell {
        &self.cell
    }
}

impl AsMut<FixedCell> for Relay {
    fn as_mut(&mut self) -> &mut FixedCell {
        &mut self.cell
    }
}

impl AsRef<[u8; FIXED_CELL_SIZE]> for Relay {
    fn as_ref(&self) -> &[u8; FIXED_CELL_SIZE] {
        self.cell.data()
    }
}

impl AsMut<[u8; FIXED_CELL_SIZE]> for Relay {
    fn as_mut(&mut self) -> &mut [u8; FIXED_CELL_SIZE] {
        self.cell.data_mut()
    }
}

impl AsRef<[u8]> for Relay {
    fn as_ref(&self) -> &[u8] {
        self.cell.data()
    }
}

impl AsMut<[u8]> for Relay {
    fn as_mut(&mut self) -> &mut [u8] {
        self.cell.data_mut()
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
        CellRef::Fixed(&self.cell)
    }
}

impl Cachable for Option<Relay> {
    fn maybe_into_fixed(self) -> Option<FixedCell> {
        self?.maybe_into_fixed()
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
            cell: data,
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

    /// Unwraps into inner [`FixedCell`].
    pub fn into_inner(self) -> FixedCell {
        self.cell
    }
}

/// Represents a RELAY_EARLY cell.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct RelayEarly {
    pub circuit: NonZeroU32,
    cell: FixedCell,
}

impl Sealed for RelayEarly {}
impl RelayLike for RelayEarly {}

impl AsRef<FixedCell> for RelayEarly {
    fn as_ref(&self) -> &FixedCell {
        &self.cell
    }
}

impl AsMut<FixedCell> for RelayEarly {
    fn as_mut(&mut self) -> &mut FixedCell {
        &mut self.cell
    }
}

impl AsRef<[u8; FIXED_CELL_SIZE]> for RelayEarly {
    fn as_ref(&self) -> &[u8; FIXED_CELL_SIZE] {
        self.cell.data()
    }
}

impl AsMut<[u8; FIXED_CELL_SIZE]> for RelayEarly {
    fn as_mut(&mut self) -> &mut [u8; FIXED_CELL_SIZE] {
        self.cell.data_mut()
    }
}

impl AsRef<[u8]> for RelayEarly {
    fn as_ref(&self) -> &[u8] {
        self.cell.data()
    }
}

impl AsMut<[u8]> for RelayEarly {
    fn as_mut(&mut self) -> &mut [u8] {
        self.cell.data_mut()
    }
}

impl From<Relay> for RelayEarly {
    fn from(v: Relay) -> Self {
        Self {
            circuit: v.circuit,
            cell: v.cell,
        }
    }
}

impl From<RelayEarly> for Relay {
    fn from(v: RelayEarly) -> Self {
        Self {
            circuit: v.circuit,
            cell: v.cell,
        }
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
        CellRef::Fixed(&self.cell)
    }
}

impl Cachable for Option<RelayEarly> {
    fn maybe_into_fixed(self) -> Option<FixedCell> {
        self?.maybe_into_fixed()
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
            cell: data,
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

    /// Unwraps into inner [`FixedCell`].
    pub fn into_inner(self) -> FixedCell {
        self.cell
    }
}

/// Helper for wrapping RELAY cell payload.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[repr(transparent)]
struct RelayWrapper(FixedCell);

impl Sealed for RelayWrapper {}
impl RelayLike for RelayWrapper {}

impl AsRef<FixedCell> for RelayWrapper {
    fn as_ref(&self) -> &FixedCell {
        &self.0
    }
}

impl AsMut<FixedCell> for RelayWrapper {
    fn as_mut(&mut self) -> &mut FixedCell {
        &mut self.0
    }
}

impl AsRef<[u8; FIXED_CELL_SIZE]> for RelayWrapper {
    fn as_ref(&self) -> &[u8; FIXED_CELL_SIZE] {
        self.0.data()
    }
}

impl AsMut<[u8; FIXED_CELL_SIZE]> for RelayWrapper {
    fn as_mut(&mut self) -> &mut [u8; FIXED_CELL_SIZE] {
        self.0.data_mut()
    }
}

impl From<FixedCell> for RelayWrapper {
    fn from(v: FixedCell) -> Self {
        Self(v)
    }
}

impl From<RelayWrapper> for FixedCell {
    fn from(v: RelayWrapper) -> FixedCell {
        v.0
    }
}

impl<'a> From<&'a FixedCell> for &'a RelayWrapper {
    fn from(v: &'a FixedCell) -> Self {
        // SAFETY: RelayWrapper can be transparently transmuted to FixedCell
        unsafe { transmute(v) }
    }
}

impl<'a> From<&'a mut FixedCell> for &'a mut RelayWrapper {
    fn from(v: &'a mut FixedCell) -> Self {
        // SAFETY: RelayWrapper can be transparently transmuted to FixedCell
        unsafe { transmute(v) }
    }
}

impl<'a> From<&'a RelayWrapper> for &'a FixedCell {
    fn from(v: &'a RelayWrapper) -> Self {
        // SAFETY: FixedCell can be transparently transmuted to RelayWrapper
        unsafe { transmute(v) }
    }
}

impl<'a> From<&'a mut RelayWrapper> for &'a mut FixedCell {
    fn from(v: &'a mut RelayWrapper) -> Self {
        // SAFETY: FixedCell can be transparently transmuted to RelayWrapper
        unsafe { transmute(v) }
    }
}

/// Trait to cast from [`Relay`] cell.
pub trait TryFromRelay: Sized {
    /// Checks cell content, take it, then cast it into `Self`.
    ///
    /// Returns a [`None`] value if the checks are failed, but can be passed onto the next type.
    /// Error result only happens when the format of the cell itself is invalid.
    ///
    /// # Implementers Note
    ///
    /// This method **should** not mutate the cell, it's only allowed to inspect it.
    /// If the checks are good, then use the [`Option::take`] method to pop cell out of it.
    /// The cell may not be dropped, only moved.
    fn try_from_relay(relay: &mut Option<Relay>) -> Result<Option<Self>, errors::CellFormatError>;
}

/// Convenient function wrapping [`TryFromRelay`].
pub fn cast<T: TryFromRelay>(
    relay: &mut Option<Relay>,
) -> Result<Option<T>, errors::CellFormatError> {
    T::try_from_relay(relay)
}

fn take_if(
    relay: &mut Option<Relay>,
    check: impl FnOnce(&[u8]) -> bool,
) -> Result<Option<RelayWrapper>, errors::CellFormatError> {
    match relay.take() {
        Some(r) if check(r.data()) => Ok(Some(r.cell.into())),
        None => Ok(None),
        v => {
            *relay = v;
            Err(errors::CellFormatError)
        }
    }
}

/// Convert cell into [`Relay`] cell.
pub trait IntoRelay: Sized {
    /// Convert into [`Relay`] with given circuit ID.
    fn into_relay(self, circuit: NonZeroU32) -> Relay;

    /// Convert into [`RelayEarly`] with given circuit ID.
    fn into_relay_early(self, circuit: NonZeroU32) -> RelayEarly {
        self.into_relay(circuit).into()
    }
}

impl IntoRelay for RelayWrapper {
    fn into_relay(self, circuit: NonZeroU32) -> Relay {
        Relay {
            circuit,
            cell: self.0,
        }
    }
}

fn with_cmd_stream(mut data: RelayWrapper, cmd: u8, stream: u16, circuit: NonZeroU32) -> Relay {
    data.set_command(cmd);
    data.set_stream(stream);
    data.fill_padding();
    data.into_relay(circuit)
}

#[cfg(test)]
mod tests {
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
