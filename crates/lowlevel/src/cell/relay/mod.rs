pub mod begin;
pub mod begin_dir;
pub mod connected;
pub mod data;
pub mod drop;
pub mod end;
pub mod extend;
pub mod sendme;
pub mod v0;
pub mod v1;

use std::mem::transmute;
use std::num::{NonZeroU16, NonZeroU32};

use zerocopy::byteorder::big_endian::U16;
use zerocopy::{
    FromBytes, Immutable, IntoBytes, KnownLayout, Unaligned, transmute_mut, transmute_ref,
};

use super::{
    Cell, CellHeader, CellLike, CellRef, FIXED_CELL_SIZE, FixedCell, TryFromCell, to_fixed,
};
use crate::cache::{Cachable, Cached, CellCache};
use crate::errors;
use crate::private::Sealed;

/// Common trait for [`Relay`] and [`RelayEarly`] cells.
pub trait RelayLike: Sealed + AsRef<[u8; FIXED_CELL_SIZE]> + AsMut<[u8; FIXED_CELL_SIZE]> {}

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

impl Cachable for Relay {
    fn cache<C: CellCache + ?Sized>(self, cache: &C) {
        self.cell.cache(cache);
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
    /// Panics if `data` is longer than [`RELAY_DATA_LENGTH`](`v0::RELAY_DATA_LENGTH``).
    pub fn new(
        cell: FixedCell,
        circuit: NonZeroU32,
        command: u8,
        stream: u16,
        data: &[u8],
    ) -> Self {
        use v0::RelayExt as _;
        let mut ret = Self::from_cell(circuit, cell);
        ret.set_data(data);
        ret.set_command(command);
        ret.set_recognized([0; 2]);
        ret.set_stream(stream);
        ret.set_digest([0; 4]);
        ret
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
    /// Panics if `data` is longer than [`RELAY_DATA_LENGTH`](`v1::RELAY_DATA_LENGTH``).
    pub fn new_v1(
        cell: FixedCell,
        circuit: NonZeroU32,
        command: u8,
        stream: u16,
        data: &[u8],
    ) -> Self {
        use v1::RelayExt as _;
        let mut ret = Self::from_cell(circuit, cell);
        ret.set_data(data);
        ret.set_command(command);
        ret.set_stream(stream);
        *ret.tag_mut() = [0; 16];
        ret
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

impl Cachable for RelayEarly {
    fn cache<C: CellCache + ?Sized>(self, cache: &C) {
        self.cell.cache(cache);
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
    /// Panics if `data` is longer than [`RELAY_DATA_LENGTH`](`v0::RELAY_DATA_LENGTH``).
    pub fn new(
        cell: FixedCell,
        circuit: NonZeroU32,
        command: u8,
        stream: u16,
        data: &[u8],
    ) -> Self {
        let Relay { circuit, cell } = Relay::new(cell, circuit, command, stream, data);
        Self::from_cell(circuit, cell)
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
    /// Panics if `data` is longer than [`RELAY_DATA_LENGTH`](`v1::RELAY_DATA_LENGTH``).
    pub fn new_v1(
        cell: FixedCell,
        circuit: NonZeroU32,
        command: u8,
        stream: u16,
        data: &[u8],
    ) -> Self {
        let Relay { circuit, cell } = Relay::new_v1(cell, circuit, command, stream, data);
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

impl Cachable for RelayWrapper {
    fn cache<C: CellCache + ?Sized>(self, cache: &C) {
        self.0.cache(cache);
    }
}

impl RelayWrapper {
    /// Convert into relay.
    fn into_relay(self, circuit: NonZeroU32) -> Relay {
        Relay {
            circuit,
            cell: self.0,
        }
    }
}

/// Helper for wrapping reference to RELAY cell payload.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[repr(transparent)]
pub struct RelayRefWrapper([u8; FIXED_CELL_SIZE]);

impl Sealed for RelayRefWrapper {}
impl RelayLike for RelayRefWrapper {}

impl AsRef<[u8; FIXED_CELL_SIZE]> for RelayRefWrapper {
    fn as_ref(&self) -> &[u8; FIXED_CELL_SIZE] {
        &self.0
    }
}

impl AsMut<[u8; FIXED_CELL_SIZE]> for RelayRefWrapper {
    fn as_mut(&mut self) -> &mut [u8; FIXED_CELL_SIZE] {
        &mut self.0
    }
}

impl<'a> From<&'a [u8; FIXED_CELL_SIZE]> for &'a RelayRefWrapper {
    fn from(v: &'a [u8; FIXED_CELL_SIZE]) -> Self {
        // SAFETY: RelayRefWrapper can be transparently transmuted to array
        unsafe { transmute(v) }
    }
}

impl<'a> From<&'a mut [u8; FIXED_CELL_SIZE]> for &'a mut RelayRefWrapper {
    fn from(v: &'a mut [u8; FIXED_CELL_SIZE]) -> Self {
        // SAFETY: RelayRefWrapper can be transparently transmuted to array
        unsafe { transmute(v) }
    }
}

impl<'a> From<&'a RelayRefWrapper> for &'a [u8; FIXED_CELL_SIZE] {
    fn from(v: &'a RelayRefWrapper) -> Self {
        // SAFETY: array can be transparently transmuted to RelayRefWrapper
        unsafe { transmute(v) }
    }
}

impl<'a> From<&'a mut RelayRefWrapper> for &'a mut [u8; FIXED_CELL_SIZE] {
    fn from(v: &'a mut RelayRefWrapper) -> Self {
        // SAFETY: array can be transparently transmuted to RelayRefWrapper
        unsafe { transmute(v) }
    }
}

/// Relay format version.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum RelayVersion {
    /// Default version.
    #[default]
    V0,

    /// (Proposed) version for counter galois mode.
    V1,
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
    fn try_from_relay(
        relay: &mut Option<Relay>,
        version: RelayVersion,
    ) -> Result<Option<Self>, errors::CellFormatError>;

    /// Cast from version 0 relay.
    fn try_from_relay_v0(
        relay: &mut Option<Relay>,
    ) -> Result<Option<Self>, errors::CellFormatError> {
        Self::try_from_relay(relay, RelayVersion::V0)
    }

    /// Cast from version 1 relay.
    fn try_from_relay_v1(
        relay: &mut Option<Relay>,
    ) -> Result<Option<Self>, errors::CellFormatError> {
        Self::try_from_relay(relay, RelayVersion::V1)
    }
}

/// Convenient function wrapping [`TryFromRelay`].
pub fn cast<T: TryFromRelay>(
    relay: &mut Option<Relay>,
    version: RelayVersion,
) -> Result<Option<T>, errors::CellFormatError> {
    T::try_from_relay(relay, version)
}

fn take_if_nonzero_stream(
    relay: &mut Option<Relay>,
    command: u8,
    version: RelayVersion,
    check: impl FnOnce(&[u8]) -> bool,
) -> Result<Option<(NonZeroU16, RelayWrapper)>, errors::CellFormatError> {
    let Some(r) = relay.as_ref() else {
        return Ok(None);
    };

    let (c, stream, data) = match version {
        RelayVersion::V0 => (
            v0::RelayExt::command(r),
            v0::RelayExt::stream(r),
            v0::RelayExt::data(r),
        ),
        RelayVersion::V1 => (
            v1::RelayExt::command(r),
            v1::RelayExt::stream(r),
            v1::RelayExt::data(r),
        ),
    };
    let stream = if c != command {
        return Ok(None);
    } else if let Some(stream) = NonZeroU16::new(stream)
        && check(data)
    {
        stream
    } else {
        return Err(errors::CellFormatError);
    };

    // SAFETY: Relay is some
    unsafe { Ok(Some((stream, relay.take().unwrap_unchecked().cell.into()))) }
}

fn take_if(
    relay: &mut Option<Relay>,
    command: u8,
    version: RelayVersion,
    check: impl FnOnce(&[u8]) -> bool,
) -> Result<Option<(u16, RelayWrapper)>, errors::CellFormatError> {
    let Some(r) = relay.as_ref() else {
        return Ok(None);
    };

    let (c, stream, data) = match version {
        RelayVersion::V0 => (
            v0::RelayExt::command(r),
            v0::RelayExt::stream(r),
            v0::RelayExt::data(r),
        ),
        RelayVersion::V1 => (
            v1::RelayExt::command(r),
            v1::RelayExt::stream(r),
            v1::RelayExt::data(r),
        ),
    };
    let stream = if c != command {
        return Ok(None);
    } else if check(data) {
        stream
    } else {
        return Err(errors::CellFormatError);
    };

    // SAFETY: Relay is some
    unsafe { Ok(Some((stream, relay.take().unwrap_unchecked().cell.into()))) }
}

/// Convert cell into [`Relay`] cell.
pub trait IntoRelay: Sized {
    /// Convert into [`Relay`] with given circuit ID and version.
    fn try_into_relay(
        self,
        circuit: NonZeroU32,
        version: RelayVersion,
    ) -> Result<Relay, errors::CellLengthOverflowError>;

    /// Convert into [`RelayEarly`] with given circuit ID and version.
    fn try_into_relay_early(
        self,
        circuit: NonZeroU32,
        version: RelayVersion,
    ) -> Result<RelayEarly, errors::CellLengthOverflowError> {
        self.try_into_relay(circuit, version).map(RelayEarly::from)
    }

    /// Same as [`try_into_relay`], but with [`Cached`].
    fn try_into_relay_cached<C: CellCache>(
        this: Cached<Self, C>,
        circuit: NonZeroU32,
        version: RelayVersion,
    ) -> Result<Cached<Relay, C>, errors::CellLengthOverflowError>
    where
        Self: Cachable;

    /// Same as [`try_into_relay_early`], but with [`Cached`].
    fn try_into_relay_early_cached<C: CellCache>(
        this: Cached<Self, C>,
        circuit: NonZeroU32,
        version: RelayVersion,
    ) -> Result<Cached<RelayEarly, C>, errors::CellLengthOverflowError>
    where
        Self: Cachable,
    {
        Ok(Cached::map_into(Self::try_into_relay_cached(
            this, circuit, version,
        )?))
    }
}

fn set_cmd_stream(
    orig_version: Option<RelayVersion>,
    version: RelayVersion,
    cmd: u8,
    stream: u16,
    data: &mut RelayWrapper,
) -> Result<(), errors::CellLengthOverflowError> {
    match version {
        RelayVersion::V0 => {
            match orig_version {
                None => v0::to_v0(data)?,
                Some(RelayVersion::V0) => (),
                Some(RelayVersion::V1) => v1::v1_to_v0(data)?,
            }
            set_cmd_stream_v0(cmd, stream, data)
        }
        RelayVersion::V1 => {
            match orig_version {
                None => v1::to_v1(data)?,
                Some(RelayVersion::V0) => v1::v0_to_v1(data)?,
                Some(RelayVersion::V1) => (),
            }
            set_cmd_stream_v1(cmd, stream, data)
        }
    }
    Ok(())
}

fn set_cmd_stream_v0(cmd: u8, stream: u16, data: &mut RelayWrapper) {
    use v0::RelayExt as _;
    data.set_command(cmd);
    data.set_stream(stream);
    data.fill_padding();
}

fn set_cmd_stream_v1(cmd: u8, stream: u16, data: &mut RelayWrapper) {
    use v1::RelayExt as _;
    data.set_command(cmd);
    data.set_stream(stream);
    data.fill_padding();
}

/// Version 0.0.1
///
/// Not actually a valid version, it only store length and data.
#[derive(FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned, Debug, PartialEq, Eq)]
#[repr(C)]
struct RelayV001 {
    data: [u8; const { FIXED_CELL_SIZE - 2 }],
    len: U16,
}

impl RelayV001 {
    fn from_ref(v: &RelayWrapper) -> &Self {
        transmute_ref!(AsRef::<[u8; FIXED_CELL_SIZE]>::as_ref(v))
    }

    fn from_mut(v: &mut RelayWrapper) -> &mut Self {
        transmute_mut!(AsMut::<[u8; FIXED_CELL_SIZE]>::as_mut(v))
    }

    fn data(&self) -> &[u8] {
        &self.data[..self.len.get() as usize]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use proptest::prelude::*;

    pub(crate) fn strat_relay_version() -> impl Strategy<Value = RelayVersion> {
        prop_oneof![Just(RelayVersion::V0), Just(RelayVersion::V1),]
    }
}
