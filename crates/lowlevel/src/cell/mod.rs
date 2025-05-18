pub mod auth;
pub mod certs;
pub mod create;
pub mod destroy;
pub mod dispatch;
pub mod netinfo;
pub mod padding;
pub mod reader;
pub mod versions;
pub mod writer;

use std::fmt::{Debug, Formatter, Result as FmtResult};
use std::io::Result as IoResult;
use std::ops::Deref;
use std::pin::Pin;

use futures_io::AsyncRead;
use zerocopy::byteorder::big_endian::{U16, U32};
use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout, Unaligned};

use crate::{errors, util};

/// Size of [`FixedCell`] content.
pub const FIXED_CELL_SIZE: usize = 509;

/// A fixed-sized cell.
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct FixedCell {
    inner: Box<[u8; FIXED_CELL_SIZE]>,
}

impl Default for FixedCell {
    fn default() -> Self {
        Self {
            inner: Box::new([0; FIXED_CELL_SIZE]),
        }
    }
}

impl AsRef<[u8; FIXED_CELL_SIZE]> for FixedCell {
    fn as_ref(&self) -> &[u8; FIXED_CELL_SIZE] {
        self.data()
    }
}

impl AsMut<[u8; FIXED_CELL_SIZE]> for FixedCell {
    fn as_mut(&mut self) -> &mut [u8; FIXED_CELL_SIZE] {
        self.data_mut()
    }
}

impl From<[u8; FIXED_CELL_SIZE]> for FixedCell {
    fn from(arr: [u8; FIXED_CELL_SIZE]) -> Self {
        Self::new(Box::new(arr))
    }
}

impl<'a> TryFrom<&'a [u8]> for FixedCell {
    type Error = errors::InvalidLength;

    fn try_from(data: &'a [u8]) -> Result<Self, Self::Error> {
        data.get(..FIXED_CELL_SIZE)
            .and_then(|v| <&[u8; FIXED_CELL_SIZE]>::try_from(v).ok())
            .map(|v| Self::new(Box::new(*v)))
            .ok_or(errors::InvalidLength)
    }
}

impl Debug for FixedCell {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        // Filters out cell content
        f.debug_struct("FixedCell").finish_non_exhaustive()
    }
}

impl FixedCell {
    /// Creates new `FixedCell`.
    pub const fn new(inner: Box<[u8; FIXED_CELL_SIZE]>) -> Self {
        Self { inner }
    }

    /// Gets reference into cell data.
    pub fn data(&self) -> &[u8; FIXED_CELL_SIZE] {
        &self.inner
    }

    /// Gets mutable reference into cell data.
    pub fn data_mut(&mut self) -> &mut [u8; FIXED_CELL_SIZE] {
        &mut self.inner
    }

    /// Unwraps inner data.
    pub fn into_inner(self) -> Box<[u8; FIXED_CELL_SIZE]> {
        self.inner
    }
}

/// A variable-sized cell.
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct VariableCell {
    inner: Box<[u8]>,
}

impl AsRef<[u8]> for VariableCell {
    fn as_ref(&self) -> &[u8] {
        self.data()
    }
}

impl AsMut<[u8]> for VariableCell {
    fn as_mut(&mut self) -> &mut [u8] {
        self.data_mut()
    }
}

impl<'a> From<&'a [u8]> for VariableCell {
    fn from(data: &'a [u8]) -> Self {
        assert!(data.len() < 65536, "variable cell length is too long!");
        Self::new(Box::from(data))
    }
}

impl From<Vec<u8>> for VariableCell {
    fn from(v: Vec<u8>) -> Self {
        assert!(v.len() < 65536, "variable cell length is too long!");
        Self::new(v.into_boxed_slice())
    }
}

impl Debug for VariableCell {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        // Filters out cell content
        f.debug_struct("VariableCell").finish_non_exhaustive()
    }
}

impl VariableCell {
    /// Creates new `VariableCell`.
    pub const fn new(inner: Box<[u8]>) -> Self {
        assert!(inner.len() < 65536, "variable cell length is too long!");
        Self { inner }
    }

    /// Creates an empty cell.
    pub fn empty() -> Self {
        Self::new(Box::new([]))
    }

    /// Gets reference into cell data.
    pub fn data(&self) -> &[u8] {
        &self.inner
    }

    /// Gets mutable reference into cell data.
    pub fn data_mut(&mut self) -> &mut [u8] {
        &mut self.inner
    }

    /// Unwraps inner data.
    pub fn into_inner(self) -> Box<[u8]> {
        self.inner
    }

    /// Returns [`true`] if cell is empty.
    pub fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }

    /// Returns cell data length.
    pub fn len(&self) -> usize {
        self.inner.len()
    }

    /// Try to cast into [`FixedCell`].
    ///
    /// If cast fails, returns itself.
    pub fn try_into_fixed(self) -> Result<FixedCell, Self> {
        // Do the same thing as nightly Box::into_array
        if self.inner.len() == FIXED_CELL_SIZE {
            let ptr = Box::into_raw(self.inner).cast::<[u8; FIXED_CELL_SIZE]>();
            // SAFETY: Slice length is equal to array length.
            unsafe { Ok(FixedCell::new(Box::from_raw(ptr))) }
        } else {
            Err(self)
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Cell {
    pub circuit: u32,
    pub command: u8,
    data: CellData,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
enum CellData {
    Fixed(FixedCell),
    Variable(VariableCell),
}

impl Default for Cell {
    fn default() -> Self {
        Self::empty_fixed()
    }
}

impl AsRef<[u8]> for Cell {
    fn as_ref(&self) -> &[u8] {
        self.data()
    }
}

impl AsMut<[u8]> for Cell {
    fn as_mut(&mut self) -> &mut [u8] {
        self.data_mut()
    }
}

impl crate::cache::Cachable for Cell {
    fn maybe_into_fixed(self) -> Option<FixedCell> {
        self.into_fixed().ok()
    }
}

impl crate::cache::Cachable for Option<Cell> {
    fn maybe_into_fixed(self) -> Option<FixedCell> {
        self?.maybe_into_fixed()
    }
}

impl Cell {
    /// Creates empty fixed-sized cell.
    pub fn empty_fixed() -> Self {
        Self::from_fixed(CellHeader::default(), FixedCell::default())
    }

    /// Creates fixed-sized cell.
    pub const fn from_fixed(header: CellHeader, data: FixedCell) -> Self {
        Self {
            circuit: header.circuit,
            command: header.command,
            data: CellData::Fixed(data),
        }
    }

    /// Creates variable-sized cell.
    pub const fn from_variable(header: CellHeader, data: VariableCell) -> Self {
        Self {
            circuit: header.circuit,
            command: header.command,
            data: CellData::Variable(data),
        }
    }

    /// Gets reference into cell data.
    pub fn data(&self) -> &[u8] {
        match &self.data {
            CellData::Fixed(v) => &v.data()[..],
            CellData::Variable(v) => v.data(),
        }
    }

    /// Gets mutable reference into cell data.
    pub fn data_mut(&mut self) -> &mut [u8] {
        match &mut self.data {
            CellData::Fixed(v) => &mut v.data_mut()[..],
            CellData::Variable(v) => v.data_mut(),
        }
    }

    /// Returns [`true`] if cell is fixed-sized.
    pub fn is_fixed(&self) -> bool {
        matches!(self.data, CellData::Fixed(_))
    }

    /// Returns [`true`] if cell is variable-sized.
    pub fn is_variable(&self) -> bool {
        matches!(self.data, CellData::Variable(_))
    }

    /// Try to get [`FixedCell`] reference.
    pub fn as_fixed(&self) -> Option<&FixedCell> {
        match &self.data {
            CellData::Fixed(v) => Some(v),
            _ => None,
        }
    }

    /// Try to get [`FixedCell`] mutable reference.
    pub fn as_fixed_mut(&mut self) -> Option<&mut FixedCell> {
        match &mut self.data {
            CellData::Fixed(v) => Some(v),
            _ => None,
        }
    }

    /// Try to get [`VariableCell`] reference.
    pub fn as_variable(&self) -> Option<&VariableCell> {
        match &self.data {
            CellData::Variable(v) => Some(v),
            _ => None,
        }
    }

    /// Try to get [`VariableCell`] mutable reference.
    pub fn as_variable_mut(&mut self) -> Option<&mut VariableCell> {
        match &mut self.data {
            CellData::Variable(v) => Some(v),
            _ => None,
        }
    }

    /// Try to unwrap into [`FixedCell`].
    pub fn into_fixed(self) -> Result<FixedCell, Self> {
        match self.data {
            CellData::Fixed(v) => Ok(v),
            _ => Err(self),
        }
    }

    /// Try to unwrap into [`VariableCell`].
    pub fn into_variable(self) -> Result<VariableCell, Self> {
        match self.data {
            CellData::Variable(v) => Ok(v),
            _ => Err(self),
        }
    }

    /// Reads fixed-sized cell from a [`AsyncRead`] stream.
    ///
    /// # Parameters
    /// - `header` : Cell header.
    /// - `cached` : [`FixedCell`] to use. Use [`FixedCell::default`] to create a new one or reuse cached one.
    pub async fn read_fixed<R: AsyncRead>(
        reader: Pin<&mut R>,
        header: CellHeader,
        cached: FixedCell,
    ) -> IoResult<Self> {
        util::async_reader(reader, reader::FixedCellReader::new(header, cached)).await
    }

    /// Reads variable-sized cell from a [`AsyncRead`] stream.
    ///
    /// # Parameters
    /// - `header` : Cell header.
    pub async fn read_variable<R: AsyncRead>(
        reader: Pin<&mut R>,
        header: CellHeader,
    ) -> IoResult<Self> {
        util::async_reader(reader, reader::VariableCellReader::new(header)).await
    }

    fn into_fixed_with(
        self,
        f: impl FnOnce(&[u8; FIXED_CELL_SIZE]) -> bool,
    ) -> Result<FixedCell, Self> {
        match self.data {
            CellData::Fixed(v) if f(v.data()) => Ok(v),
            _ => Err(self),
        }
    }

    fn into_variable_with(self, f: impl FnOnce(&[u8]) -> bool) -> Result<VariableCell, Self> {
        match self.data {
            CellData::Variable(v) if f(v.data()) => Ok(v),
            _ => Err(self),
        }
    }
}

/// Trait to cast from a cell.
pub trait TryFromCell: Sized {
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
    fn try_from_cell(cell: &mut Option<Cell>) -> Result<Option<Self>, errors::CellFormatError>;
}

/// Convenient function wrapping [`TryFromCell`].
///
/// ```
/// use onioncloud_lowlevel::cell::{cast, Cell, CellHeader, FixedCell};
/// use onioncloud_lowlevel::cell::padding::{Padding, VPadding};
///
/// // A cell
/// let cell = Cell::from_fixed(CellHeader::new(0, 0), FixedCell::default());
///
/// // Dispatch cell
/// let mut cell = Some(cell);
/// if let Some(cell) = cast::<Padding>(&mut cell).unwrap() {
///     // Handle padding cell
/// } else if let Some(cell) = cast::<VPadding>(&mut cell).unwrap() {
///     // Handle variable padding cell
/// } else if let Some(cell) = cell {
///     panic!("unknown cell ID {}!", cell.command);
/// }
/// ```
pub fn cast<T: TryFromCell>(cell: &mut Option<Cell>) -> Result<Option<T>, errors::CellFormatError> {
    T::try_from_cell(cell)
}

/// Reference to cell content.
///
/// Used for [`CellLike::cell`].
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum CellRef<'a> {
    Fixed(&'a FixedCell),
    Variable(&'a VariableCell),
}

/// Trait for everything that behaves like a cell.
///
/// It is important that the return values **must not** change between invocation.
/// Basically, don't use interior mutability, as it can cause problems downstream on writing.
pub trait CellLike {
    /// Get circuit ID.
    fn circuit(&self) -> u32;

    /// Get cell command.
    fn command(&self) -> u8;

    /// Get cell content.
    fn cell(&self) -> CellRef<'_>;
}

impl<T> CellLike for T
where
    T: Deref + ?Sized,
    T::Target: CellLike,
{
    fn circuit(&self) -> u32 {
        <T as Deref>::Target::circuit(self)
    }

    fn command(&self) -> u8 {
        <T as Deref>::Target::command(self)
    }

    fn cell(&self) -> CellRef<'_> {
        <T as Deref>::Target::cell(self)
    }
}

impl CellLike for Cell {
    fn circuit(&self) -> u32 {
        self.circuit
    }

    fn command(&self) -> u8 {
        self.command
    }

    fn cell(&self) -> CellRef<'_> {
        match &self.data {
            CellData::Fixed(v) => CellRef::Fixed(v),
            CellData::Variable(v) => CellRef::Variable(v),
        }
    }
}

/// Helper to take a [`FixedCell`].
pub(crate) fn to_fixed(
    cell: &mut Option<Cell>,
) -> Result<Option<FixedCell>, errors::CellFormatError> {
    cell.take()
        .map(|v| v.into_fixed())
        .transpose()
        .map_err(|v| {
            *cell = Some(v);
            errors::CellFormatError
        })
}

/// Helper to take a [`VariableCell`].
pub(crate) fn to_variable(
    cell: &mut Option<Cell>,
) -> Result<Option<VariableCell>, errors::CellFormatError> {
    cell.take()
        .map(|v| v.into_variable())
        .transpose()
        .map_err(|v| {
            *cell = Some(v);
            errors::CellFormatError
        })
}

/// Helper to take a [`FixedCell`] with check function.
pub(crate) fn to_fixed_with(
    cell: &mut Option<Cell>,
    check: impl FnOnce(&[u8; FIXED_CELL_SIZE]) -> bool,
) -> Result<Option<FixedCell>, errors::CellFormatError> {
    cell.take()
        .map(|v| v.into_fixed_with(check))
        .transpose()
        .map_err(|v| {
            *cell = Some(v);
            errors::CellFormatError
        })
}

/// Helper to take a [`VariableCell`] with check function.
pub(crate) fn to_variable_with(
    cell: &mut Option<Cell>,
    check: impl FnOnce(&[u8]) -> bool,
) -> Result<Option<VariableCell>, errors::CellFormatError> {
    cell.take()
        .map(|v| v.into_variable_with(check))
        .transpose()
        .map_err(|v| {
            *cell = Some(v);
            errors::CellFormatError
        })
}

/// Cell header.
///
/// The typical way to create it is by reading from stream (see [`CellHeader::read`]).
/// It is then passed to functions like [`Cell::read_fixed`] and [`Cell::read_variable`],
/// depending on the header command.
#[derive(Default, Debug)]
#[non_exhaustive]
pub struct CellHeader {
    pub circuit: u32,
    pub command: u8,
}

impl CellHeader {
    /// Creates new header.
    ///
    /// Useful for manually creating [`Cell`] (see [`Cell::from_fixed`] and [`Cell::from_variable`]).
    pub fn new(circuit: u32, command: u8) -> Self {
        Self { circuit, command }
    }

    pub(crate) fn dup(&self) -> Self {
        Self { ..*self }
    }

    /// Reads cell header from a [`AsyncRead`] stream.
    ///
    /// # Parameters
    /// - `circuit_4bytes` : `true` if circuit ID length is 4 bytes.
    pub async fn read<R: AsyncRead>(reader: Pin<&mut R>, circuit_4bytes: bool) -> IoResult<Self> {
        util::async_reader(reader, reader::CellHeaderReader::new(circuit_4bytes)).await
    }
}

/// Cell header with 4-bytes circuit ID.
#[derive(FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned)]
#[repr(C)]
pub(crate) struct CellHeaderBig {
    pub(crate) circuit: U32,
    pub(crate) command: u8,
}

impl<'a> From<&'a CellHeaderBig> for CellHeader {
    fn from(v: &'a CellHeaderBig) -> Self {
        Self::new(v.circuit.get(), v.command)
    }
}

impl From<CellHeader> for CellHeaderBig {
    fn from(v: CellHeader) -> Self {
        Self {
            circuit: v.circuit.into(),
            command: v.command,
        }
    }
}

/// Cell header with 2-bytes circuit ID.
#[derive(FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned)]
#[repr(C)]
pub(crate) struct CellHeaderSmall {
    pub(crate) circuit: U16,
    pub(crate) command: u8,
}

impl<'a> From<&'a CellHeaderSmall> for CellHeader {
    fn from(v: &'a CellHeaderSmall) -> Self {
        Self::new(v.circuit.get().into(), v.command)
    }
}

impl From<CellHeader> for CellHeaderSmall {
    fn from(v: CellHeader) -> Self {
        debug_assert!(
            v.circuit < u32::from(u16::MAX),
            "circuit ID {} is too large to fit into 2 bytes",
            v.circuit
        );

        Self {
            circuit: (v.circuit as u16).into(),
            command: v.command,
        }
    }
}
