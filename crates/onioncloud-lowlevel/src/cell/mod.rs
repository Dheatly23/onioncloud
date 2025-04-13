pub mod auth;
pub mod certs;
pub mod dispatch;
pub mod netinfo;
pub mod padding;
pub mod versions;

use std::fmt::{Debug, Formatter, Result as FmtResult};
use std::io::{ErrorKind, Read, Result as IoResult};
use std::mem::replace;
use std::pin::Pin;

use futures_io::AsyncRead;

use crate::util::sans_io::Handle;
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
        util::async_reader(reader, FixedCellReader::new(header, cached)).await
    }

    /// Reads variable-sized cell from a [`AsyncRead`] stream.
    ///
    /// # Parameters
    /// - `header` : Cell header.
    pub async fn read_variable<R: AsyncRead>(
        reader: Pin<&mut R>,
        header: CellHeader,
    ) -> IoResult<Self> {
        util::async_reader(reader, VariableCellReader::new(header)).await
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
    /// This method **should** not mutate the cell, it's only allowed to inspect it.
    /// If the checks are good, then use the [`Option::take`] method to pop cell out of it.
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

/// Reader for [`FixedCell`].
pub struct FixedCellReader {
    header: CellHeader,
    data: Option<FixedCell>,
    index: usize,
}

impl FixedCellReader {
    /// Create a new [`FixedCellReader`].
    ///
    /// # Parameter
    /// - `header` : Cell header.
    /// - `cached` : Cached cell data. It's content will be overwritten.
    pub fn new(header: CellHeader, cached: FixedCell) -> Self {
        Self {
            header,
            data: Some(cached),
            index: 0,
        }
    }
}

/// Handle reading from a stream reader.
///
/// Reader **should not** be polled after successfully reading, otherwise it will panic.
impl Handle<&mut dyn Read> for FixedCellReader {
    type Return = IoResult<Cell>;

    fn handle(&mut self, reader: &mut dyn Read) -> Self::Return {
        let data = self
            .data
            .as_mut()
            .expect("reader got polled after producing result");
        while self.index < FIXED_CELL_SIZE {
            let n = reader.read(&mut data.data_mut()[self.index..])?;
            if n == 0 {
                return Err(ErrorKind::UnexpectedEof.into());
            }
            self.index += n;
        }

        Ok(Cell::from_fixed(
            self.header.dup(),
            self.data
                .take()
                .expect("reader got polled after producing result"),
        ))
    }
}

/// Reader for [`VariableCell`].
#[repr(transparent)]
pub struct VariableCellReader(VariableCellReaderInner);

impl VariableCellReader {
    /// Create new [`VariableCellReader`].
    pub fn new(header: CellHeader) -> Self {
        Self(VariableCellReaderInner::new(header))
    }
}

/// Handle reading from a stream reader.
///
/// Reader **should not** be polled after successfully reading, otherwise it will panic.
impl Handle<&mut dyn Read> for VariableCellReader {
    type Return = IoResult<Cell>;

    fn handle(&mut self, reader: &mut dyn Read) -> Self::Return {
        self.0.handle(reader)
    }
}

pub(crate) enum VariableCellReaderInner {
    Initial {
        header: CellHeader,
        buf: [u8; 2],
        index: u8,
    },
    Data {
        header: CellHeader,
        data: VariableCell,
        index: usize,
    },
    End,
}

impl VariableCellReaderInner {
    pub(crate) fn new(header: CellHeader) -> Self {
        Self::Initial {
            header,
            buf: [0; 2],
            index: 0,
        }
    }

    /// Handle reading from reader.
    pub(crate) fn handle(&mut self, reader: &mut dyn Read) -> IoResult<Cell> {
        loop {
            match self {
                Self::Initial { header, buf, index } => {
                    while usize::from(*index) < buf.len() {
                        let n = reader.read(&mut buf[usize::from(*index)..])?;
                        if n == 0 {
                            return Err(ErrorKind::UnexpectedEof.into());
                        }
                        debug_assert!(n <= buf.len());
                        *index += n as u8;
                    }
                    debug_assert_eq!(usize::from(*index), buf.len());

                    let n = u16::from_be_bytes(*buf) as usize;
                    let header = header.dup();
                    *self = Self::Data {
                        header,
                        data: VariableCell::from(vec![0; n]),
                        index: 0,
                    };
                }
                Self::Data {
                    header,
                    data,
                    index,
                } => {
                    let buf = data.data_mut();
                    while *index != buf.len() {
                        let n = reader.read(&mut buf[*index..])?;
                        if n == 0 {
                            return Err(ErrorKind::UnexpectedEof.into());
                        }
                        *index += n;
                    }

                    let header = header.dup();
                    let data = replace(data, VariableCell::empty());
                    *self = Self::End;
                    return Ok(Cell::from_variable(header, data));
                }
                Self::End => panic!("reader got polled after producing result"),
            }
        }
    }
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

/// Reader for [`CellHeader`].
pub struct CellHeaderReader {
    buf: [u8; 5],
    flags: u8,
}

impl CellHeaderReader {
    /// Create new [`CellHeaderReader`].
    ///
    /// # Parameter
    /// - `circuit_4bytes` : [`true`] if circuit ID is 4 bytes long. (See [`dispatch::WithCellConfig::is_circ_id_4bytes`]).
    pub fn new(circuit_4bytes: bool) -> Self {
        Self {
            buf: [0; 5],
            flags: if circuit_4bytes { 1 << 7 } else { 0 },
        }
    }
}

/// Handle reading from a stream reader.
///
/// Reader **should not** be polled after successfully reading, otherwise it will panic.
impl Handle<&mut dyn Read> for CellHeaderReader {
    type Return = IoResult<CellHeader>;

    fn handle(&mut self, reader: &mut dyn Read) -> Self::Return {
        Ok(if self.flags & (1 << 7) != 0 {
            while self.flags != (1 << 7) | 5 {
                let n = reader.read(&mut self.buf[(self.flags & !(1 << 7)) as usize..])?;
                if n == 0 {
                    return Err(ErrorKind::UnexpectedEof.into());
                }
                debug_assert!(n <= 5, "{n} > 5");
                self.flags += n as u8;
                debug_assert!(self.flags & !(1 << 7) <= 5);
            }

            self.flags = 1 << 7;
            let [a, b, c, d, e] = self.buf;
            CellHeader {
                circuit: u32::from_be_bytes([a, b, c, d]),
                command: e,
            }
        } else {
            while self.flags != 3 {
                let n = reader.read(&mut self.buf[self.flags as usize..3])?;
                if n == 0 {
                    return Err(ErrorKind::UnexpectedEof.into());
                }
                debug_assert!(n <= 3, "{n} > 3");
                self.flags += n as u8;
                debug_assert!(self.flags <= 3);
            }

            self.flags = 0;
            let [a, b, c, ..] = self.buf;
            CellHeader {
                circuit: u16::from_be_bytes([a, b]).into(),
                command: c,
            }
        })
    }
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
        util::async_reader(reader, CellHeaderReader::new(circuit_4bytes)).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use proptest::collection::vec;
    use proptest::prelude::*;

    use crate::util::test_read_helper;

    fn steps() -> impl Strategy<Value = Vec<usize>> {
        vec(0..=256usize, 0..32)
    }

    proptest! {
        #[test]
        fn test_header_read(
            steps in steps(),
            (is_4bytes, circuit) in any::<bool>().prop_flat_map(|v| (Just(v), 0..=if v {
                u32::MAX
            } else {
                u16::MAX.into()
            })),
            command: u8,
        ) {
            let mut buf = [0; 5];
            let buf = if is_4bytes {
                *<&mut [u8; 4]>::try_from(&mut buf[..4]).unwrap() = circuit.to_be_bytes();
                buf[4] = command;
                &buf[..]
            } else {
                *<&mut [u8; 2]>::try_from(&mut buf[..2]).unwrap() = (circuit as u16).to_be_bytes();
                buf[2] = command;
                &buf[..3]
            };

            let res = test_read_helper(
                buf,
                steps,
                CellHeaderReader::new(is_4bytes),
            );

            assert_eq!(res.circuit, circuit);
            assert_eq!(res.command, command);
        }

        #[test]
        fn test_circuit_read_fixed(
            steps in steps(),
            (is_4bytes, circuit) in any::<bool>().prop_flat_map(|v| (Just(v), 0..=if v {
                u32::MAX
            } else {
                u16::MAX.into()
            })),
            command: u8,
            data: [u8; FIXED_CELL_SIZE],
        ) {
            let mut buf = [0; FIXED_CELL_SIZE + 5];
            let buf = if is_4bytes {
                *<&mut [u8; 4]>::try_from(&mut buf[..4]).unwrap() = circuit.to_be_bytes();
                buf[4] = command;
                *<&mut [u8; FIXED_CELL_SIZE]>::try_from(&mut buf[5..]).unwrap() = data;
                &buf[..]
            } else {
                *<&mut [u8; 2]>::try_from(&mut buf[..2]).unwrap() = (circuit as u16).to_be_bytes();
                buf[2] = command;
                *<&mut [u8; FIXED_CELL_SIZE]>::try_from(&mut buf[3..3 + FIXED_CELL_SIZE]).unwrap() = data;
                &buf[..3 + FIXED_CELL_SIZE]
            };

            enum Reader {
                Init(CellHeaderReader),
                Header(FixedCellReader),
            }

            impl Handle<&mut dyn Read> for Reader {
                type Return = IoResult<Cell>;

                fn handle(&mut self, s: &mut dyn Read) -> Self::Return {
                    loop {
                        *self = match self {
                            Self::Init(r) => Self::Header(FixedCellReader::new(r.handle(s)?, FixedCell::default())),
                            Self::Header(r) => return r.handle(s),
                        };
                    }
                }
            }

            let cell = test_read_helper(
                buf,
                steps,
                Reader::Init(CellHeaderReader::new(is_4bytes)),
            );

            assert_eq!(cell.circuit, circuit);
            assert_eq!(cell.command, command);
            assert_eq!(cell.data(), data);
        }

        #[test]
        fn test_circuit_read_variable(
            steps in steps(),
            (is_4bytes, circuit) in any::<bool>().prop_flat_map(|v| (Just(v), 0..=if v {
                u32::MAX
            } else {
                u16::MAX.into()
            })),
            command: u8,
            data in vec(any::<u8>(), 0..=u16::MAX as usize),
        ) {
            let mut buf;
            let t = if is_4bytes {
                buf = vec![0; 7 + data.len()];
                *<&mut [u8; 4]>::try_from(&mut buf[..4]).unwrap() = circuit.to_be_bytes();
                buf[4] = command;
                &mut buf[5..]
            } else {
                buf = vec![0; 5 + data.len()];
                *<&mut [u8; 2]>::try_from(&mut buf[..2]).unwrap() = (circuit as u16).to_be_bytes();
                buf[2] = command;
                *<&mut [u8; 2]>::try_from(&mut buf[3..5]).unwrap() = (data.len() as u16).to_be_bytes();
                &mut buf[3..]
            };
            *<&mut [u8; 2]>::try_from(&mut t[..2]).unwrap() = (data.len() as u16).to_be_bytes();
            t[2..].copy_from_slice(&data);

            enum Reader {
                Init(CellHeaderReader),
                Header(VariableCellReader),
            }

            impl Handle<&mut dyn Read> for Reader {
                type Return = IoResult<Cell>;

                fn handle(&mut self, s: &mut dyn Read) -> Self::Return {
                    loop {
                        *self = match self {
                            Self::Init(r) => Self::Header(VariableCellReader::new(r.handle(s)?)),
                            Self::Header(r) => return r.handle(s),
                        };
                    }
                }
            }

            let cell = test_read_helper(
                &buf,
                steps,
                Reader::Init(CellHeaderReader::new(is_4bytes)),
            );

            assert_eq!(cell.circuit, circuit);
            assert_eq!(cell.command, command);
            assert_eq!(cell.data(), data);
        }
    }
}
