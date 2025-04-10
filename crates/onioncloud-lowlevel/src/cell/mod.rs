use std::io::{ErrorKind, Read, Result as IoResult};
use std::mem::replace;
use std::pin::Pin;

use futures_io::AsyncRead;

use crate::errors;
use crate::util;

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
        Self::new(Box::from(data))
    }
}

impl From<Vec<u8>> for VariableCell {
    fn from(v: Vec<u8>) -> Self {
        Self::new(v.into_boxed_slice())
    }
}

impl VariableCell {
    /// Creates new `VariableCell`.
    pub const fn new(inner: Box<[u8]>) -> Self {
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

pub struct Cell {
    pub circuit: u32,
    pub command: u8,
    data: CellData,
}

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

    pub async fn read_fixed<R: AsyncRead>(
        reader: Pin<&mut R>,
        header: CellHeader,
        cached: FixedCell,
    ) -> IoResult<Self> {
        let mut r = FixedCellReader::new(header, cached);
        util::async_reader(reader, move |s| r.handle_read(s)).await
    }

    pub async fn read_variable<R: AsyncRead>(
        reader: Pin<&mut R>,
        header: CellHeader,
    ) -> IoResult<Self> {
        let mut r = VariableCellReader::new(header);
        util::async_reader(reader, move |s| r.handle_read(s)).await
    }
}

pub(crate) struct FixedCellReader {
    header: CellHeader,
    data: Option<FixedCell>,
    index: usize,
}

impl FixedCellReader {
    pub(crate) fn new(header: CellHeader, data: FixedCell) -> Self {
        Self {
            header,
            data: Some(data),
            index: 0,
        }
    }

    /// Handle reading from reader.
    pub(crate) fn handle_read<R: Read>(&mut self, reader: &mut R) -> IoResult<Cell> {
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

pub(crate) enum VariableCellReader {
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

impl VariableCellReader {
    pub(crate) fn new(header: CellHeader) -> Self {
        Self::Initial {
            header,
            buf: [0; 2],
            index: 0,
        }
    }

    /// Handle reading from reader.
    pub(crate) fn handle_read<R: Read>(&mut self, reader: &mut R) -> IoResult<Cell> {
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

#[derive(Default)]
#[non_exhaustive]
pub struct CellHeader {
    pub circuit: u32,
    pub command: u8,
}

pub(crate) struct CellHeaderReader {
    buf: [u8; 5],
    flags: u8,
}

impl CellHeaderReader {
    /// Handle reading from reader.
    pub(crate) fn handle_read<R: Read>(&mut self, reader: &mut R) -> IoResult<CellHeader> {
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
    pub(crate) fn dup(&self) -> Self {
        Self { ..*self }
    }

    /// Handle reading header from buffer.
    ///
    /// If returns [`None`], then buffer needs to read more data.
    pub async fn read<R: AsyncRead>(reader: Pin<&mut R>, circuit_4bytes: bool) -> IoResult<Self> {
        let mut r = CellHeaderReader {
            buf: [0; 5],
            flags: if circuit_4bytes { 1 << 7 } else { 0 },
        };

        util::async_reader(reader, move |s| r.handle_read(s)).await
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

            let res = {
                let mut r = CellHeaderReader {
                    buf: [0; 5],
                    flags: if is_4bytes { 1 << 7 } else {
                        assert!(circuit <= u16::MAX.into());
                        0
                    },
                };
                test_read_helper(buf, steps, |s| r.handle_read(s))
            };

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

            let mut r = Reader::Init(CellHeaderReader {
                buf: [0; 5],
                flags: if is_4bytes { 1 << 7 } else {
                    assert!(circuit <= u16::MAX.into());
                    0
                },
            });
            let cell = test_read_helper(buf, steps, |s| loop {
                r = match &mut r {
                    Reader::Init(r) => Reader::Header(FixedCellReader::new(r.handle_read(s)?, FixedCell::default())),
                    Reader::Header(r) => return Ok(r.handle_read(s)?),
                };
            });

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
            data in vec(any::<u8>(), 0..u16::MAX as usize),
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

            let mut r = Reader::Init(CellHeaderReader {
                buf: [0; 5],
                flags: if is_4bytes { 1 << 7 } else {
                    assert!(circuit <= u16::MAX.into());
                    0
                },
            });
            let cell = test_read_helper(&buf, steps, |s| loop {
                r = match &mut r {
                    Reader::Init(r) => Reader::Header(VariableCellReader::new(r.handle_read(s)?)),
                    Reader::Header(r) => return Ok(r.handle_read(s)?),
                };
            });

            assert_eq!(cell.circuit, circuit);
            assert_eq!(cell.command, command);
            assert_eq!(cell.data(), data);
        }
    }
}
