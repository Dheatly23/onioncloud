use std::io::{Read, Result as IoResult};
use std::mem::{replace, size_of};

use zerocopy::byteorder::big_endian::U16;
use zerocopy::{transmute_mut, transmute_ref};

use super::{
    Cell, CellHeader, CellHeaderBig, CellHeaderSmall, FIXED_CELL_SIZE, FixedCell, VariableCell,
};
use crate::cache::{Cachable, CellCache};
use crate::util::sans_io::Handle;
use crate::util::wrap_eof;

/// Reader for [`FixedCell`].
pub struct FixedCellReader {
    header: CellHeader,
    data: Option<FixedCell>,
    index: usize,
}

impl Cachable for FixedCellReader {
    fn cache<C: CellCache + ?Sized>(self, cache: &C) {
        self.data.cache(cache);
    }
}

impl FixedCellReader {
    /// Create a new [`FixedCellReader`].
    ///
    /// # Parameters
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
            self.index += wrap_eof(reader.read(&mut data.data_mut()[self.index..]))?;
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

enum VariableCellReaderInner {
    Initial {
        header: CellHeader,
        len: U16,
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
            len: U16::new(0),
            index: 0,
        }
    }

    /// Handle reading from reader.
    pub(crate) fn handle(&mut self, reader: &mut dyn Read) -> IoResult<Cell> {
        loop {
            match self {
                Self::Initial { header, len, index } => {
                    let buf: &mut [u8; 2] = transmute_mut!(len);
                    while usize::from(*index) < buf.len() {
                        let n = wrap_eof(reader.read(&mut buf[usize::from(*index)..]))?;
                        debug_assert!(n <= buf.len());
                        *index += n as u8;
                    }
                    debug_assert_eq!(usize::from(*index), buf.len());

                    let len = usize::from(len.get());
                    let header = header.dup();
                    *self = Self::Data {
                        header,
                        data: VariableCell::from(vec![0; len]),
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
                        *index += wrap_eof(reader.read(&mut buf[*index..]))?;
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

/// Reader for [`CellHeader`].
pub struct CellHeaderReader {
    buf: [u8; const { size_of::<CellHeaderBig>() }],
    flags: u8,
}

impl CellHeaderReader {
    /// Create new [`CellHeaderReader`].
    ///
    /// # Parameters
    /// - `circuit_4bytes` : [`true`] if circuit ID is 4 bytes long. (See [`dispatch::WithCellConfig::is_circ_id_4bytes`]).
    pub fn new(circuit_4bytes: bool) -> Self {
        Self {
            buf: [0; const { size_of::<CellHeaderBig>() }],
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
            const SIZE: usize = size_of::<CellHeaderBig>();
            while self.flags != (1 << 7) | (SIZE as u8) {
                let n = wrap_eof(reader.read(&mut self.buf[(self.flags & !(1 << 7)) as usize..]))?;
                debug_assert!(n <= SIZE, "{n} > {SIZE}");
                self.flags += n as u8;
                debug_assert!(self.flags & !(1 << 7) <= SIZE as u8);
            }

            self.flags = 1 << 7;
            let header: &CellHeaderBig = transmute_ref!(&self.buf);
            header.into()
        } else {
            const SIZE: usize = size_of::<CellHeaderSmall>();

            while self.flags != SIZE as u8 {
                let n = wrap_eof(reader.read(&mut self.buf[self.flags as usize..SIZE]))?;
                debug_assert!(n <= SIZE, "{n} > {SIZE}");
                self.flags += n as u8;
                debug_assert!(self.flags <= SIZE as u8);
            }

            self.flags = 0;
            let header: &CellHeaderSmall =
                transmute_ref!(<&[u8; SIZE]>::try_from(&self.buf[..SIZE]).unwrap());
            header.into()
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use proptest::prelude::*;

    use crate::util::{circ_id_strat, steps, test_read_helper, var_cell_strat};

    proptest! {
        #[test]
        fn test_header_read(
            steps in steps(),
            (is_4bytes, circuit) in circ_id_strat(),
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
            (is_4bytes, circuit) in circ_id_strat(),
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
            (is_4bytes, circuit) in circ_id_strat(),
            command: u8,
            data in var_cell_strat(),
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
