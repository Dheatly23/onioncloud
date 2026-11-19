//! Cell reader.

use std::io::{Error as IoError, ErrorKind, Read};
use std::mem::replace;
use std::ops::Deref;

use zerocopy::{IntoBytes, transmute_mut};

use crate::cell::{Cell, CellHeader};
use crate::error::{CellFinished, CellFormatError, CellReadError, UnknownIoError};
use crate::fixed::FixedCell;
use crate::utils::{HeaderLargeVariable, HeaderSmallVariable, PrefixedFixedCell};
use crate::variable::VariableCell;

/// Configurator trait for [`Reader`].
///
/// # Implementer's Note
///
/// Almost all the methods have sensible (but incorrect) defaults.
/// It's encouraged for implementers to override all methods.
pub trait ReadConfig {
    /// Gets configuration of circuit ID length.
    ///
    /// Returns [`true`] if circuit ID should be 4 bytes.
    /// Legacy Tor protocol uses 2 bytes for circuit ID, but newer version switched to 4 bytes.
    /// Before version negotiation it must be assumed the link used legacy version.
    fn is_circ_id_4bytes(&self) -> bool {
        false
    }

    /// Gets cell type by it's header.
    ///
    /// If the header is valid, returns a [`CellType`].
    /// Otherwise it returns [`None`].
    fn cell_type(&self, header: &CellHeader) -> Option<CellType> {
        let _ = header;
        None
    }

    /// Gets empty [`FixedCell`].
    ///
    /// # Implementer's Note
    ///
    /// The returned cell must be set to all 0. Failure to do so might leak unwanted data.
    ///
    /// It's encouraged for configurator to use caching.
    /// The default implementation simply returns nothing.
    fn get_fixed_cell(&self) -> FixedCell {
        FixedCell::default()
    }

    /// Caches [`FixedCell`].
    ///
    /// # Implementer's Note
    ///
    /// It's encouraged for configurator to cache the given cell.
    /// The default implementation simply drops it.
    fn cache_fixed_cell(&self, cell: FixedCell) {
        drop(cell);
    }

    /// Caches [`VariableCell`].
    ///
    /// # Implementer's Note
    ///
    /// It's encouraged for configurator to cache the given cell.
    /// The default implementation simply drops it.
    fn cache_variable_cell(&self, cell: VariableCell) {
        drop(cell);
    }
}

impl<T> ReadConfig for T
where
    T: Deref,
    T::Target: ReadConfig,
{
    #[inline]
    fn is_circ_id_4bytes(&self) -> bool {
        <T as Deref>::Target::is_circ_id_4bytes(&**self)
    }

    #[inline]
    fn cell_type(&self, header: &CellHeader) -> Option<CellType> {
        <T as Deref>::Target::cell_type(&**self, header)
    }

    #[inline]
    fn get_fixed_cell(&self) -> FixedCell {
        <T as Deref>::Target::get_fixed_cell(&**self)
    }

    #[inline]
    fn cache_fixed_cell(&self, cell: FixedCell) {
        <T as Deref>::Target::cache_fixed_cell(&**self, cell);
    }

    #[inline]
    fn cache_variable_cell(&self, cell: VariableCell) {
        <T as Deref>::Target::cache_variable_cell(&**self, cell);
    }
}

/// Possible cell types.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CellType {
    /// Fixed-width cell.
    Fixed,
    /// Variable-width cell.
    Variable,
}

/// A cell reader.
#[derive(Debug)]
pub struct Reader<C: ReadConfig> {
    /// Reader configurator.
    pub config: C,

    off: usize,
    state: State,
}

#[derive(Debug)]
enum State {
    Init,
    Finished,
    Err,
    IoErr,
    Header { data: HeaderBuf },
    Cell { header: CellHeader, data: CellBuf },
}

#[derive(Debug)]
enum HeaderBuf {
    Small(HeaderSmallVariable),
    Large(HeaderLargeVariable),
}

#[derive(Debug)]
enum CellBuf {
    Fixed(FixedCell),
    Variable(VariableCell),
}

impl<C: ReadConfig> Drop for Reader<C> {
    fn drop(&mut self) {
        match replace(&mut self.state, State::Err) {
            State::Cell {
                data: CellBuf::Fixed(cell),
                ..
            } => self.config.cache_fixed_cell(cell),
            State::Cell {
                data: CellBuf::Variable(cell),
                ..
            } => self.config.cache_variable_cell(cell),
            _ => (),
        }
    }
}

impl<C: ReadConfig> Reader<C> {
    /// Create new [`Reader`].
    #[inline]
    pub const fn new(config: C) -> Self {
        Self {
            config,
            state: State::Init,
            off: 0,
        }
    }

    /// Read using sync [`Read`] trait.
    ///
    /// # Special behaviors
    ///
    /// There are two special behaviors on read:
    /// - Error of kind [`ErrorKind::WouldBlock`] will return an `Ok(None)`.
    ///
    ///   **NOTE:** [`AsyncRead`](`futures_io::AsyncRead`) can use it to wrap [`Poll::Pending`](`std::task::Poll::Pending`) result.
    /// - If it returns EOF (reading 0 bytes), it'll error with `ErrorKind::UnexpectedEof`.
    ///
    /// # Usage note
    ///
    /// **DO NOT** reuse [`Reader`] after it returns an error.
    ///
    /// # Errors
    ///
    /// Returns error if:
    /// - IO error happened.
    /// - Cell format error.
    /// - Socket is closed (EOF).
    pub fn read<R: Read>(&mut self, read: &mut R) -> Result<Option<Cell>, CellReadError> {
        loop {
            let buf = match &mut self.state {
                State::Err => return Err(CellFormatError.into()),
                State::IoErr => return Err(IoError::other(UnknownIoError).into()),
                State::Finished => {
                    return Err(IoError::new(ErrorKind::UnexpectedEof, CellFinished).into());
                }
                State::Init => {
                    self.state = State::Header {
                        data: if self.config.is_circ_id_4bytes() {
                            HeaderBuf::Large(Default::default())
                        } else {
                            HeaderBuf::Small(Default::default())
                        },
                    };
                    self.off = 0;
                    continue;
                }
                State::Header {
                    data: HeaderBuf::Small(v),
                } => v.as_mut_bytes(),
                State::Header {
                    data: HeaderBuf::Large(v),
                } => v.as_mut_bytes(),
                State::Cell {
                    data: CellBuf::Fixed(v),
                    ..
                } => v.data_mut(),
                State::Cell {
                    data: CellBuf::Variable(v),
                    ..
                } => v.data_mut(),
            };

            let buf = &mut buf[self.off..];
            if !buf.is_empty() {
                let n = match read.read(buf) {
                    Ok(0) => {
                        return Err(if matches!(
                            self,
                            Self {
                                off: 0,
                                state: State::Header { .. },
                                ..
                            }
                        ) {
                            // Not reading anything yet.
                            self.state = State::Finished;
                            IoError::new(ErrorKind::UnexpectedEof, CellFinished)
                        } else {
                            self.state = State::IoErr;
                            IoError::from(ErrorKind::UnexpectedEof)
                        }
                        .into());
                    }
                    Ok(n) => n,
                    Err(e) if e.kind() == ErrorKind::WouldBlock => return Ok(None),
                    Err(e) => {
                        self.state = State::IoErr;
                        return Err(e.into());
                    }
                };

                self.off += n;
                if n < buf.len() {
                    continue;
                }
            }

            match replace(&mut self.state, State::Err) {
                State::Header { data } => {
                    let (header, len) = match data {
                        HeaderBuf::Small(v) => (
                            CellHeader {
                                circuit: v.header.circuit.get().into(),
                                command: v.header.command,
                            },
                            v.len,
                        ),
                        HeaderBuf::Large(v) => (
                            CellHeader {
                                circuit: v.header.circuit.get(),
                                command: v.header.command,
                            },
                            v.len,
                        ),
                    };
                    let ty = self.config.cell_type(&header).ok_or(CellFormatError)?;

                    let (data, off) = match ty {
                        CellType::Fixed => {
                            let mut cell = self.config.get_fixed_cell();
                            let PrefixedFixedCell { v, .. } = transmute_mut!(cell.data_mut());
                            *v = len;
                            (CellBuf::Fixed(cell), 2)
                        }
                        CellType::Variable => (
                            CellBuf::Variable(VariableCell::new(
                                vec![0; len.get() as usize].into(),
                            )),
                            0,
                        ),
                    };
                    self.state = State::Cell { header, data };
                    self.off = off;
                }
                State::Cell { header, data, .. } => {
                    let ret = match data {
                        CellBuf::Fixed(data) => Cell::new(header, data),
                        CellBuf::Variable(data) => Cell::new(header, data),
                    };
                    self.state = State::Init;
                    self.off = 0;
                    return Ok(Some(ret));
                }
                _ => unreachable!(),
            }
        }
    }

    /// Checks if read is finished.
    ///
    /// It will only return true if it's EOF after reading full cell.
    /// Unfinished reads are treated as typical [`ErrorKind::UnexpectedEof`] instead of finished.
    pub fn is_finished(&self) -> bool {
        matches!(self.state, State::Finished)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use test_log::test;
    use tracing::instrument;

    use crate::fixed::FIXED_CELL_SIZE;
    use crate::utils::run_test;

    struct Config;

    impl ReadConfig for Config {
        fn cell_type(&self, header: &CellHeader) -> Option<CellType> {
            match header.command {
                0 => Some(CellType::Fixed),
                1 => Some(CellType::Variable),
                _ => None,
            }
        }
    }

    #[test]
    fn test_read_fixed() {
        #[instrument]
        fn test() {
            let mut buf: &[u8] = &[0; const { FIXED_CELL_SIZE + 3 }];

            let mut reader = Reader::new(Config);
            let _ = reader.read(&mut buf).unwrap().unwrap();
        }

        run_test(test);
    }

    #[test]
    fn test_read_variable() {
        #[instrument]
        fn test() {
            let mut buf: &[u8] = &[0, 0, 1, 0, 0];

            let mut reader = Reader::new(Config);
            let _ = reader.read(&mut buf).unwrap().unwrap();
        }

        run_test(test);
    }

    #[test]
    fn test_read_fixed_truncated() {
        #[instrument]
        fn test() {
            let mut buf: &[u8] = &[0; const { FIXED_CELL_SIZE + 2 }];

            let mut reader = Reader::new(Config);
            let e = reader.read(&mut buf).unwrap_err();
            match e {
                CellReadError::Io(e) if e.kind() == ErrorKind::UnexpectedEof => (),
                e => panic!("read error: {e:?}"),
            }
            assert!(!reader.is_finished(), "read is finished");
        }

        run_test(test);
    }

    #[test]
    fn test_read_variable_truncated() {
        #[instrument]
        fn test() {
            let mut buf: &[u8] = &[0, 0, 1, 0, 1];

            let mut reader = Reader::new(Config);
            let e = reader.read(&mut buf).unwrap_err();
            match e {
                CellReadError::Io(e) if e.kind() == ErrorKind::UnexpectedEof => (),
                e => panic!("read error: {e:?}"),
            }
            assert!(!reader.is_finished(), "read is finished");
        }

        run_test(test);
    }
}
