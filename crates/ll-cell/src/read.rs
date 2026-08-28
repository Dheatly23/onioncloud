//! Cell reader.

use std::io::{Error as IoError, ErrorKind, Read};
use std::mem::replace;

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
pub struct Reader<C> {
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
                    Ok(0) if self.off == 0 => {
                        // Not reading anything yet.
                        self.state = State::Finished;
                        return Err(IoError::new(ErrorKind::UnexpectedEof, CellFinished).into());
                    }
                    Ok(0) => {
                        self.state = State::IoErr;
                        return Err(IoError::from(ErrorKind::UnexpectedEof).into());
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
