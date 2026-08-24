//! Cell writer.

use std::io::{Error as IoError, ErrorKind, Write};
use std::mem::replace;

use zerocopy::IntoBytes;

use crate::cell::{Cell, CellHeader, CellTy};
use crate::error::{CellFinished, CellFormatError, CellWriteError, UnknownIoError};
use crate::fixed::FixedCell;
use crate::utils::{HeaderLarge, HeaderLargeVariable, HeaderSmall, HeaderSmallVariable};
use crate::variable::VariableCell;

/// Configurator trait for [`Writer`].
///
/// # Implementer's Note
///
/// Almost all the methods have sensible (but incorrect) defaults.
/// It's encouraged for implementers to override all methods.
pub trait WriteConfig {
    /// Gets configuration of circuit ID length.
    ///
    /// Returns [`true`] if circuit ID should be 4 bytes.
    /// Legacy Tor protocol uses 2 bytes for circuit ID, but newer version switched to 4 bytes.
    /// Before version negotiation it must be assumed the link used legacy version.
    fn is_circ_id_4bytes(&self) -> bool {
        false
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

/// A cell writer.
pub struct Writer<C: WriteConfig> {
    /// Writer configurator.
    pub config: C,

    state: State,
    off: usize,
}

enum State {
    Err,
    IoErr,
    Finished,
    Init,
    Fixed {
        cell: FixedCell,
        data: FixedData,
    },
    Variable {
        cell: VariableCell,
        data: VariableData,
    },
}

enum FixedData {
    HeaderSmall(HeaderSmall),
    HeaderLarge(HeaderLarge),
    Data,
}

enum VariableData {
    HeaderSmall(HeaderSmallVariable),
    HeaderLarge(HeaderLargeVariable),
    Data,
}

enum Header {
    Small(HeaderSmall),
    Large(HeaderLarge),
}

impl<C: WriteConfig> Drop for Writer<C> {
    fn drop(&mut self) {
        match replace(&mut self.state, State::Err) {
            State::Fixed { cell, .. } => self.config.cache_fixed_cell(cell),
            State::Variable { cell, .. } => self.config.cache_variable_cell(cell),
            _ => (),
        }
    }
}

impl<C: WriteConfig> Writer<C> {
    /// Create new [`Writer`].
    pub const fn new(config: C) -> Self {
        Self {
            config,
            state: State::Init,
            off: 0,
        }
    }

    /// Write using sync [`Write`] trait.
    ///
    /// Returns `Ok(true)` if writing finished or there are no (more) value to write.
    ///
    /// # Special behaviors
    ///
    /// There are two special behaviors on write:
    /// - Error of kind [`ErrorKind::WouldBlock`] will return an `Ok(false)`.
    ///
    ///   **NOTE:** [`AsyncRead`](`futures_io::AsyncRead`) can use it to wrap [`Poll::Pending`](`std::task::Poll::Pending`) result.
    /// - If it returns EOF (reading 0 bytes), it'll error with `ErrorKind::UnexpectedEof`.
    ///
    /// # Usage note
    ///
    /// **DO NOT** reuse [`Writer`] after it returns an error.
    pub fn write<W: Write>(&mut self, write: &mut W) -> Result<bool, CellWriteError> {
        loop {
            let buf = match &self.state {
                State::Err => return Err(CellFormatError.into()),
                State::IoErr => return Err(IoError::other(UnknownIoError).into()),
                State::Finished => {
                    return Err(IoError::new(ErrorKind::UnexpectedEof, CellFinished).into());
                }
                State::Init => return Ok(true),
                State::Fixed {
                    data: FixedData::HeaderSmall(v),
                    ..
                } => v.as_bytes(),
                State::Fixed {
                    data: FixedData::HeaderLarge(v),
                    ..
                } => v.as_bytes(),
                State::Fixed {
                    data: FixedData::Data,
                    cell,
                } => cell.data(),
                State::Variable {
                    data: VariableData::HeaderSmall(v),
                    ..
                } => v.as_bytes(),
                State::Variable {
                    data: VariableData::HeaderLarge(v),
                    ..
                } => v.as_bytes(),
                State::Variable {
                    data: VariableData::Data,
                    cell,
                } => cell.data(),
            };

            let buf = &buf[self.off..];
            if !buf.is_empty() {
                let n = match write.write(buf) {
                    Ok(0) => {
                        if self.off == 0 {
                            // Not reading anything yet.
                            self.state = State::Finished;
                            return Err(IoError::new(ErrorKind::UnexpectedEof, CellFinished).into());
                        } else {
                            self.state = State::IoErr;
                            return Err(IoError::from(ErrorKind::UnexpectedEof).into());
                        }
                    }
                    Ok(n) => n,
                    Err(e) if e.kind() == ErrorKind::WouldBlock => return Ok(false),
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
                State::Fixed {
                    data: FixedData::Data,
                    cell,
                } => {
                    self.config.cache_fixed_cell(cell);
                    self.state = State::Init;
                    self.off = 0;
                    return Ok(true);
                }
                State::Variable {
                    data: VariableData::Data,
                    cell,
                } => {
                    self.config.cache_variable_cell(cell);
                    self.state = State::Init;
                    self.off = 0;
                    return Ok(true);
                }
                State::Fixed { cell, .. } => {
                    self.state = State::Fixed {
                        data: FixedData::Data,
                        cell,
                    };
                    self.off = 0;
                }
                State::Variable { cell, .. } => {
                    self.state = State::Variable {
                        data: VariableData::Data,
                        cell,
                    };
                    self.off = 0;
                }
                _ => unreachable!(),
            }
        }
    }

    /// Checks if write is finished.
    ///
    /// It will only return true if it's EOF before writing cell.
    /// Unfinished writes are treated as typical [`ErrorKind::UnexpectedEof`] instead of finished.
    pub fn is_finished(&self) -> bool {
        matches!(self.state, State::Finished)
    }

    /// Checks if [`Writer`] is ready to receive new cell.
    pub fn is_ready(&self) -> bool {
        matches!(self.state, State::Init)
    }

    /// Conditionally inserts new cell.
    ///
    /// If [`Writer`] is ready to receive cell (AKA [`Self::is_ready`] returns [`true`]),
    /// it will call the function and returns [`true`] if cell is inserted.
    /// Otherwise, it will return [`false`].
    ///
    /// # Panics
    ///
    /// Panics if circuit ID of the cell is bigger than 65535 and config uses 2 bytes ID.
    pub fn maybe_receive(&mut self, f: impl FnOnce() -> Option<Cell>) -> bool {
        if !self.is_ready() {
            return false;
        }

        let Some(Cell {
            data,
            header: CellHeader { circuit, command },
        }) = f()
        else {
            return false;
        };

        let header = if self.config.is_circ_id_4bytes() {
            Header::Large(HeaderLarge {
                circuit: circuit.into(),
                command: command,
            })
        } else {
            Header::Small(HeaderSmall {
                circuit: u16::try_from(circuit)
                    .expect("circuit ID must fit in u16")
                    .into(),
                command: command,
            })
        };
        self.state = match data {
            CellTy::Fixed(c) => State::Fixed {
                data: match header {
                    Header::Small(v) => FixedData::HeaderSmall(v),
                    Header::Large(v) => FixedData::HeaderLarge(v),
                },
                cell: c,
            },
            CellTy::Variable(c) => State::Variable {
                data: match header {
                    Header::Small(v) => VariableData::HeaderSmall(HeaderSmallVariable {
                        header: v,
                        len: (c.len() as u16).into(),
                    }),
                    Header::Large(v) => VariableData::HeaderLarge(HeaderLargeVariable {
                        header: v,
                        len: (c.len() as u16).into(),
                    }),
                },
                cell: c,
            },
        };
        self.off = 0;

        true
    }
}
