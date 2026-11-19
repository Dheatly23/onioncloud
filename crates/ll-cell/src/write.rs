//! Cell writer.

use std::io::{Error as IoError, ErrorKind, Write};
use std::mem::replace;
use std::ops::Deref;

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

impl<T> WriteConfig for T
where
    T: Deref,
    T::Target: WriteConfig,
{
    #[inline]
    fn is_circ_id_4bytes(&self) -> bool {
        <T as Deref>::Target::is_circ_id_4bytes(&**self)
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
    ///
    /// # Errors
    ///
    /// Returns error if:
    /// - IO error happened.
    /// - Cell format error.
    /// - Socket is closed (EOF).
    #[expect(clippy::too_many_lines)]
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
                        if self.off == 0
                            && !matches!(
                                self.state,
                                State::Fixed {
                                    data: FixedData::Data,
                                    ..
                                } | State::Variable {
                                    data: VariableData::Data,
                                    ..
                                }
                            )
                        {
                            // Not reading anything yet.
                            self.state = State::Finished;
                            return Err(IoError::new(ErrorKind::UnexpectedEof, CellFinished).into());
                        }
                        self.state = State::IoErr;
                        return Err(IoError::from(ErrorKind::UnexpectedEof).into());
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
    #[expect(clippy::cast_possible_truncation)]
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
                command,
            })
        } else {
            Header::Small(HeaderSmall {
                circuit: u16::try_from(circuit)
                    .expect("circuit ID must fit in u16")
                    .into(),
                command,
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

#[cfg(test)]
mod tests {
    use super::*;

    use test_log::test;
    use tracing::instrument;

    use crate::fixed::FIXED_CELL_SIZE;
    use crate::utils::run_test;

    struct Config;

    impl WriteConfig for Config {}

    #[test]
    fn test_write_fixed() {
        #[instrument]
        fn test() {
            let mut writer = Writer::new(Config);
            assert!(writer.is_ready(), "writer is not ready");
            assert!(!writer.is_finished(), "writer is finished");
            assert!(
                writer.maybe_receive(|| Some(Cell::new(
                    CellHeader {
                        command: 1,
                        circuit: 0x101
                    },
                    FixedCell::from([1u8; FIXED_CELL_SIZE])
                ))),
                "writer does not receive cell"
            );

            let mut buf = [255; const { FIXED_CELL_SIZE + 3 }];
            let mut w = &mut buf[..];
            assert!(writer.write(&mut w).unwrap(), "write is not finished");
            assert_eq!(w.len(), 0);
            assert_eq!(buf, [1; const { FIXED_CELL_SIZE + 3 }]);

            assert!(writer.is_ready(), "writer is not ready");
            assert!(!writer.is_finished(), "writer is finished");
            assert!(
                writer.maybe_receive(|| Some(Cell::new(
                    CellHeader {
                        command: 1,
                        circuit: 0x101
                    },
                    FixedCell::from([1u8; FIXED_CELL_SIZE])
                ))),
                "writer does not receive cell"
            );
            let mut w = &mut buf[..0];
            let e = writer.write(&mut w).unwrap_err();
            match e {
                CellWriteError::Io(e) if e.kind() == ErrorKind::UnexpectedEof => (),
                e => panic!("write error: {e:?}"),
            }
            assert!(!writer.is_ready(), "writer is ready");
            assert!(writer.is_finished(), "writer is not finished");
        }

        run_test(test);
    }

    #[test]
    fn test_write_variable() {
        #[instrument]
        fn test() {
            let mut writer = Writer::new(Config);
            assert!(writer.is_ready(), "writer is not ready");
            assert!(!writer.is_finished(), "writer is finished");
            assert!(
                writer.maybe_receive(|| Some(Cell::new(
                    CellHeader {
                        command: 1,
                        circuit: 0x101
                    },
                    VariableCell::empty()
                ))),
                "writer does not receive cell"
            );

            let mut buf = [255; const { 5 }];
            let mut w = &mut buf[..];
            assert!(writer.write(&mut w).unwrap(), "write is not finished");
            assert_eq!(w.len(), 0);
            assert_eq!(buf, [1, 1, 1, 0, 0]);

            assert!(writer.is_ready(), "writer is not ready");
            assert!(!writer.is_finished(), "writer is finished");
            assert!(
                writer.maybe_receive(|| Some(Cell::new(
                    CellHeader {
                        command: 1,
                        circuit: 0x101
                    },
                    VariableCell::empty()
                ))),
                "writer does not receive cell"
            );
            let mut w = &mut buf[..0];
            let e = writer.write(&mut w).unwrap_err();
            match e {
                CellWriteError::Io(e) if e.kind() == ErrorKind::UnexpectedEof => (),
                e => panic!("write error: {e:?}"),
            }
            assert!(!writer.is_ready(), "writer is ready");
            assert!(writer.is_finished(), "writer is not finished");
        }

        run_test(test);
    }

    #[test]
    fn test_write_fixed_truncated() {
        #[instrument]
        fn test() {
            let mut writer = Writer::new(Config);
            assert!(writer.is_ready(), "writer is not ready");
            assert!(!writer.is_finished(), "writer is finished");
            assert!(
                writer.maybe_receive(|| Some(Cell::new(
                    CellHeader {
                        command: 1,
                        circuit: 0x101
                    },
                    FixedCell::from([1u8; FIXED_CELL_SIZE])
                ))),
                "writer does not receive cell"
            );

            let mut buf = [0; const { FIXED_CELL_SIZE + 2 }];
            let mut w = &mut buf[..];
            let e = writer.write(&mut w).unwrap_err();
            match e {
                CellWriteError::Io(e) if e.kind() == ErrorKind::UnexpectedEof => (),
                e => panic!("write error: {e:?}"),
            }
            assert!(!writer.is_ready(), "writer is ready");
            assert!(!writer.is_finished(), "writer is not finished");
            assert_eq!(buf, [1; const { FIXED_CELL_SIZE + 2 }]);
        }

        run_test(test);
    }

    #[test]
    fn test_write_variable_truncated() {
        #[instrument]
        fn test() {
            let mut writer = Writer::new(Config);
            assert!(writer.is_ready(), "writer is not ready");
            assert!(!writer.is_finished(), "writer is finished");
            assert!(
                writer.maybe_receive(|| Some(Cell::new(
                    CellHeader {
                        command: 1,
                        circuit: 0x101
                    },
                    VariableCell::empty()
                ))),
                "writer does not receive cell"
            );

            let mut buf = [0; const { 4 }];
            let mut w = &mut buf[..];
            let e = writer.write(&mut w).unwrap_err();
            match e {
                CellWriteError::Io(e) if e.kind() == ErrorKind::UnexpectedEof => (),
                e => panic!("write error: {e:?}"),
            }
            assert!(!writer.is_ready(), "writer is ready");
            assert!(!writer.is_finished(), "writer is not finished");
            assert_eq!(buf, [1, 1, 1, 0]);
        }

        run_test(test);
    }
}
