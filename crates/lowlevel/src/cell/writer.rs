use std::io::{Result as IoResult, Write};

use zerocopy::IntoBytes;
use zerocopy::byteorder::big_endian::U16;

use super::dispatch::{CellType, WithCellConfig};
use super::{CellHeader, CellHeaderBig, CellHeaderSmall, CellLike, CellRef};
use crate::cache::{Cachable, Cached, CellCache};
use crate::errors;
use crate::util::sans_io::Handle;
use crate::util::wrap_eof;

/// Writer for [`Cell`].
pub struct CellWriter<C> {
    cell: Option<C>,
    index: CellWriterIndex,
}

enum CellWriterIndex {
    HeaderSmall(CellHeaderSmall, u8),
    HeaderBig(CellHeaderBig, u8),
    HeaderDone,
    CellSize(U16, u8),
    Data(usize),
    End,
}

impl<C: CellLike> CellWriter<C> {
    /// Create new [`CellWriter`].
    ///
    /// # Parameters
    /// - `cell` : The cell to be written.
    /// - `circuit_4bytes` : [`true`] if circuit ID is 4 bytes.
    pub fn new(cell: C, circuit_4bytes: bool) -> Self {
        let header = CellHeader::new(cell.circuit(), cell.command());
        Self::with_header(cell, circuit_4bytes, header)
    }

    /// Create finished [`CellWriter`].
    ///
    /// It does not write anything and is always finished.
    pub fn new_finished() -> Self {
        Self {
            cell: None,
            index: CellWriterIndex::End,
        }
    }

    fn with_header(cell: C, circuit_4bytes: bool, header: CellHeader) -> Self {
        Self {
            cell: Some(cell),
            index: if circuit_4bytes {
                CellWriterIndex::HeaderBig(header.into(), 0)
            } else {
                CellWriterIndex::HeaderSmall(header.into(), 0)
            },
        }
    }

    /// Create new [`CellWriter`] using configuration.
    pub fn with_cell_config<Cfg: WithCellConfig>(
        cell: C,
        cfg: &Cfg,
    ) -> Result<Self, errors::CellDataError> {
        Self::check_cell_config(&cell, cfg).map(|(t, h)| Self::with_header(cell, t, h))
    }

    fn check_cell_config<Cfg: WithCellConfig>(
        cell: &C,
        cfg: &Cfg,
    ) -> Result<(bool, CellHeader), errors::CellDataError> {
        let header = CellHeader::new(cell.circuit(), cell.command());
        match (cfg.cell_type(&header)?, cell.cell()) {
            (CellType::Fixed, CellRef::Fixed(_)) | (CellType::Variable, CellRef::Variable(_)) => {
                Ok((cfg.is_circ_id_4bytes(), header))
            }
            _ => Err(errors::CellFormatError.into()),
        }
    }

    /// Check if writer is finished.
    pub fn is_finished(&self) -> bool {
        self.cell.is_none()
    }
}

/// Wraps a [`Cached`] cell to be written.
impl<T, C> TryFrom<Cached<T, C>> for CellWriter<Cached<T, C>>
where
    T: CellLike + Cachable,
    C: CellCache + WithCellConfig,
{
    type Error = errors::CellDataError;

    fn try_from(v: Cached<T, C>) -> Result<Self, Self::Error> {
        Self::check_cell_config(&v, Cached::cache(&v)).map(|(t, h)| Self::with_header(v, t, h))
    }
}

fn write_u8(i: &mut u8, b: &[u8], writer: &mut dyn Write) -> IoResult<()> {
    debug_assert!(b.len() < 255);
    while usize::from(*i) < b.len() {
        *i += wrap_eof(writer.write(&b[usize::from(*i)..]))? as u8;
    }

    Ok(())
}

fn write_cell(
    writer: &mut dyn Write,
    cell: &dyn CellLike,
    ix: &mut CellWriterIndex,
) -> IoResult<()> {
    loop {
        *ix = match ix {
            CellWriterIndex::HeaderSmall(b, i) => {
                write_u8(i, b.as_bytes(), writer)?;
                CellWriterIndex::HeaderDone
            }
            CellWriterIndex::HeaderBig(b, i) => {
                write_u8(i, b.as_bytes(), writer)?;
                CellWriterIndex::HeaderDone
            }
            CellWriterIndex::HeaderDone => match cell.cell() {
                CellRef::Fixed(_) => CellWriterIndex::Data(0),
                CellRef::Variable(b) => CellWriterIndex::CellSize((b.len() as u16).into(), 0),
            },
            CellWriterIndex::CellSize(b, i) => {
                write_u8(i, b.as_bytes(), writer)?;
                CellWriterIndex::Data(0)
            }
            CellWriterIndex::Data(i) => {
                let b = match cell.cell() {
                    CellRef::Fixed(b) => b.data(),
                    CellRef::Variable(b) => b.data(),
                };

                while *i < b.len() {
                    *i += wrap_eof(writer.write(&b[*i..]))?;
                }

                CellWriterIndex::End
            }
            CellWriterIndex::End => break Ok(()),
        };
    }
}

/// Handle a [`Write`] stream.
///
/// When it returns an [`Ok`] value, [`CellWriter`] is finished and should be dropped.
/// [`handle`] can be called after it finished, but writer return [`Ok`] immediately.
/// Use [`is_finished`](`Self::is_finished`) to check.
impl<C: CellLike> Handle<&mut dyn Write> for CellWriter<C> {
    type Return = IoResult<()>;

    fn handle(&mut self, writer: &mut dyn Write) -> Self::Return {
        if let Some(cell) = self.cell.as_ref() {
            write_cell(writer, cell, &mut self.index)?;
            self.cell = None;
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::sync::Arc;

    use proptest::prelude::*;

    use crate::cell::padding::{Padding, VPadding};
    use crate::cell::{Cell, FIXED_CELL_SIZE, FixedCell, VariableCell};
    use crate::util::{TestConfig, circ_id_strat, var_cell_strat};

    proptest! {
        #[test]
        fn test_writer_cached_fixed(
            is_4bytes: bool,
            data: [u8; FIXED_CELL_SIZE],
        ) {
            let cfg = Arc::new(TestConfig::new(is_4bytes));

            let mut v = Vec::with_capacity(FIXED_CELL_SIZE + if is_4bytes { 5 } else { 3 });
            v.resize(
                if is_4bytes {
                    4
                } else {
                    2
                },
                0,
            );
            v.push(Padding::ID);
            v.extend_from_slice(&data);

            let mut r = Vec::new();
            CellWriter::try_from(Cached::new(
                cfg.clone(),
                Padding::new(FixedCell::new(Box::new(data))),
            ))
                .unwrap()
                .handle(&mut r)
                .unwrap();
            assert_eq!(r, v);
            assert_eq!(cfg.cache.as_inner(), (0, 1));
        }

        #[test]
        fn test_writer_variable(
            is_4bytes: bool,
            data in var_cell_strat(),
        ) {
            let mut v = Vec::with_capacity(data.len() + if is_4bytes { 7 } else { 5 });
            v.resize(
                if is_4bytes {
                    4
                } else {
                    2
                },
                0,
            );
            v.push(VPadding::ID);
            v.extend_from_slice(&(data.len() as u16).to_be_bytes());
            v.extend_from_slice(&data);

            let mut r = Vec::new();
            CellWriter::new(VPadding::new(VariableCell::from(data)), is_4bytes)
                .handle(&mut r)
                .unwrap();
            assert_eq!(r, v);
        }

        #[test]
        fn test_writer_cell_fixed(
            (is_4bytes, circ_id) in circ_id_strat(),
            command: u8,
            data: [u8; FIXED_CELL_SIZE],
        ) {
            let mut v = Vec::with_capacity(FIXED_CELL_SIZE + if is_4bytes { 5 } else { 3 });
            if is_4bytes {
                v.extend_from_slice(&circ_id.to_be_bytes());
            } else {
                v.extend_from_slice(&(circ_id as u16).to_be_bytes());
            }
            v.push(command);
            v.extend_from_slice(&data);

            let mut r = Vec::new();
            CellWriter::new(
                Cell::from_fixed(CellHeader::new(circ_id, command), FixedCell::new(Box::new(data))),
                is_4bytes,
            ).handle(&mut r).unwrap();
            assert_eq!(r, v);
        }

        #[test]
        fn test_writer_cell_variable(
            (is_4bytes, circ_id) in circ_id_strat(),
            command: u8,
            data in var_cell_strat(),
        ) {
            let mut v = Vec::with_capacity(data.len() + if is_4bytes { 7 } else { 5 });
            if is_4bytes {
                v.extend_from_slice(&circ_id.to_be_bytes());
            } else {
                v.extend_from_slice(&(circ_id as u16).to_be_bytes());
            }
            v.push(command);
            v.extend_from_slice(&(data.len() as u16).to_be_bytes());
            v.extend_from_slice(&data);

            let mut r = Vec::new();
            CellWriter::new(
                Cell::from_variable(CellHeader::new(circ_id, command), VariableCell::from(data)),
                is_4bytes,
            ).handle(&mut r).unwrap();
            assert_eq!(r, v);
        }
    }
}
