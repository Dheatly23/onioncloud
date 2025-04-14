use std::io::{Result as IoResult, Write};

use super::dispatch::{CellType, WithCellConfig};
use super::{CellHeader, CellLike, CellRef, FixedCell};
use crate::cache::{Cached, CellCache};
use crate::errors;
use crate::util::sans_io::Handle;
use crate::util::wrap_eof;

/// Writer for [`Cell`].
pub struct CellWriter<C> {
    cell: Option<C>,
    is_4bytes: bool,
    index: usize,
}

impl<C: CellLike> CellWriter<C> {
    /// Create new [`CellWriter`].
    ///
    /// # Parameters
    /// - `cell` : The cell to be written.
    /// - `circuit_4bytes` : [`true`] if circuit ID is 4 bytes.
    pub fn new(cell: C, circuit_4bytes: bool) -> Self {
        Self {
            cell: Some(cell),
            is_4bytes: circuit_4bytes,
            index: 0,
        }
    }
}

/// Wraps a [`Cached`] cell to be written.
impl<T, C> TryFrom<Cached<T, C>> for CellWriter<Cached<T, C>>
where
    T: CellLike + Into<FixedCell>,
    C: CellCache + WithCellConfig,
{
    type Error = errors::CellError;

    fn try_from(v: Cached<T, C>) -> Result<Self, Self::Error> {
        let config = Cached::cache(&v);
        if !matches!(
            (
                config.cell_type(&CellHeader::new(v.circuit(), v.command()))?,
                v.cell()
            ),
            (CellType::Fixed, CellRef::Fixed(_)) | (CellType::Variable, CellRef::Variable(_))
        ) {
            return Err(errors::CellFormatError.into());
        }

        let circuit_4bytes = config.is_circ_id_4bytes();
        Ok(Self::new(v, circuit_4bytes))
    }
}

fn write_cell(
    writer: &mut dyn Write,
    cell: &dyn CellLike,
    ix: &mut usize,
    is_4bytes: bool,
) -> IoResult<()> {
    // Write header
    let mut i = match (is_4bytes, *ix) {
        (false, 0..3) => {
            let circuit = cell.circuit();
            debug_assert!(
                circuit < u32::from(u16::MAX),
                "circuit ID {circuit} is too large to fit into protocol"
            );
            let [a, b] = (circuit as u16).to_be_bytes();
            let b = [a, b, cell.command()];

            while *ix < 3 {
                *ix += wrap_eof(writer.write(&b[*ix..]))?;
            }
            *ix - 3
        }
        (false, i @ 3..) => i - 3,
        (true, 0..5) => {
            let [a, b, c, d] = cell.circuit().to_be_bytes();
            let b = [a, b, c, d, cell.command()];

            while *ix < 5 {
                *ix += wrap_eof(writer.write(&b[*ix..]))?;
            }
            *ix - 5
        }
        (true, i @ 5..) => i - 5,
    };

    // Write cell data
    match cell.cell() {
        // Fixed data
        CellRef::Fixed(b) => {
            let b = b.data();

            while i < b.len() {
                let n = wrap_eof(writer.write(&b[i..]))?;
                i += n;
                *ix += n;
            }
        }
        CellRef::Variable(b) => {
            let b = b.data();

            if i < 2 {
                // Variable length
                let b = (b.len() as u16).to_be_bytes();

                while i < 2 {
                    let n = wrap_eof(writer.write(&b[i..]))?;
                    i += n;
                    *ix += n;
                }
            }

            // Variable data
            i -= 2;

            while i < b.len() {
                let n = wrap_eof(writer.write(&b[i..]))?;
                i += n;
                *ix += n;
            }
        }
    }

    Ok(())
}

/// Handle a [`Write`] stream.
///
/// When it returns an [`Ok`] value, [`CellWriter`] is finished and should be dropped.
impl<C: CellLike> Handle<&mut dyn Write> for CellWriter<C> {
    type Return = IoResult<()>;

    fn handle(&mut self, writer: &mut dyn Write) -> Self::Return {
        if let Some(cell) = self.cell.as_ref() {
            write_cell(writer, cell, &mut self.index, self.is_4bytes)?;
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
    use crate::cell::{Cell, FIXED_CELL_SIZE, VariableCell};
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
            let mut v = Vec::with_capacity(FIXED_CELL_SIZE + if is_4bytes { 5 } else { 3 });
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
            let mut v = Vec::with_capacity(FIXED_CELL_SIZE + if is_4bytes { 5 } else { 3 });
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
