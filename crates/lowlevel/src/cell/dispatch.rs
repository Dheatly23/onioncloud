use std::io::Read;
use std::ops::Deref;
use std::pin::Pin;

use futures_io::AsyncRead;

use super::reader::{CellHeaderReader, FixedCellReader, VariableCellReader};
use super::{Cell, CellHeader};
use crate::cache::{Cachable, CellCache};
use crate::util::sans_io::{FnHandle, Handle};
use crate::{errors, util};

/// Cell type.
///
/// Returned by [`WithCellConfig::cell_type`] to indicate the type of the cell.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CellType {
    Fixed,
    Variable,
}

/// Cell configuration storage.
///
/// Should be implemented by a configuration data type.
/// Provides configuration for the inner cell protocol.
pub trait WithCellConfig {
    /// Gets configuration of circuit ID length.
    ///
    /// Returns [`true`] if circuit ID should be 4 bytes.
    /// Legacy Tor protocol uses 2 bytes for circuit ID, but newer version switched to 4 bytes.
    /// Before version negotiation it must be assumed the link used legacy version.
    fn is_circ_id_4bytes(&self) -> bool;

    /// Check cell type by it's header.
    ///
    /// If the header is valid, returns a [`CellType`].
    /// Otherwise it returns a [`InvalidCellHeader`](`errors::InvalidCellHeader`) value.
    fn cell_type(&self, header: &CellHeader) -> Result<CellType, errors::InvalidCellHeader>;
}

impl<T> WithCellConfig for T
where
    T: Deref + ?Sized,
    T::Target: WithCellConfig,
{
    fn is_circ_id_4bytes(&self) -> bool {
        <T as Deref>::Target::is_circ_id_4bytes(self)
    }

    fn cell_type(&self, header: &CellHeader) -> Result<CellType, errors::InvalidCellHeader> {
        <T as Deref>::Target::cell_type(self, header)
    }
}

/// Cell reader type.
///
/// Continuously generates cell from a stream.
pub struct CellReader {
    inner: CellReaderInner,
}

enum CellReaderInner {
    Init,
    Err,
    Header(CellHeaderReader),
    Fixed(FixedCellReader),
    Variable(VariableCellReader),
}

impl CellReader {
    #[inline(always)]
    pub fn new() -> Self {
        Self {
            inner: CellReaderInner::Init,
        }
    }
}

impl Cachable for CellReader {
    fn cache<C: CellCache + ?Sized>(self, cache: &C) {
        if let CellReaderInner::Fixed(v) = self.inner {
            v.cache(cache);
        }
    }
}

impl Default for CellReader {
    fn default() -> Self {
        Self::new()
    }
}

impl<C: WithCellConfig + CellCache> Handle<(&mut dyn Read, C)> for CellReader {
    type Return = Result<Cell, errors::CellError>;

    fn handle(&mut self, (reader, config): (&mut dyn Read, C)) -> Self::Return {
        let Self { inner } = self;
        loop {
            match inner {
                CellReaderInner::Err => return Err(errors::CellFormatError.into()),
                CellReaderInner::Init => {
                    *inner =
                        CellReaderInner::Header(CellHeaderReader::new(config.is_circ_id_4bytes()));
                }
                CellReaderInner::Header(h) => {
                    let header = h.handle(reader)?;
                    *inner = CellReaderInner::Err;
                    *inner = match config.cell_type(&header)? {
                        CellType::Fixed => CellReaderInner::Fixed(FixedCellReader::new(
                            header,
                            config.get_cached(),
                        )),
                        CellType::Variable => {
                            CellReaderInner::Variable(VariableCellReader::new(header))
                        }
                    };
                }
                CellReaderInner::Fixed(h) => {
                    let cell = h.handle(reader)?;
                    *inner = CellReaderInner::Init;
                    return Ok(cell);
                }
                CellReaderInner::Variable(h) => {
                    let cell = h.handle(reader)?;
                    *inner = CellReaderInner::Init;
                    return Ok(cell);
                }
            }
        }
    }
}

/// Asynchronously reads cell from a stream.
pub async fn read_cell_cached(
    reader: Pin<&mut impl AsyncRead>,
    config: impl WithCellConfig + CellCache,
) -> Result<Cell, errors::CellError> {
    let mut handle = CellReader::new();
    util::async_reader(
        reader,
        FnHandle(move |s: &mut dyn Read| handle.handle((s, &config))),
    )
    .await
}

#[cfg(test)]
mod tests {
    use super::*;

    use proptest::collection::vec;
    use proptest::prelude::*;

    use crate::cell::FIXED_CELL_SIZE;
    use crate::util::{TestConfig, steps, test_read_helper};

    #[test]
    fn test_parse_header_fail() {
        let r =
            CellReader::new(TestConfig::new(false)).handle(&mut util::Buffer::new(&[0, 0, 255]));
        assert!(matches!(r, Err(errors::CellError::InvalidCellHeader(_))));

        let r = CellReader::new(TestConfig::new(true))
            .handle(&mut util::Buffer::new(&[0, 0, 0, 0, 255]));
        assert!(matches!(r, Err(errors::CellError::InvalidCellHeader(_))));
    }

    proptest! {
        #[test]
        fn test_parse_fixed(steps in steps(), is_4bytes: bool, data: [u8; FIXED_CELL_SIZE]) {
            let mut buf = Vec::new();
            buf.extend_from_slice(&[0u8; 4][..if is_4bytes {
                4
            } else {
                2
            }]);
            buf.push(1);
            buf.extend_from_slice(&data);

            let cell = test_read_helper(
                &buf,
                steps,
                CellReader::new(TestConfig::new(is_4bytes)),
            );
            assert_eq!(cell.data(), data);
        }

        #[test]
        fn test_parse_variable(
            steps in steps(),
            is_4bytes: bool,
            data in vec(any::<u8>(), 0..=u16::MAX as usize),
        ) {
            let mut buf = Vec::new();
            buf.extend_from_slice(&[0u8; 4][..if is_4bytes {
                4
            } else {
                2
            }]);
            buf.push(128);
            buf.extend_from_slice(&(data.len() as u16).to_be_bytes());
            buf.extend_from_slice(&data);

            let cell = test_read_helper(
                &buf,
                steps,
                CellReader::new(TestConfig::new(is_4bytes)),
            );
            assert_eq!(cell.data(), data);
        }
    }
}
