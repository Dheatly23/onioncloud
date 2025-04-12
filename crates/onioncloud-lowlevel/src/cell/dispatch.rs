use std::pin::Pin;
use std::sync::Arc;

use futures_io::AsyncRead;

use super::{Cell, CellHeader, FixedCell};
use crate::cache::CellCache;
use crate::errors;

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

impl<T: WithCellConfig + ?Sized> WithCellConfig for &T {
    fn is_circ_id_4bytes(&self) -> bool {
        T::is_circ_id_4bytes(self)
    }

    fn cell_type(&self, header: &CellHeader) -> Result<CellType, errors::InvalidCellHeader> {
        T::cell_type(self, header)
    }
}

impl<T: WithCellConfig + ?Sized> WithCellConfig for Box<T> {
    fn is_circ_id_4bytes(&self) -> bool {
        T::is_circ_id_4bytes(self)
    }

    fn cell_type(&self, header: &CellHeader) -> Result<CellType, errors::InvalidCellHeader> {
        T::cell_type(self, header)
    }
}

impl<T: WithCellConfig + ?Sized> WithCellConfig for Arc<T> {
    fn is_circ_id_4bytes(&self) -> bool {
        T::is_circ_id_4bytes(self)
    }

    fn cell_type(&self, header: &CellHeader) -> Result<CellType, errors::InvalidCellHeader> {
        T::cell_type(self, header)
    }
}

/// Asynchronously reads cell from a stream.
pub async fn read_cell(
    mut reader: Pin<&mut impl AsyncRead>,
    config: impl WithCellConfig,
) -> Result<Cell, errors::CellError> {
    let header = CellHeader::read(reader.as_mut(), config.is_circ_id_4bytes()).await?;
    Ok(match config.cell_type(&header)? {
        CellType::Fixed => Cell::read_fixed(reader, header, FixedCell::default()).await?,
        CellType::Variable => Cell::read_variable(reader, header).await?,
    })
}

/// Asynchronously reads cell from a stream with cell caching.
pub async fn read_cell_cached(
    mut reader: Pin<&mut impl AsyncRead>,
    config: impl WithCellConfig + CellCache,
) -> Result<Cell, errors::CellError> {
    let header = CellHeader::read(reader.as_mut(), config.is_circ_id_4bytes()).await?;
    Ok(match config.cell_type(&header)? {
        CellType::Fixed => Cell::read_fixed(reader, header, config.get_cached()).await?,
        CellType::Variable => Cell::read_variable(reader, header).await?,
    })
}
