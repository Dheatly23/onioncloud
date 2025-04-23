use std::io::Error as IoError;

use thiserror::Error;

/// Cell error.
#[derive(Error, Debug)]
#[non_exhaustive]
pub enum CellError {
    #[error("network error: {0}")]
    Io(#[from] IoError),
    #[error(transparent)]
    InvalidCellHeader(#[from] super::InvalidCellHeader),
    #[error(transparent)]
    CellFormatError(#[from] super::CellFormatError),
}
