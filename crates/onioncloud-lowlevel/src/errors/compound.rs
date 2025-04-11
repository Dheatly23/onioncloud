use std::io::Error as IoError;

use thiserror::Error;

/// Cell error.
#[derive(Error, Debug)]
#[non_exhaustive]
pub enum CellError {
    #[error("network error")]
    Io(#[from] IoError),
    #[error("invalid cell header")]
    InvalidCellHeader(#[from] super::InvalidCellHeader),
}
