//! Error types.

use std::io::Error as IoError;
use std::num::NonZeroUsize;

use thiserror::Error;

/// Variable cell is too long.
#[derive(Error, Debug)]
#[error("variable cell is too long ({} > 65535)", self.len)]
#[non_exhaustive]
pub struct VariableCellTooLong {
    // Use nonzero for better niching.
    // (Should always be > 65535 but this is acceptable for now).
    pub(crate) len: NonZeroUsize,
}

#[derive(Error, Debug)]
#[error("unknown IO error")]
#[non_exhaustive]
pub(crate) struct UnknownIoError;

/// Invalid cell format.
#[derive(Error, Debug)]
#[error("invalid cell format")]
#[non_exhaustive]
pub struct CellFormatError;

/// Cell reading is finished.
///
/// Will be the error source of [`CellReadError::Io`] if cell reading is finished.
#[derive(Error, Debug)]
#[error("finished reading cell")]
#[non_exhaustive]
pub struct CellFinished;

/// Cell read error.
#[derive(Error, Debug)]
#[error(transparent)]
#[non_exhaustive]
pub enum CellReadError {
    /// IO error.
    Io(#[from] IoError),
    CellFormatError(#[from] CellFormatError),
}
