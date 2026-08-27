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

/// Circuit ID is not zero.
#[derive(Error, Debug)]
#[error("circuit ID is not zero")]
#[non_exhaustive]
pub struct NonZeroCircID;

/// Circuit ID is zero.
#[derive(Error, Debug)]
#[error("circuit ID is zero")]
#[non_exhaustive]
pub struct ZeroCircID;

/// Cell is fixed-sized.
#[derive(Error, Debug)]
#[error("cell is fixed-sized")]
#[non_exhaustive]
pub struct CellIsFixed;

/// Cell is variable-sized.
#[derive(Error, Debug)]
#[error("cell is variable-sized")]
#[non_exhaustive]
pub struct CellIsVariable;

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

/// Cell write error.
#[derive(Error, Debug)]
#[error(transparent)]
#[non_exhaustive]
pub enum CellWriteError {
    /// IO error.
    Io(#[from] IoError),
    CellFormatError(#[from] CellFormatError),
}

/// Cell cast error.
#[derive(Error, Debug)]
#[error(transparent)]
#[non_exhaustive]
pub enum CellCastError {
    CellFormatError(#[from] CellFormatError),
    NonZeroCircID(#[from] NonZeroCircID),
    ZeroCircID(#[from] ZeroCircID),
    CellIsFixed(#[from] CellIsFixed),
    CellIsVariable(#[from] CellIsVariable),
}
