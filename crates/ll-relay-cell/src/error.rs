//! Error types.

use thiserror::Error;

pub use onioncloud_ll_cell::error::CellFormatError;

/// Stream ID is not zero.
#[derive(Error, Debug)]
#[error("stream ID is not zero")]
#[non_exhaustive]
pub struct NonZeroStreamID;

/// Stream ID is zero.
#[derive(Error, Debug)]
#[error("stream ID is zero")]
#[non_exhaustive]
pub struct ZeroStreamID;

/// Cell cast error.
#[derive(Error, Debug)]
#[error(transparent)]
#[non_exhaustive]
pub enum CellCastError {
    CellFormatError(#[from] CellFormatError),
    NonZeroStreamID(#[from] NonZeroStreamID),
    ZeroStreamID(#[from] ZeroStreamID),
}
