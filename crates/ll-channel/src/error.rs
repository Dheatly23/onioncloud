//! Error types.

use std::io::Error as IoError;

use rustls::Error as RustlsError;
use thiserror::Error;

/// Channel error.
#[derive(Error, Debug)]
#[error(transparent)]
#[non_exhaustive]
pub enum ChannelError {
    Io(#[from] IoError),
    Rustls(#[from] RustlsError),
}
