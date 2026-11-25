//! Error types.

#[doc(no_inline)]
pub use std::io::Error as IoError;

#[doc(no_inline)]
pub use rustls::Error as RustlsError;
use thiserror::Error;

/// Channel error.
#[derive(Error, Debug)]
#[error(transparent)]
#[non_exhaustive]
pub enum ChannelError {
    Io(#[from] IoError),
    Rustls(#[from] RustlsError),
}
