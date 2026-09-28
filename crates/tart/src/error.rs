//! Error types.

use std::error::Error;
use std::fmt::{Debug, Display, Formatter, Result as FmtResult};

/// Type for marking send error.
///
/// It's not defined what error it is.
/// Most likely reason is receiver disconnection.
/// But only for [`Sender::start_send`], it could also means the buffer is full.
#[derive(Clone)]
#[non_exhaustive]
pub struct SendError {}

impl Debug for SendError {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        write!(f, "SendError")
    }
}

impl Display for SendError {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        write!(f, "error sending data")
    }
}

impl Error for SendError {}
