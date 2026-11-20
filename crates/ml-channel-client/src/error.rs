//! Channel error type.
use std::time::Duration;

use anyhow::Error as AnyError;
use onioncloud_ll::cell::error::{
    CellCastError, CellFormatError, CellIsFixed, CellIsVariable, CellReadError, CellWriteError,
    NonZeroCircID, ZeroCircID,
};
use onioncloud_ll::channel::error::{ChannelError, IoError, RustlsError};
use onioncloud_ll::error_from_enum;
use onioncloud_ll::utils::LinkVersionNegotiateError;
use thiserror::Error;

use crate::utils::{CellID, Timedelta};

/// Error type for [`ClientHandle`].
#[derive(Error, Debug)]
#[error(transparent)]
#[non_exhaustive]
pub enum ClientError {
    Any(#[from] AnyError),
    Io(#[from] IoError),
    Rustls(#[from] RustlsError),
    LinkVersionNegotiate(#[from] LinkVersionNegotiateError),
    CellFormat(#[from] CellFormatError),
    NonZeroCircID(#[from] NonZeroCircID),
    ZeroCircID(#[from] ZeroCircID),
    CellIsFixed(#[from] CellIsFixed),
    CellIsVariable(#[from] CellIsVariable),
    Handshake(#[from] HandshakeError),
    ClockSkew(#[from] ClockSkewError),
}

error_from_enum! {
    ClientError {
        else v => Self::Any(v.into()),
        ChannelError => [Io, Rustls],
        CellReadError => [Io, CellFormatError],
        CellWriteError => [Io, CellFormatError],
        CellCastError => [CellFormatError, NonZeroCircID, ZeroCircID, CellIsFixed, CellIsVariable],
    }
}

#[derive(Error, Debug)]
#[error("channel handshake error: {err}")]
pub struct HandshakeError {
    #[source]
    err: HandshakeErrorInner,
}

impl From<HandshakeErrorInner> for ClientError {
    fn from(err: HandshakeErrorInner) -> Self {
        HandshakeError { err }.into()
    }
}

#[derive(Error, Debug)]
pub(crate) enum HandshakeErrorInner {
    #[error("expected VERSIONS cell, got cell {id}")]
    ExpectVersions { id: CellID },
    #[error("got unexpected cell {id}")]
    UnexpectedCell { id: CellID },
    #[error("got duplicate cell {id}")]
    DuplicateCell { id: CellID },
    #[error("NETINFO peer address does not match actual connected address")]
    NetinfoPeerAddrMismatch,
}

#[derive(Error, Debug)]
#[error("clock skew detected! (system clock skews by {delta})")]
pub struct ClockSkewError {
    pub(crate) delta: Timedelta,
}

impl ClockSkewError {
    /// Gets clock skew.
    ///
    /// To get which direction it is, use [`Self::is_skew_past`] or [`Self::is_skew_future`].
    #[inline]
    #[must_use]
    pub fn skew(&self) -> Duration {
        self.delta.get_dur()
    }

    /// Checks if clock skews to the past.
    #[inline]
    #[must_use]
    pub fn is_skew_past(&self) -> bool {
        matches!(self.delta, Timedelta::Neg(_))
    }

    /// Checks if clock skews to the future.
    #[inline]
    #[must_use]
    pub fn is_skew_future(&self) -> bool {
        matches!(self.delta, Timedelta::Pos(_))
    }
}
