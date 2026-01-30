use std::error::Error;
use std::fmt::{Debug, Display, Formatter, Result as FmtResult};

use thiserror::Error;

macro_rules! display2debug {
    ($i:ident) => {
        impl Debug for $i {
            fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
                Display::fmt(self, f)
            }
        }
    };
}

macro_rules! wraps_enum {
    ($(#[$meta:meta])* $v_outer:vis $outer:ident : $v_inner:vis $inner:ident {$($data:tt)*}) => {
        $(#[$meta])*
        $v_outer struct $outer($v_inner $inner);

        impl Debug for $outer {
            fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
                Display::fmt(&self.0, f)
            }
        }

        impl Display for $outer {
            fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
                Display::fmt(&self.0, f)
            }
        }

        impl Error for $outer {}

        #[derive(Error)]
        $v_inner enum $inner { $($data)* }

        impl Debug for $inner {
            fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
                Display::fmt(self, f)
            }
        }
    };
}

wraps_enum! {
/// Error in parsing relay ID.
pub RelayIdParseError: pub(crate) ParseRelayIdInner {
    #[error("cannot represent relay ID from empty string")]
    Empty,
    #[error("string is too short")]
    TooShort,
    #[error("invalid digit found in string")]
    InvalidDigit,
}}

wraps_enum! {
/// Ed25519 certificate subject/key type mismatch.
pub CertTypeError: pub(crate) CertTypeInner {
    #[error("certificate type mismatch (expected {expect}, got {actual})")]
    CertTy { expect: u8, actual: u8 },
    #[error("certificate key mismatch (expected {expect}, got {actual})")]
    KeyTy { expect: u8, actual: u8 },
}}

wraps_enum! {
/// Circuit protocol error.
pub CircuitProtocolError: pub(crate) CircuitProtocolInner {
    #[error("unexpected RELAY_BEGIN/RELAY_BEGIN_DIR from peer")]
    RelayBegin,
    #[error("token bucket undeflows")]
    BucketUnderflow,
    #[error("unexpected RELAY_SENDME cell")]
    UnexpectedSendme,
    #[error("SENDME digest mismatch")]
    SendmeDigest,
}}

#[derive(Error)]
pub(crate) enum NetdocParseErrorType {
    #[error("invalid keyword character")]
    InvalidKeywordChar,
    #[error("invalid argument character")]
    InvalidArgumentChar,
    #[error("invalid object format")]
    InvalidObjectFormat,
    #[error("invalid object content")]
    InvalidObjectContent,
    #[error("no newline found")]
    NoNewline,
    #[error("null character")]
    Null,
    #[error("document is empty")]
    Empty,
    #[error("input string have trailing characters")]
    HasTrailing,
}

display2debug!(NetdocParseErrorType);

enum NetdocPos {
    Unknown,
    LinePos { line: isize, pos: usize },
    ByteOff { off: usize },
}

impl Display for NetdocPos {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        match self {
            Self::LinePos { line, pos } => write!(f, "line {line} byte {pos}"),
            Self::ByteOff { off } => write!(f, "byte offset {off}"),
            Self::Unknown => write!(f, "unknown position"),
        }
    }
}

/// Netdoc parsing error.
#[derive(Error)]
#[error("error parsing netdoc at {pos}: {reason}")]
pub struct NetdocParseError {
    pos: NetdocPos,
    reason: NetdocParseErrorType,
}

display2debug! {NetdocParseError}

impl NetdocParseError {
    pub(crate) const fn with_line_pos(
        line: isize,
        pos: usize,
        reason: NetdocParseErrorType,
    ) -> Self {
        Self {
            reason,
            pos: NetdocPos::LinePos { line, pos },
        }
    }

    pub(crate) const fn with_byte_off(off: usize, reason: NetdocParseErrorType) -> Self {
        Self {
            reason,
            pos: NetdocPos::ByteOff { off },
        }
    }

    pub(crate) const fn with_unknown_pos(reason: NetdocParseErrorType) -> Self {
        Self {
            reason,
            pos: NetdocPos::Unknown,
        }
    }
}
