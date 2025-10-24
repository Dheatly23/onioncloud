use std::io::Error as IoError;

use rustls::Error as RustlsError;
use thiserror::Error;

macro_rules! remap {
    (#pat $from:ident $to:ident $v:ident $var:ident) => {
        $from::$var($v)
    };
    (#pat $from:ident $to:ident $v:ident ($vfrom:ident => $vto:ident)) => {
        $from::$vfrom($v)
    };
    (#val $from:ident $to:ident $v:ident $var:ident) => {
        $to::$var($v)
    };
    (#val $from:ident $to:ident $v:ident ($vfrom:ident => $vto:ident)) => {
        $to::$vto($v)
    };
    ($from:ident => $to:ident {$($item:tt),* $(,)?}) => {
        impl From<$from> for $to {
            fn from(v: $from) -> $to {
                match v {
                    $(remap!(#pat $from $to v $item) => remap!(#val $from $to v $item)),*
                }
            }
        }
    };
}

/// Cell data error.
#[derive(Error, Debug)]
#[non_exhaustive]
pub enum CellDataError {
    #[error(transparent)]
    InvalidCellHeader(#[from] super::InvalidCellHeader),
    #[error(transparent)]
    CellFormatError(#[from] super::CellFormatError),
}

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

remap! {
    CellDataError => CellError {
        InvalidCellHeader,
        CellFormatError,
    }
}

/// User controller error.
#[derive(Error, Debug)]
#[non_exhaustive]
pub enum UserControllerError {
    #[error("network error: {0}")]
    Io(#[from] IoError),
    #[error("rustls error: {0}")]
    Rustls(#[from] RustlsError),
    #[error(transparent)]
    InvalidCellHeader(#[from] super::InvalidCellHeader),
    #[error(transparent)]
    CellFormatError(#[from] super::CellFormatError),
    #[error(transparent)]
    VersionsNegotiateError(#[from] super::VersionsNegotiateError),
    #[error(transparent)]
    PeerSocketMismatchError(#[from] super::PeerSocketMismatchError),
    #[error(transparent)]
    CertsError(#[from] super::CertsError),
    #[error(transparent)]
    CertFormatError(#[from] super::CertFormatError),
    #[error(transparent)]
    CertVerifyError(#[from] super::CertVerifyError),
    #[error(transparent)]
    CertTypeError(#[from] super::CertTypeError),
    #[error(transparent)]
    NetinfoError(#[from] super::NetinfoError),
    #[error(transparent)]
    CellLengthOverflowError(#[from] super::CellLengthOverflowError),
}

remap! {
    CellError => UserControllerError {
        Io,
        InvalidCellHeader,
        CellFormatError,
    }
}

remap! {
    CellDataError => UserControllerError {
        InvalidCellHeader,
        CellFormatError,
    }
}

/// Directory controller error.
#[derive(Error, Debug)]
#[non_exhaustive]
pub enum DirControllerError {
    #[error(transparent)]
    InvalidCellHeader(#[from] super::InvalidCellHeader),
    #[error(transparent)]
    CellFormatError(#[from] super::CellFormatError),
    #[error(transparent)]
    CipherError(#[from] super::CipherError),
    #[error(transparent)]
    CellDigestError(#[from] super::CellDigestError),
    #[error(transparent)]
    CircuitHandshakeError(#[from] super::CircuitHandshakeError),
    #[error(transparent)]
    ChannelClosedError(#[from] super::ChannelClosedError),
    #[error(transparent)]
    CircuitProtocolError(#[from] super::CircuitProtocolError),
    #[error(transparent)]
    CellLengthOverflowError(#[from] super::CellLengthOverflowError),
}
