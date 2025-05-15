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
}

remap! {
    CellError => UserControllerError {
        Io,
        InvalidCellHeader,
        CellFormatError,
    }
}
