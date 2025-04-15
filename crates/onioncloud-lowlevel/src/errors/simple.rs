use std::fmt::{Debug, Display, Formatter, Result as FmtResult};

use thiserror::Error;

use crate::cell::CellHeader;

macro_rules! display2debug {
    ($i:ident) => {
        impl Debug for $i {
            fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
                Display::fmt(self, f)
            }
        }
    };
}

#[derive(Error)]
#[error("invalid length")]
pub struct InvalidLength;

display2debug! {InvalidLength}

impl From<cipher::InvalidLength> for InvalidLength {
    fn from(_: cipher::InvalidLength) -> Self {
        Self
    }
}

#[derive(Error)]
#[error("cannot convert stream data into UTF-8")]
pub(crate) struct StreamUtf8Error;

display2debug! {StreamUtf8Error}

#[derive(Error, Debug)]
#[error("invalid cell header")]
pub struct InvalidCellHeader {
    header: Option<CellHeader>,
}

impl Default for InvalidCellHeader {
    fn default() -> Self {
        Self::new()
    }
}

impl InvalidCellHeader {
    pub fn new() -> Self {
        Self { header: None }
    }

    pub fn with_header(header: &CellHeader) -> Self {
        Self {
            header: Some(header.dup()),
        }
    }
}

#[derive(Error)]
#[error("bad cell format")]
pub struct CellFormatError;

display2debug! {CellFormatError}

#[derive(Error)]
#[error("version negotiation error")]
pub struct VersionsNegotiateError;

display2debug! {VersionsNegotiateError}
