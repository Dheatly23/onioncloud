use std::error::Error;
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

#[derive(Error)]
#[error("no free circuit ID found")]
pub struct NoFreeCircIDError;

display2debug! {NoFreeCircIDError}

#[derive(Error)]
#[error("task handle returns an error")]
pub struct HandleError;

display2debug! {HandleError}

#[derive(Error)]
#[non_exhaustive]
pub enum SendControlMsgError {
    #[error("failed to send control message: {0}")]
    HandleError(#[from] HandleError),
    #[error("failed to send control message: task handle finished")]
    HandleFinalized,
}

display2debug! {SendControlMsgError}

pub struct RelayIdParseError(pub(crate) ParseRelayIdInner);

impl Display for RelayIdParseError {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        Display::fmt(&self.0, f)
    }
}

display2debug! {RelayIdParseError}

impl Error for RelayIdParseError {}

#[derive(Error)]
pub(crate) enum ParseRelayIdInner {
    #[error("cannot represent relay ID from empty string")]
    Empty,
    #[error("string is too short")]
    TooShort,
    #[error("invalid digit found in string")]
    InvalidDigit,
}

display2debug! {ParseRelayIdInner}

#[derive(Error)]
#[error("malformed certificate format")]
pub struct CertFormatError;

display2debug! {CertFormatError}

#[derive(Error)]
#[error("bad certificate signature")]
pub struct CertVerifyError;

display2debug! {CertVerifyError}

pub struct CertTypeError(pub(crate) CertTypeInner);

impl Display for CertTypeError {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        Display::fmt(&self.0, f)
    }
}

display2debug! {CertTypeError}

impl Error for CertTypeError {}

#[derive(Error)]
pub(crate) enum CertTypeInner {
    #[error("certificate type mismatch (expected {expect}, got {actual})")]
    CertTy { expect: u8, actual: u8 },
    #[error("certificate key mismatch (expected {expect}, got {actual})")]
    KeyTy { expect: u8, actual: u8 },
}

display2debug! {CertTypeInner}
