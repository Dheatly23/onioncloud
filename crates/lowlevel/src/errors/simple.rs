use std::error::Error;
use std::fmt::{Debug, Display, Formatter, Result as FmtResult};
use std::net::{IpAddr, SocketAddr};

use thiserror::Error;

use crate::cell::CellHeader;
use crate::util::print_list;

macro_rules! display2debug {
    ($i:ident) => {
        impl Debug for $i {
            fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
                Display::fmt(self, f)
            }
        }
    };
}

/// Invalid length.
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

/// Invalid cell header.
#[derive(Error, Debug)]
pub struct InvalidCellHeader {
    header: Option<CellHeader>,
}

impl Default for InvalidCellHeader {
    fn default() -> Self {
        Self::new()
    }
}

impl Display for InvalidCellHeader {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        write!(f, "invalid cell header")?;

        match self.header {
            Some(CellHeader { circuit, command }) => {
                write!(f, " (command: {command}, circuit: {circuit})")
            }
            None => Ok(()),
        }
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

/// Generic cell format error.
///
/// The detail of format error are intentionally obscured.
#[derive(Error)]
#[error("bad cell format")]
pub struct CellFormatError;

display2debug! {CellFormatError}

/// Protocol version negotiation error.
#[derive(Error)]
#[error("version negotiation error")]
#[non_exhaustive]
pub struct VersionsNegotiateError;

display2debug! {VersionsNegotiateError}

/// Failed to find free circuit ID.
#[derive(Error)]
#[error("no free circuit ID found")]
pub struct NoFreeCircIDError;

display2debug! {NoFreeCircIDError}

/// Delegated task returns an error.
#[derive(Error)]
#[error("task handle returns an error")]
pub struct HandleError;

display2debug! {HandleError}

/// Error in sending control message.
#[derive(Error)]
#[non_exhaustive]
pub enum SendControlMsgError {
    /// Channel errors.
    #[error("failed to send control message: {0}")]
    HandleError(#[from] HandleError),

    /// Channel gracefully shutdown.
    #[error("failed to send control message: task handle finished")]
    HandleFinalized,
}

display2debug! {SendControlMsgError}

/// Error in parsing relay ID.
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

/// Certificate format error.
///
/// It **only** covers format-related error.
/// For validation/verification, use [`CertVerifyError`] instead.
#[derive(Error)]
#[error("malformed certificate format")]
pub struct CertFormatError;

display2debug! {CertFormatError}

/// Certificate verification error.
///
/// It could be a number of errors, including:
/// - Cryptographic signature error.
/// - Some **field/extension value** are not as expected or does not exist.
/// - Certificate expired.
#[derive(Error)]
#[error("certificate verification error")]
pub struct CertVerifyError;

display2debug! {CertVerifyError}

/// Ed25519 certificate subject/key type mismatch.
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

/// Unexpected peer socket address.
#[derive(Error)]
pub struct PeerSocketMismatchError {
    peer: SocketAddr,
    addrs: Box<[SocketAddr]>,
}

impl PeerSocketMismatchError {
    pub(crate) fn new(peer: SocketAddr, addrs: Box<[SocketAddr]>) -> Self {
        Self { peer, addrs }
    }
}

impl Display for PeerSocketMismatchError {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        write!(
            f,
            "peer address {} is not in {}",
            self.peer,
            print_list(&self.addrs)
        )
    }
}

display2debug! {PeerSocketMismatchError}

/// CERTS cell related error (non-cryptographic).
#[derive(Error)]
#[non_exhaustive]
pub enum CertsError {
    #[error("duplicate certificate ID {0}")]
    Duplicate(u8),
    #[error("certificate ID {0} is not found")]
    NotFound(u8),
    #[error("no link certificate provided")]
    NoLinkCert,
}

display2debug! {CertsError}

/// NETINFO cell related error.
#[derive(Error)]
#[non_exhaustive]
pub enum NetinfoError {
    /// Invalid peer address.
    #[error("invalid peer address")]
    InvalidPeerAddr,
    /// One of this address is not expected.
    #[error("this address not found: {0}")]
    ThisAddrNotFound(#[source] PeerIpMismatchError),
}

display2debug! {NetinfoError}

/// Unexpected peer IP address.
#[derive(Error)]
pub struct PeerIpMismatchError {
    peer: IpAddr,
    addrs: Box<[IpAddr]>,
}

impl PeerIpMismatchError {
    pub(crate) fn new(peer: IpAddr, addrs: Box<[IpAddr]>) -> Self {
        Self { peer, addrs }
    }
}

impl Display for PeerIpMismatchError {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        write!(
            f,
            "peer address {} is not in {}",
            self.peer,
            print_list(&self.addrs)
        )
    }
}

display2debug! {PeerIpMismatchError}
