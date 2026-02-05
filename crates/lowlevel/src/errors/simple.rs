use std::error::Error;
use std::fmt::{Debug, Display, Formatter, Result as FmtResult};
use std::net::{IpAddr, SocketAddr};

use thiserror::Error;

use crate::cell::{Cell, CellHeader};
use crate::crypto::relay::RelayId;
use crate::util::{print_hex, print_list};

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

/// Unspecified symmetric cipher error.
#[derive(Error)]
#[error("cipher error")]
pub struct CipherError;

display2debug! {CipherError}

impl From<cipher::StreamCipherError> for CipherError {
    fn from(_: cipher::StreamCipherError) -> Self {
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

    pub fn with_cell(cell: &Cell) -> Self {
        Self {
            header: Some(CellHeader {
                circuit: cell.circuit,
                command: cell.command,
            }),
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

impl From<ed25519_dalek::SignatureError> for CertVerifyError {
    fn from(_: ed25519_dalek::SignatureError) -> Self {
        Self
    }
}

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

/// Cell digest mismatch.
#[derive(Error)]
#[error("cell digest mismatch")]
pub struct CellDigestError;

display2debug! {CellDigestError}

/// Generic circuit handshake error.
#[derive(Default)]
pub struct CircuitHandshakeError(pub(crate) CircuitHandshakeErrorInner);

impl Display for CircuitHandshakeError {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        write!(f, "error in circuit handshake: {}", self.0)
    }
}

impl Error for CircuitHandshakeError {}

display2debug! {CircuitHandshakeError}

#[derive(Error, Default)]
pub(crate) enum CircuitHandshakeErrorInner {
    #[error("cell format error")]
    CellFormatError,
    #[error("cryptographic operation error")]
    CryptoError,
    #[error("authentication error")]
    AuthError,
    #[error("relay mismatch (expected {})", print_hex(.0))]
    ServerRelayIdMismatch(RelayId),
    #[error("onion key not found or expired")]
    ServerOnionKeyNotFound,
    #[error("unknown error")]
    #[default]
    Other,
}

display2debug! {CircuitHandshakeErrorInner}

impl From<CircuitHandshakeErrorInner> for CircuitHandshakeError {
    fn from(v: CircuitHandshakeErrorInner) -> Self {
        Self(v)
    }
}

impl From<cipher::InvalidLength> for CircuitHandshakeError {
    fn from(_: cipher::InvalidLength) -> Self {
        Self(CircuitHandshakeErrorInner::CryptoError)
    }
}

impl From<cipher::StreamCipherError> for CircuitHandshakeError {
    fn from(_: cipher::StreamCipherError) -> Self {
        Self(CircuitHandshakeErrorInner::CryptoError)
    }
}

impl From<hkdf::InvalidLength> for CircuitHandshakeError {
    fn from(_: hkdf::InvalidLength) -> Self {
        Self(CircuitHandshakeErrorInner::CryptoError)
    }
}

impl CircuitHandshakeError {
    pub fn from_ct(v: subtle::Choice) -> Result<(), Self> {
        if v.into() {
            Ok(())
        } else {
            Err(Self(CircuitHandshakeErrorInner::AuthError))
        }
    }

    pub const fn crypto() -> Self {
        Self(CircuitHandshakeErrorInner::CryptoError)
    }
}

/// Channel is closed.
#[derive(Error)]
#[error("channel is closed")]
pub struct ChannelClosedError;

display2debug! {ChannelClosedError}

/// Circuit is closed.
#[derive(Error)]
#[error("circuit is closed")]
pub struct CircuitClosedError;

display2debug! {CircuitClosedError}

/// Cell length overflow.
#[derive(Error)]
#[error("cell length overflows")]
pub struct CellLengthOverflowError;

display2debug! {CellLengthOverflowError}

/// Cell length overflow.
#[derive(Error)]
#[error("too many signatures")]
pub struct TooManySignaturesError;

display2debug! {TooManySignaturesError}

/// Network parameter parsing error.
#[derive(Error)]
#[non_exhaustive]
pub enum NetparamParseError {
    #[error("no equals character found")]
    NoEquals,
    #[error("keyword is empty")]
    NoKeyword,
}

display2debug! {NetparamParseError}
