//! Defines RSA → Ed25519 cross-certificate.

use std::time::{Duration, SystemTime};

use digest::Digest;
use rsa::pkcs1v15::Pkcs1v15Sign;
use zerocopy::byteorder::big_endian::U32;
use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout, Unaligned};

use crate::error::{CertFormatError, CertValidateError};
use crate::{EdPublicKey, RsaPublicKey, Sha256};

#[derive(FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned)]
#[repr(C)]
struct RsaCertHead {
    key: EdPublicKey,
    exp: U32,
}

#[derive(FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned)]
#[repr(C)]
struct RsaCertData {
    head: RsaCertHead,
    siglen: u8,
    sig: [u8],
}

static PREFIX: &[u8] = b"Tor TLS RSA/Ed25519 cross-certificate";

/// RSA cross-certificate.
///
/// # Validation Procedure
///
/// 1. Cast from byte slice using [`TryFrom`].
/// 2. Check expiry and expiry.
/// 3. Iterate through all extensions.
/// 4. Verify signature with [`verify`].
///
/// # Example
///
/// ```no_run
/// # use onioncloud_ll_crypto::certs::rsa::RsaCert;
/// # use ed25519_dalek::VerifyingKey;
/// fn verify_cert(bytes: &[u8], pk: &VerifyingKey) {
///     // Cast
///     let mut cert = EdCert::try_from(bytes).unwrap();
///
///     // Check extensions
///     for ext in &mut cert {
///         let ext = ext.unwrap();
///
///         // Do the processing ...
///
///         if ext.flags().is_required() {
///             panic!("extension is required but unrecognized!");
///         }
///     }
///
///     // Verify
///     cert.verify(pk).unwrap();
/// }
/// ```
#[derive(Clone)]
pub struct RsaCert<'a> {
    msg: &'a RsaCertData,
}

impl<'a> TryFrom<&'a [u8]> for RsaCert<'a> {
    type Error = CertFormatError;

    #[inline]
    fn try_from(b: &'a [u8]) -> Result<Self, Self::Error> {
        let msg = RsaCertData::ref_from_bytes(b).map_err(|_| CertFormatError)?;
        if msg.siglen as usize != msg.sig.len() {
            return Err(CertFormatError);
        }
        Ok(Self { msg })
    }
}

impl<'a> RsaCert<'a> {
    /// Gets certified key.
    #[inline]
    #[must_use]
    pub fn key(&self) -> &'a EdPublicKey {
        &self.msg.head.key
    }

    /// Gets expiration time, in hours since epoch.
    #[inline]
    #[must_use]
    pub fn expiry(&self) -> u32 {
        self.msg.head.exp.get()
    }

    /// Gets expiration time.
    #[inline]
    #[must_use]
    pub fn expiry_time(&self) -> SystemTime {
        SystemTime::UNIX_EPOCH + Duration::from_hours(self.expiry().into())
    }

    /// Verifies certificate.
    ///
    /// **NOTE:** It **DOES NOT** perform expiry validation.
    ///
    /// # Errors
    ///
    /// Returns error if signature verification fails.
    ///
    /// # Panics
    ///
    /// Panics if it's format is invalid.
    #[inline]
    pub fn verify(&self, pk: &RsaPublicKey) -> Result<(), CertValidateError> {
        debug_assert_eq!(self.msg.siglen as usize, self.msg.sig.len());
        let mut hasher = Sha256::new();
        hasher.update(PREFIX);
        hasher.update(self.msg.head.as_bytes());
        pk.verify(
            Pkcs1v15Sign::new_unprefixed(),
            &hasher.finalize(),
            &self.msg.sig,
        )
        .map_err(|_| CertValidateError)
    }
}
