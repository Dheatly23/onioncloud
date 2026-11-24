//! Defines Ed25519 certificate format.

pub mod ext;

use std::borrow::Borrow;
use std::cmp::PartialEq;
use std::hash::{Hash, Hasher};
use std::mem::size_of_val;
use std::ops::{BitAnd, BitAndAssign, BitOr, BitOrAssign};
use std::time::{Duration, SystemTime};

use ed25519_dalek::{Signature, VerifyingKey};
use signature::Verifier;
use zerocopy::byteorder::big_endian::{U16, U32};
use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout, SplitAt, Unaligned};

use crate::EdPublicKey;
use crate::error::{CertFormatError, CertValidateError};

#[derive(FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned, SplitAt)]
#[repr(C)]
struct EdCertHead {
    version: u8,
    ty: u8,
    exp: U32,
    kty: u8,
    key: EdPublicKey,
    n_ext: u8,
    rest: [u8],
}

#[derive(FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned, SplitAt)]
#[repr(C)]
struct EdCertExtData {
    len: U16,
    ty: u8,
    flags: u8,
    rest: [u8],
}

type EdCertTail = [u8; 64];

/// Ed25519 preprocessed certificate type.
///
/// # Validation Procedure
///
/// 1. Cast from byte slice using [`TryFrom`].
/// 2. Check certificate type and certificate key type.
/// 3. Iterate through all extensions.
/// 4. Verify signature with [`verify`].
///
/// # Example
///
/// ```no_run
/// # use onioncloud_ll_crypto::certs::ed::EdCert;
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
pub struct EdCert<'a> {
    msg: &'a EdCertHead,
    n: u8,
    ix: usize,
}

impl<'a> TryFrom<&'a [u8]> for EdCert<'a> {
    type Error = CertFormatError;

    #[inline]
    fn try_from(b: &'a [u8]) -> Result<Self, Self::Error> {
        let msg = EdCertHead::ref_from_bytes(b).map_err(|_| CertFormatError)?;
        if msg.version != 1 {
            return Err(CertFormatError);
        }
        Ok(Self {
            n: msg.n_ext,
            ix: 0,
            msg,
        })
    }
}

impl<'a> Iterator for EdCert<'a> {
    type Item = Result<EdCertExt<'a>, CertFormatError>;

    #[inline]
    fn next(&mut self) -> Option<Self::Item> {
        if self.ix == usize::MAX {
            return None;
        } else if self.n == 0 {
            if EdCertTail::ref_from_bytes(&self.msg.rest[self.ix..]).is_ok() {
                return None;
            }
            self.ix = usize::MAX;
            return Some(Err(CertFormatError));
        }

        let ret = self.next_ext();
        if ret.is_err() {
            self.ix = usize::MAX;
        }
        self.n -= 1;
        Some(ret)
    }

    #[inline]
    fn size_hint(&self) -> (usize, Option<usize>) {
        if self.ix == usize::MAX {
            (0, Some(0))
        } else if self.n == 0 {
            (0, Some(1))
        } else {
            (1, Some(usize::from(self.n) + 1))
        }
    }
}

impl<'a> EdCert<'a> {
    /// Gets certificate type.
    #[inline]
    #[must_use]
    pub fn cert_ty(&self) -> EdCertType {
        EdCertType(self.msg.ty)
    }

    /// Gets certificate key type.
    #[inline]
    #[must_use]
    pub fn key_ty(&self) -> EdCertKeyType {
        EdCertKeyType(self.msg.kty)
    }

    /// Gets expiration time, in hours since epoch.
    #[inline]
    #[must_use]
    pub fn expiry(&self) -> u32 {
        self.msg.exp.get()
    }

    /// Gets expiration time.
    #[inline]
    #[must_use]
    pub fn expiry_time(&self) -> SystemTime {
        SystemTime::UNIX_EPOCH + Duration::from_hours(self.expiry().into())
    }

    /// Gets cerificate key material.
    #[inline]
    #[must_use]
    pub fn key(&self) -> &'a EdPublicKey {
        &self.msg.key
    }

    /// Verifies certificate.
    ///
    /// **MUST BE** done after exhausting iteration and if it did not return error.
    ///
    /// **NOTE:** It **DOES NOT** perform expiry validation.
    ///
    /// # Errors
    ///
    /// Returns error if signature verification fails.
    ///
    /// # Panics
    ///
    /// Panics if there are extension to be parsed or it's format is invalid.
    #[inline]
    pub fn verify(&self, pk: &VerifyingKey) -> Result<(), CertValidateError> {
        assert!(
            self.ix != usize::MAX && self.n == 0,
            "invalid certificate format"
        );
        let Some(s) = self.msg.split_at(self.ix) else {
            panic!("invalid certificate format");
        };
        let (head, tail) = s.via_immutable();
        let Ok(tail) = EdCertTail::ref_from_bytes(tail) else {
            panic!("invalid certificate format");
        };
        pk.verify(head.as_bytes(), &Signature::from_bytes(tail))
            .map_err(CertValidateError::from)
    }

    #[inline]
    fn next_ext(&mut self) -> Result<EdCertExt<'a>, CertFormatError> {
        let msg = EdCertExtData::ref_from_bytes(&self.msg.rest[self.ix..])
            .map_err(|_| CertFormatError)?;
        let len = usize::from(msg.len.get());
        let msg = msg.split_at(len).ok_or(CertFormatError)?.via_immutable().0;
        self.ix += size_of_val(msg);
        Ok(EdCertExt(msg))
    }
}

/// Ed25519 certificate extension type.
#[derive(Clone)]
pub struct EdCertExt<'a>(&'a EdCertExtData);

impl<'a> EdCertExt<'a> {
    /// Gets extension type.
    #[inline]
    #[must_use]
    pub fn ty(&self) -> u8 {
        self.0.ty
    }

    /// Gets extension flags.
    #[inline]
    #[must_use]
    pub fn flags(&self) -> EdCertExtFlags {
        EdCertExtFlags(self.0.flags)
    }

    /// Gets extension data.
    #[inline]
    #[must_use]
    pub fn data(&self) -> &'a [u8] {
        &self.0.rest
    }
}

/// Ed25519 certificate type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EdCertType(pub u8);

impl Hash for EdCertType {
    #[inline]
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.0.hash(state);
    }
}

impl Borrow<u8> for EdCertType {
    #[inline]
    fn borrow(&self) -> &u8 {
        &self.0
    }
}

impl From<EdCertType> for u8 {
    #[inline]
    fn from(v: EdCertType) -> u8 {
        v.0
    }
}

impl PartialEq<u8> for EdCertType {
    #[inline]
    fn eq(&self, other: &u8) -> bool {
        self.0 == *other
    }
}

impl EdCertType {
    /// Relay signing key signed by identity key.
    pub const IDENTITY_V_SIGNING: Self = Self(4);
    /// Relay (hashed) TLS certificate signed by signing key.
    pub const SIGNING_V_TLS_CERT: Self = Self(5);
    /// Relay link authentication key signed by signing key.
    pub const SIGNING_V_LINK_AUTH: Self = Self(6);
    /// Onion service signing key signed by blinded public key.
    pub const BLINDED_ID_V_SIGNING: Self = Self(8);
    /// Onion service introduction point authentication key signed by signing key.
    pub const HS_IP_V_SIGNING: Self = Self(9);
    /// Relay identity key signed by ntor key.
    pub const NTOR_CC_IDENTITY: Self = Self(10);
    /// Onion service introduction point encryption key signed by signing key.
    pub const HS_IP_CC_SIGNING: Self = Self(11);
    /// Relay identity key signed by family key.
    pub const FAMILY_V_IDENTITY: Self = Self(12);
}

/// Ed25519 certificate key type.
///
/// **NOTE:** Some Tor versions accidentally sets this field to 1.
/// Users _must_ accept [`Self::ED25519`] as valid and uses [`EdCertType`] to find it's actual key type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EdCertKeyType(pub u8);

impl Hash for EdCertKeyType {
    #[inline]
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.0.hash(state);
    }
}

impl Borrow<u8> for EdCertKeyType {
    #[inline]
    fn borrow(&self) -> &u8 {
        &self.0
    }
}

impl From<EdCertKeyType> for u8 {
    #[inline]
    fn from(v: EdCertKeyType) -> u8 {
        v.0
    }
}

impl PartialEq<u8> for EdCertKeyType {
    #[inline]
    fn eq(&self, other: &u8) -> bool {
        self.0 == *other
    }
}

impl EdCertKeyType {
    /// Ed25519 public key.
    pub const ED25519: Self = Self(1);
    /// SHA256 digest of RSA public key in DER encoding.
    pub const SHA256_RSA: Self = Self(2);
    /// SHA256 digest of X.509 certificate.
    pub const SHA256_X509: Self = Self(3);
}

/// Ed25519 certificate extension flags.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EdCertExtFlags(pub u8);

impl Hash for EdCertExtFlags {
    #[inline]
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.0.hash(state);
    }
}

impl Borrow<u8> for EdCertExtFlags {
    #[inline]
    fn borrow(&self) -> &u8 {
        &self.0
    }
}

impl From<EdCertExtFlags> for u8 {
    #[inline]
    fn from(v: EdCertExtFlags) -> u8 {
        v.0
    }
}

impl PartialEq<u8> for EdCertExtFlags {
    #[inline]
    fn eq(&self, other: &u8) -> bool {
        self.0 == *other
    }
}

impl BitOr for EdCertExtFlags {
    type Output = Self;

    #[inline]
    fn bitor(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }
}

impl BitOrAssign for EdCertExtFlags {
    #[inline]
    fn bitor_assign(&mut self, other: Self) {
        self.0 |= other.0;
    }
}

impl BitAnd for EdCertExtFlags {
    type Output = Self;

    #[inline]
    fn bitand(self, other: Self) -> Self {
        Self(self.0 & other.0)
    }
}

impl BitAndAssign for EdCertExtFlags {
    #[inline]
    fn bitand_assign(&mut self, other: Self) {
        self.0 &= other.0;
    }
}

impl EdCertExtFlags {
    /// Indicates extension is required to be processed.
    pub const REQUIRED: Self = Self(1);

    /// Checks if extension is required to be processed.
    ///
    /// Equivalent to `flags & EdCertExtFlags::REQUIRED != 0`
    #[inline]
    #[must_use]
    pub fn is_required(self) -> bool {
        self & Self::REQUIRED != 0
    }
}

#[cfg(all(test, feature = "test-keys"))]
mod tests {
    use super::*;

    use test_log::test;
    use tracing::{info, instrument};

    use signature::Signer;

    use crate::certs::ed::ext::{SignedWithEd25519Key, TryFromExt};
    use crate::test_keys::test_ed25519_keypair;

    #[derive(FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned)]
    #[repr(C)]
    struct EdCertHeadOnly {
        version: u8,
        ty: u8,
        exp: U32,
        kty: u8,
        key: EdPublicKey,
        n_ext: u8,
    }

    #[test]
    fn test_cert_validation() {
        #[instrument]
        fn test() {
            // SAFETY: We're in unit test.
            let (sk, pk) = unsafe { test_ed25519_keypair() };

            info!("creating certificate");
            let mut buf = Vec::new();
            buf.extend_from_slice(
                EdCertHeadOnly {
                    version: 1,
                    ty: 4,
                    exp: 0.into(),
                    kty: 1,
                    key: [123; 32],
                    n_ext: 1,
                }
                .as_bytes(),
            );
            SignedWithEd25519Key::from_pk(pk.as_bytes()).write_bytes(&mut buf);
            buf.extend_from_slice(&sk.sign(&buf).to_bytes());

            info!("validating certificate");

            let mut cert = EdCert::try_from(&buf[..]).unwrap();

            assert_eq!(cert.cert_ty(), EdCertType::IDENTITY_V_SIGNING);
            assert_eq!(cert.key_ty(), EdCertKeyType::ED25519);
            assert_eq!(cert.expiry(), 0);
            assert_eq!(*cert.key(), [123; 32]);

            info!("validating extensions");

            for ext in &mut cert {
                let ext = ext.unwrap();
                if let Some(ext) = SignedWithEd25519Key::try_from_ext(&ext).unwrap() {
                    assert_eq!(ext.key(), pk.as_bytes());
                } else {
                    panic!("unknown extension {}", ext.ty());
                }
            }

            info!("validating signature");

            cert.verify(&pk).unwrap();
        }

        test();
    }
}
