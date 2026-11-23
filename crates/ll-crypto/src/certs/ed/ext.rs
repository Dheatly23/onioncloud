//! Ed25519 certificate extensions.

use std::mem::size_of;

use zerocopy::byteorder::big_endian::U16;
use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout, Unaligned, transmute};

use super::EdCertExt;
use crate::Ed25519PublicKey;
use crate::error::CertFormatError;

#[derive(FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned)]
#[repr(C)]
struct EdCertExtData {
    len: U16,
    ty: u8,
    flags: u8,
}

/// Helper trait for casting from [`EdCertExt`].
pub trait TryFromExt<'a>: Sized {
    /// Try to cast from [`EdCertExt`].
    ///
    /// # Errors
    ///
    /// Returns error if extension payload format is invalid.
    /// If extension type does not match, it should return `Ok(None)` instead.
    fn try_from_ext(ext: &EdCertExt<'a>) -> Result<Option<Self>, CertFormatError>;
}

/// Embedded public key that signs this certificate.
#[derive(Clone)]
pub struct SignedWithEd25519Key<'a>(&'a Ed25519PublicKey);

impl<'a> TryFromExt<'a> for SignedWithEd25519Key<'a> {
    fn try_from_ext(ext: &EdCertExt<'a>) -> Result<Option<Self>, CertFormatError> {
        if ext.ty() != Self::ID {
            return Ok(None);
        }
        match <&Ed25519PublicKey>::try_from(ext.data()) {
            Ok(v) => Ok(Some(Self(v))),
            Err(_) => Err(CertFormatError),
        }
    }
}

impl<'a> SignedWithEd25519Key<'a> {
    const ID: u8 = 4;

    /// Creates new [`SignedWithEd25519Key`] from [`Ed25519PublicKey`].
    #[inline]
    #[must_use]
    pub fn from_pk(key: &'a Ed25519PublicKey) -> Self {
        Self(key)
    }

    /// Gets embedded public key.
    #[inline]
    #[must_use]
    pub fn key(&self) -> &'a Ed25519PublicKey {
        self.0
    }

    /// Writes bytes representation into container.
    #[inline]
    pub fn write_bytes<V: Extend<u8>>(&self, container: &mut V) {
        let head: [u8; const { size_of::<EdCertExtData>() }] = transmute!(EdCertExtData {
            len: 32.into(),
            ty: Self::ID,
            flags: 0,
        });
        container.extend(head);
        container.extend(*self.0);
    }
}
