//! Implements certificate [specification](spec).
//!
//! [spec]: https://spec.torproject.org/cert-spec.html#ed-certs

use std::time::{Duration, SystemTime};

use digest::Digest;
use ed25519_dalek::VerifyingKey;
use rsa::pkcs1::EncodeRsaPublicKey;
use rsa::pkcs1v15::Pkcs1v15Sign;
use rsa::pkcs8::DecodePublicKey;
use rustls::pki_types::CertificateDer;
use sha1::Sha1;
use sha2::Sha256;
use webpki::EndEntityCert;
use zerocopy::byteorder::big_endian::{U16, U32};
use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout, Unaligned};

use super::relay::RelayId;
use super::{EdPublicKey, EdSignature, RsaPublicKey};
use crate::errors;

/// Verifies expiry time is not past.
fn verify_exp(t: u32) -> bool {
    let Some(t) = SystemTime::UNIX_EPOCH.checked_add(Duration::from_secs(t as u64 * 3600)) else {
        return true;
    };
    t >= SystemTime::now()
}

/// Header for ed25519 certificate.
#[derive(Debug, Clone, Copy, FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned)]
#[repr(C)]
pub struct EdCertHeader {
    /// Cerificate type.
    pub cert_ty: u8,

    /// Expiration date in terms of _hours_ since epoch.
    pub expiry: U32,

    /// Certificate key type.
    pub key_ty: u8,

    /// Certificate key.
    pub key: [u8; 32],

    /// Number of extensions.
    pub n_ext: u8,
}

impl EdCertHeader {
    /// Checks certificate type.
    ///
    /// # Parameters
    /// - `cert_ty` : Certificate type.
    /// - `key_ty` : Certificate key type.
    ///
    /// **NOTE: Due to Tor bug, certificate key type may be 1 regardless of actual expected key type.
    /// So key type of 1 will be accepted regardless of expected key type.**
    #[inline(always)]
    pub const fn check_type(
        &self,
        cert_ty: u8,
        key_ty: u8,
    ) -> Result<&Self, errors::CertTypeError> {
        if self.cert_ty != cert_ty {
            Err(errors::CertTypeError(errors::CertTypeInner::CertTy {
                expect: cert_ty,
                actual: self.cert_ty,
            }))
        } else if self.key_ty != 1 && self.key_ty != key_ty {
            Err(errors::CertTypeError(errors::CertTypeInner::KeyTy {
                expect: key_ty,
                actual: self.key_ty,
            }))
        } else {
            Ok(self)
        }
    }
}

/// Header for ed25519 certificate extension.
#[derive(Debug, Clone, Copy, FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned)]
#[repr(C)]
pub struct EdCertExtHeader {
    /// Extension length.
    pub len: U16,

    /// Extension type.
    pub ty: u8,

    /// Extension flags.
    pub flags: u8,
}

/// Unverified ed25519 certificate.
///
/// # Example
///
/// ```no_run
/// use onioncloud_lowlevel::crypto::cert::UnverifiedEdCert;
///
/// // Parse unverified certificate
/// let unverified = UnverifiedEdCert::new(&[]).unwrap();
///
/// // Verify certificate
/// unverified.verify(&Default::default()).unwrap();
/// ```
#[derive(Debug)]
pub struct UnverifiedEdCert<'a> {
    data: &'a [u8],
    pub header: &'a EdCertHeader,

    i: u8,
    rest: &'a [u8],
}

impl<'a> UnverifiedEdCert<'a> {
    /// Parse ed25519 certificate.
    pub fn new(data: &'a [u8]) -> Result<Self, errors::CertFormatError> {
        // Check certificate version
        // TODO: Handle multiple versions?
        let [1, rest @ ..] = data else {
            return Err(errors::CertFormatError);
        };
        let (header, rest) =
            EdCertHeader::ref_from_prefix(rest).map_err(|_| errors::CertFormatError)?;

        Ok(Self {
            data,
            header,
            i: header.n_ext,
            rest,
        })
    }

    /// Process next cerificate extension.
    ///
    /// **NOTE: All extensions must be processed before verifying!**
    pub fn next_ext(
        &mut self,
    ) -> Option<Result<(&'a EdCertExtHeader, &'a [u8]), errors::CertFormatError>> {
        self.i = self.i.checked_sub(1)?;

        let Ok((header, rest)) = EdCertExtHeader::ref_from_prefix(self.rest) else {
            return Some(Err(errors::CertFormatError));
        };
        let Ok((data, rest)) = <[u8]>::ref_from_prefix_with_elems(rest, header.len.get().into())
        else {
            return Some(Err(errors::CertFormatError));
        };
        self.rest = rest;
        Some(Ok((header, data)))
    }

    /// Verifies certificate using public key.
    ///
    /// **NOTE: All extensions must be processed before verifying!**
    pub fn verify(self, pk: &EdPublicKey) -> Result<(), errors::CertVerifyError> {
        let sig = EdSignature::ref_from_bytes(self.rest).map_err(|_| errors::CertVerifyError)?;

        // SAFETY: sig is within data.
        let msg = unsafe {
            self.data
                .get_unchecked(..(sig as *const EdSignature).byte_offset_from(self.data) as usize)
        };

        VerifyingKey::from_bytes(pk)?.verify_strict(msg, &sig.into())?;
        if !verify_exp(self.header.expiry.get()) {
            return Err(errors::CertVerifyError);
        }
        Ok(())
    }
}

/// Header for RSA certificate.
#[derive(Debug, Clone, Copy, FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned)]
#[repr(C)]
pub struct RsaCertHeader {
    /// Ed25519 public key.
    pub key: EdPublicKey,

    /// Expiration date in terms of _hours_ since epoch.
    pub expiry: U32,
}

/// Unverified RSA certificate.
///
/// Use [`UnverifiedRsaCert::verify`] to verify it's signature.
///
/// # Example
///
/// ```no_run
/// use onioncloud_lowlevel::crypto::cert::{extract_rsa_from_x509, UnverifiedRsaCert};
///
/// // Parse unverified certificate
/// let unverified = UnverifiedRsaCert::new(&[]).unwrap();
///
/// // Get RSA public key from somewhere
/// let key = extract_rsa_from_x509(&[]).unwrap().0;
/// unverified.verify(&key).unwrap();
/// ```
#[derive(Debug, FromBytes, KnownLayout, Immutable, Unaligned)]
#[repr(C)]
pub struct UnverifiedRsaCert {
    /// Certificate header.
    ///
    /// **NOTE: Do not use this until certificate is verified!**
    pub header: RsaCertHeader,

    /// Signature length.
    pub len: u8,

    /// Certificate signature.
    pub sig: [u8],
}

impl UnverifiedRsaCert {
    const PREFIX: &[u8] = b"Tor TLS RSA/Ed25519 cross-certificate";

    /// Parse RSA certificate.
    pub fn new(data: &[u8]) -> Result<&Self, errors::CertFormatError> {
        let ret = Self::ref_from_bytes(data).map_err(|_| errors::CertFormatError)?;
        if ret.sig.len() != usize::from(ret.len) {
            return Err(errors::CertFormatError);
        }
        Ok(ret)
    }

    /// Verify certificate.
    ///
    /// Returns verified certificate header.
    pub fn verify(&self, pk: &RsaPublicKey) -> Result<&RsaCertHeader, errors::CertVerifyError> {
        let mut hasher = Sha256::new();
        hasher.update(Self::PREFIX);
        hasher.update(self.header.as_bytes());
        match pk.verify(
            Pkcs1v15Sign::new_unprefixed(),
            &hasher.finalize(),
            &self.sig,
        ) {
            Ok(()) if verify_exp(self.header.expiry.get()) => Ok(&self.header),
            _ => Err(errors::CertVerifyError),
        }
    }
}

/// Extract RSA public key from X.509 certificate.
///
/// Returns a [`RsaPublicKey`] and it's corresponding [`RelayId`].
///
/// **NOTE: Does not perform any cryptographic verification of certificate signature.**
pub fn extract_rsa_from_x509(
    data: &[u8],
) -> Result<(RsaPublicKey, RelayId), errors::CertFormatError> {
    let spki = EndEntityCert::try_from(&CertificateDer::from_slice(data))
        .map_err(|_| errors::CertFormatError)?
        .subject_public_key_info();
    let pk = RsaPublicKey::from_public_key_der(&spki).map_err(|_| errors::CertFormatError)?;
    let id: RelayId = Sha1::digest(
        pk.to_pkcs1_der()
            .map_err(|_| errors::CertFormatError)?
            .as_bytes(),
    )
    .into();
    Ok((pk, id))
}

#[cfg(test)]
mod tests {
    use super::*;

    use ed25519_dalek::{Signer, SigningKey};
    use rand::prelude::*;
    use rsa::RsaPrivateKey;
    use rsa::pkcs8::{EncodePrivateKey, LineEnding};

    use crate::util::print_hex;

    #[test]
    fn test_rsa_cert() {
        let mut rng = ThreadRng::default();
        let private_key = RsaPrivateKey::new(&mut rng, 1024).unwrap();
        println!(
            "Private key:\n{}",
            *private_key.to_pkcs8_pem(LineEnding::LF).unwrap()
        );
        let public_key = private_key.to_public_key();

        // Sign
        let key = rng.r#gen::<EdPublicKey>();
        let cert = {
            let cert = RsaCertHeader {
                key,
                expiry: u32::MAX.into(),
            };
            let mut hasher = Sha256::new();
            hasher.update(UnverifiedRsaCert::PREFIX);
            hasher.update(cert.as_bytes());
            let sig = private_key
                .sign(Pkcs1v15Sign::new_unprefixed(), &hasher.finalize())
                .unwrap();

            let mut v = Vec::with_capacity(cert.as_bytes().len() + 1 + sig.len());
            v.extend_from_slice(cert.as_bytes());
            v.push(sig.len() as u8);
            v.extend(sig);
            v
        };
        println!("Cert: {}", print_hex(&cert));

        // Verify
        let cert = UnverifiedRsaCert::new(&cert)
            .unwrap()
            .verify(&public_key)
            .unwrap();
        assert_eq!(cert.key, key);
    }

    #[test]
    fn test_ed_cert() {
        let mut rng = ThreadRng::default();
        let private_key = SigningKey::generate(&mut rng);
        println!("Private key:{}", print_hex(private_key.as_bytes()));
        let public_key = private_key.verifying_key();

        // Sign
        let key = rng.r#gen::<EdPublicKey>();
        let cert = {
            let cert = EdCertHeader {
                cert_ty: 0,
                key_ty: 0,
                key,
                expiry: u32::MAX.into(),
                n_ext: 0,
            };

            let mut v = Vec::with_capacity(1 + cert.as_bytes().len() + 64);
            v.push(1);
            v.extend_from_slice(cert.as_bytes());

            let sig = private_key.sign(&v).to_bytes();
            v.extend(sig);
            v
        };
        println!("Cert: {}", print_hex(&cert));

        // Verify
        let mut unverified = UnverifiedEdCert::new(&cert).unwrap();
        assert_eq!(unverified.header.key, key);
        while let Some((header, data)) = unverified.next_ext().transpose().unwrap() {
            println!("extension header: {header:?} {}", print_hex(data));
        }
        unverified
            .verify(public_key.as_ref().try_into().unwrap())
            .unwrap();
    }
}
