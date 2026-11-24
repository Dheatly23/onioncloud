use onioncloud_ll_crypto::error::CertFormatError;
use onioncloud_ll_crypto::{Digest, RsaPublicKey, Sha1};
use pkcs1::EncodeRsaPublicKey;
use pkcs8::DecodePublicKey;
use rustls_pki_types::CertificateDer;
use tracing::instrument;
use webpki::EndEntityCert;

use crate::utils::RelayId;

/// Extract RSA public key from X.509 certificate.
///
/// Returns a [`RsaPublicKey`] and it's corresponding [`RelayId`].
///
/// **NOTE:** Does not perform any cryptographic verification of certificate signature.
///
/// # Errors
///
/// Returns error if certificate format is invalid.
#[cfg(feature = "crypto")]
#[instrument(level = "debug")]
pub fn extract_rsa_from_x509(data: &[u8]) -> Result<(RsaPublicKey, RelayId), CertFormatError> {
    let spki = EndEntityCert::try_from(&CertificateDer::from_slice(data))
        .map_err(|_| CertFormatError::default())?
        .subject_public_key_info();
    let pk = RsaPublicKey::from_public_key_der(&spki).map_err(|_| CertFormatError::default())?;
    drop(spki);
    let b = pk.to_pkcs1_der().map_err(|_| CertFormatError::default())?;
    let id = Sha1::digest(b.as_bytes());
    Ok((pk, id.into()))
}
