pub mod cert;
pub mod onion;
pub mod relay;
pub(crate) mod tls;

use curve25519_dalek::edwards::EdwardsPoint;
use curve25519_dalek::montgomery::MontgomeryPoint;

/// Symmetric cipher used in Tor (128-bit).
pub type Cipher128 = ctr::Ctr128BE<aes::Aes128>;

/// Symmetric cipher used in Tor (256-bit).
pub type Cipher256 = ctr::Ctr128BE<aes::Aes256>;

/// Ed25519 public key (unchecked).
pub type EdPublicKey = [u8; 32];

/// Ed25519 signature.
pub type EdSignature = [u8; 64];

/// RSA public key.
pub type RsaPublicKey = rsa::RsaPublicKey;

/// SHA1 hash output.
pub type Sha1Output = [u8; 20];

/// SHA256 hash output.
pub type Sha256Output = [u8; 32];

/// 128-bit symmetric cipher key.
pub type CipherKey128 = [u8; 16];

/// 256-bit symmetric cipher key.
pub type CipherKey256 = [u8; 32];

/// Try to convert montgomery point to edwards point.
///
/// Returns [`None`] if point is invalid.
///
/// See also: [spec](https://spec.torproject.org/dir-spec/converting-to-ed25519.html).
pub fn montgomery_to_edwards(point: MontgomeryPoint, sign: bool) -> Option<EdwardsPoint> {
    point.to_edwards(if sign { 1 } else { 0 })
}
