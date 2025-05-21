pub mod cert;
pub mod onion;
pub mod relay;
pub(crate) mod tls;

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
