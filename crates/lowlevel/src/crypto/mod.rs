pub mod cert;
pub mod relay;
pub(crate) mod tls;

/// Symmetric cipher used in Tor.
pub type Cipher = ctr::Ctr128BE<aes::Aes128>;

/// Ed25519 public key (unchecked).
pub type EdPublicKey = [u8; 32];

/// Ed25519 signature.
pub type EdSignature = [u8; 64];

/// RSA public key.
pub type RsaPublicKey = rsa::RsaPublicKey;
