//! Lowlevel crypto operations.

pub mod certs;
pub mod error;
#[cfg(any(test, feature = "test-keys"))]
pub mod test_keys;

#[doc(no_inline)]
pub use digest::Digest;
#[doc(no_inline)]
pub use ed25519_dalek::{SigningKey as EdSigningKey, VerifyingKey as EdVerifyingKey};
#[doc(no_inline)]
pub use rsa::{PrivateKey as RsaPrivateKey, PublicKey as RsaPublicKey};
#[doc(no_inline)]
pub use sha1::Sha1;
#[doc(no_inline)]
pub use sha2::Sha256;
#[doc(no_inline)]
pub use signature::{Signer, Verifier};

/// Ed25519 public key.
pub type EdPublicKey = [u8; 32];
