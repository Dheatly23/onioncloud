//! Lowlevel crypto operations.

pub mod certs;
pub mod error;
#[cfg(feature = "test-keys")]
pub mod test_keys;

/// Ed25519 public key.
pub type Ed25519PublicKey = [u8; 32];
