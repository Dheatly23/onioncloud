//! Lowlevel crypto operations.

pub mod certs;
pub mod error;

/// Ed25519 public key.
pub type Ed25519PublicKey = [u8; 32];
