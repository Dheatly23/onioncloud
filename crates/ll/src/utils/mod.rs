//! Miscellaneous utility types.

#[cfg(feature = "cell")]
pub mod cell_rw;
#[cfg(feature = "crypto")]
mod extract_rsa;
mod versions;

#[cfg(feature = "crypto")]
pub use extract_rsa::*;
pub use versions::*;

/// Relay ID/fingerprint.
pub type RelayId = [u8; 20];

/// Relay Ed25519 public key.
///
/// Used in conjunction with [`RelayId`].
pub type RelayIdEd = [u8; 32];
