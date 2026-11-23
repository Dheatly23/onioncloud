//! Tor certificate format parsing and validation.
//!
//! See also:
//! - [Ed25519 certificate format](https://spec.torproject.org/cert-spec.html).

mod ed;

pub use ed::*;
