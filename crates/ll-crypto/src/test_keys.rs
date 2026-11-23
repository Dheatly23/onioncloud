//! Test keys used for consistency.
//!
//! **⚠️⚠️⚠️ DO NOT USE IN PRODUCTION! ⚠️⚠️⚠️**
//!
//! All functions are marked unsafe to reduce misuse.
//! While it's memory-safe, using unsafe made it very obvious in production code.
#![expect(clippy::missing_safety_doc)]

use ed25519_dalek::{SigningKey, VerifyingKey};

/// Gets test Ed25519 keypair.
#[must_use]
pub unsafe fn test_ed25519_keypair() -> (SigningKey, VerifyingKey) {
    static PRIVATE_KEY: [u8; 32] = [
        0xe1, 0x10, 0xfe, 0xa6, 0x9b, 0xfc, 0x56, 0x9b, 0x73, 0xa6, 0x86, 0x75, 0x9c, 0xa3, 0x1b,
        0x1a, 0x37, 0xcf, 0xbb, 0xa7, 0xce, 0xbb, 0x19, 0xe3, 0x71, 0x41, 0x42, 0x0f, 0x40, 0x26,
        0x34, 0x2f,
    ];

    let sk = SigningKey::from_bytes(&PRIVATE_KEY);
    let pk = sk.verifying_key();
    (sk, pk)
}
