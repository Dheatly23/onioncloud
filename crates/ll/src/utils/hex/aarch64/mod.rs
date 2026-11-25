//! aarch64 SIMD accelerated implementation.

pub mod neon;

use std::arch::is_aarch64_feature_detected;

use super::{FmtHex, usimd};

#[inline]
pub fn dispatch() -> &'static dyn FmtHex {
    if is_aarch64_feature_detected!("neon") {
        &neon::I
    } else {
        &usimd::I
    }
}
