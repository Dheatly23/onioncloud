//! x86 SIMD accelerated implementation.

pub mod avx;
pub mod sse;

use std::arch::is_x86_feature_detected;

use super::{FmtHex, usimd};

#[inline]
pub fn dispatch() -> &'static dyn FmtHex {
    if is_x86_feature_detected!("avx2") {
        &avx::I
    } else if is_x86_feature_detected!("sse2") {
        &sse::I
    } else {
        &usimd::I
    }
}
