//! Format byte slice into hexadecimal string.

#[cfg(target_arch = "aarch64")]
pub mod aarch64;
pub mod usimd;
#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
pub mod x86;

use std::ptr::{from_mut, from_ref};
use std::mem::MaybeUninit;

/// Helper trait for dispatching implementation.
pub trait FmtHex {
    /// Format byte slice into hexadecimal string.
    ///
    /// # Safety
    ///
    /// - `i` must point to input buffer.
    /// - `o` must point to output buffer.
    /// - `l` is length of input buffer.
    /// - Output buffer length must be equals to twice input buffer length.
    /// - Output buffer must not overlap with input buffer.
    unsafe fn fmt_hex(&self, o: *mut u8, i: *const u8, l: usize);
}

/// Format byte slice into hexadecimal string.
///
/// # Panics
///
/// Panics if output buffer length is not equals to input buffer length times 2.
pub fn fmt_hex(o: &mut [MaybeUninit<u8>], i: &[u8]) {
    assert_eq!(o.len(), i.len() * 2, "{} != {} * 2", o.len(), i.len());
    // SAFETY: Precondition satisfied.
    unsafe {
        let t = cfg_select! {
            any(target_arch = "x86", target_arch = "x86_64") => x86::dispatch(),
            target_arch = "aarch64" => aarch64::dispatch(),
            _ => &usimd::I,
        };
        t.fmt_hex(o.as_mut_ptr().cast(), i.as_ptr(), i.len());
    }
}
