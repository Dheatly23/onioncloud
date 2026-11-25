//! x86 AVX2 implementation.

#[cfg(target_arch = "x86")]
use core::arch::x86::*;
#[cfg(target_arch = "x86_64")]
use core::arch::x86_64::*;

use super::FmtHex;

pub struct I;

impl FmtHex for I {
    #[target_feature(enable = "avx2")]
    unsafe fn fmt_hex(&self, mut o: *mut u8, mut i: *const u8, mut l: usize) {
        // SAFETY: Safety requirement is satisfied.
        unsafe {
            while l >= 32 {
                let v = _mm256_loadu_si256(i.cast());
                i = i.add(32);
                l -= 32;

                // Split nibbles
                let v0 = _mm256_and_si256(_mm256_srli_epi16(v, 4), _mm256_set1_epi8(15));
                let v1 = _mm256_and_si256(v, _mm256_set1_epi8(15));

                // >= 10
                let f0 = _mm256_cmpgt_epi8(v0, _mm256_set1_epi8(9));
                let f1 = _mm256_cmpgt_epi8(v1, _mm256_set1_epi8(9));

                // Select digit or tens (uppercase)
                let mut t0 = _mm256_blendv_epi8(
                    _mm256_set1_epi8(b'0' as _),
                    _mm256_set1_epi8((b'A' - 10) as _),
                    f0,
                );
                let mut t1 = _mm256_blendv_epi8(
                    _mm256_set1_epi8(b'0' as _),
                    _mm256_set1_epi8((b'A' - 10) as _),
                    f1,
                );
                // Add
                t0 = _mm256_add_epi8(v0, t0);
                t1 = _mm256_add_epi8(v1, t1);

                // Interleave
                (t0, t1) = (_mm256_unpacklo_epi8(t0, t1), _mm256_unpackhi_epi8(t0, t1));
                (t0, t1) = (
                    _mm256_permute2x128_si256(t0, t1, 0x20),
                    _mm256_permute2x128_si256(t0, t1, 0x31),
                );

                // Write
                _mm256_storeu_si256(o.cast(), t0);
                _mm256_storeu_si256(o.add(32).cast(), t1);
                o = o.add(64);
            }

            // Tail
            while l > 0 {
                let v = *i;
                i = i.add(1);
                l -= 1;

                let l = match v & 15 {
                    i @ ..=9 => i + b'0',
                    i => i + (b'A' - 10),
                };
                let h = match v >> 4 {
                    i @ ..=9 => i + b'0',
                    i => i + (b'A' - 10),
                };
                *o = h;
                *o.add(1) = l;
                o = o.add(2);
            }
        }
    }
}
