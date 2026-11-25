//! x86 SSE2 implementation.

#[cfg(target_arch = "x86")]
use core::arch::x86::*;
#[cfg(target_arch = "x86_64")]
use core::arch::x86_64::*;

use super::FmtHex;

pub struct I;

impl FmtHex for I {
    #[target_feature(enable = "sse2")]
    unsafe fn fmt_hex(&self, mut o: *mut u8, mut i: *const u8, mut l: usize) {
        // SAFETY: Safety requirement is satisfied.
        unsafe {
            while l >= 16 {
                let v = _mm_loadu_si128(i.cast());
                i = i.add(16);
                l -= 16;

                // Split nibbles
                let v0 = _mm_and_si128(_mm_srli_epi16(v, 4), _mm_set1_epi8(15));
                let v1 = _mm_and_si128(v, _mm_set1_epi8(15));

                // >= 10
                let f0 = _mm_cmpgt_epi8(v0, _mm_set1_epi8(9));
                let f1 = _mm_cmpgt_epi8(v1, _mm_set1_epi8(9));

                // Digits
                let mut t0 = _mm_add_epi8(v0, _mm_set1_epi8(b'0' as _));
                let mut t1 = _mm_add_epi8(v1, _mm_set1_epi8(b'0' as _));
                // Tens (uppercase)
                t0 = _mm_add_epi8(t0, _mm_and_si128(f0, _mm_set1_epi8(0x10 - 0b1001)));
                t1 = _mm_add_epi8(t1, _mm_and_si128(f1, _mm_set1_epi8(0x10 - 0b1001)));

                // Interleave
                (t0, t1) = (_mm_unpacklo_epi8(t0, t1), _mm_unpackhi_epi8(t0, t1));

                // Write
                _mm_storeu_si128(o.cast(), t0);
                _mm_storeu_si128(o.add(16).cast(), t1);
                o = o.add(32);
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
