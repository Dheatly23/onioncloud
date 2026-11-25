//! aarch64 NEON implementation.

use core::arch::aarch64::*;

use super::FmtHex;

pub struct I;

impl FmtHex for I {
    #[target_feature(enable = "neon")]
    unsafe fn fmt_hex(&self, mut o: *mut u8, mut i: *const u8, mut l: usize) {
        // SAFETY: Safety requirement is satisfied.
        unsafe {
            while l >= 16 {
                let v = vld1q_u8(i);
                i = i.add(16);
                l -= 16;

                // Split nibbles
                let v0 = vandq_u8(vshrq_n_u8(v, 4), vdupq_n_u8(15));
                let v1 = vandq_u8(v, vdupq_n_u8(15));

                // >= 10
                let f0 = vcgtq_u8(v0, vdupq_n_u8(9));
                let f1 = vcgtq_u8(v1, vdupq_n_u8(9));

                // Select digit or tens (uppercase)
                let mut t0 = vbslq_u8(vdupq_n_u8((b'A' - 10) as _), vdupq_n_u8(b'0' as _), f0);
                let mut t1 = vbslq_u8(vdupq_n_u8((b'A' - 10) as _), vdupq_n_u8(b'0' as _), f1);
                // Add
                t0 = vaddq_u8(v0, t0);
                t1 = vaddq_u8(v1, t1);

                // Interleave
                let t = vzipq_u8(t0, t1);

                // Write
                vst2q_u8(o, t0);
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
