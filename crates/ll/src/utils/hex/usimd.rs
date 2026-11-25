//! USIMD implementation.

use std::ptr::{read_unaligned, write_unaligned};

use super::FmtHex;

pub struct I;

impl FmtHex for I {
    #[inline]
    unsafe fn fmt_hex(&self, mut o: *mut u8, mut i: *const u8, mut l: usize) {
        // SAFETY: Safety requirement is satisfied.
        unsafe {
            while l >= 16 {
                let v = read_unaligned(i.cast::<u128>()).to_le();
                i = i.add(16);
                l -= 16;

                for i in 0..4 {
                    let mut v = ((v >> (32 * i)) as u64) & 0xffff_ffff;

                    // Interleave with 4 0s
                    v = ((v & 0xffff_0000) << 16) | (v & 0xffff);
                    v = ((v & 0xff00_0000_ff00) << 8) | (v & 0x00ff_0000_00ff);
                    v = ((v & 0x00f0_00f0_00f0_00f0) >> 4) | ((v & 0x000f_000f_000f_000f) << 8);

                    // >= 10
                    let mut f = v.wrapping_add(bcast(6));
                    f >>= 4;
                    f &= bcast(1);

                    // Digits
                    let mut t = v.wrapping_add(bcast(b'0'));
                    // Tens (uppercase)
                    t = t.wrapping_add(f << 4).wrapping_sub((f << 3) | f);

                    // Write
                    write_unaligned(o.cast::<u64>(), u64::from_le(t));
                    o = o.add(8);
                }
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

const fn bcast(c: u8) -> u64 {
    let mut r = c as u64;
    r |= r << 8;
    r |= r << 16;
    r |= r << 32;
    r
}
