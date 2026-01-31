use std::ptr::from_ref;

use super::super::get_unchecked;
use super::arch;

/// Helper function for movemask.
///
/// # Parameters
///
/// A u8x16 where all lanes are either all 0 or all 1.
///
/// # Return
///
/// Returns u16 where each bit corresponds to if lane is all 1 or not.
#[target_feature(enable = "neon")]
fn movemask(v: arch::uint8x16_t) -> u16 {
    const C: [u8; 16] = [
        1 << 0,
        1 << 1,
        1 << 2,
        1 << 3,
        1 << 4,
        1 << 5,
        1 << 6,
        1 << 7,
        1 << 0,
        1 << 1,
        1 << 2,
        1 << 3,
        1 << 4,
        1 << 5,
        1 << 6,
        1 << 7,
    ];
    let v = arch::vandq_u8(v, unsafe { arch::vld1q_u8(from_ref(&C).cast()) });
    let vl = arch::vget_low_u8(v);
    let vh = arch::vget_high_u8(v);
    arch::vaddv_u8(vl) as u16 | (arch::vaddv_u8(vh) as u16) << 8
}

#[target_feature(enable = "neon")]
pub(crate) fn check_line(s: &str) -> Result<usize, usize> {
    // SAFETY: It's more ergonomic to wrap the entire function in unsafe :D
    unsafe {
        let mut i = 0usize;
        let c = from_ref(s.as_bytes());

        // Should be impossible even with maximal allocation.
        // Rust don't allow pointer offset > isize::MAX.
        // But we do sanity check anyway.
        debug_assert_ne!(c.len(), usize::MAX);

        // Main
        while i + 15 < c.len() {
            let v = arch::vld1q_u8(get_unchecked(c, i));

            if i == 0 && arch::vgetq_lane_u8(v, 0) == 0x2d {
                // First character is -
                return Err(0);
            }

            // Space and tab
            let st = arch::vorrq_u8(
                arch::vceqq_u8(v, arch::vdupq_n_u8(b' ')),
                arch::vceqq_u8(v, arch::vdupq_n_u8(b'\t')),
            );

            // A-Z and a-z
            let v_ = arch::vandq_u8(v, arch::vdupq_n_u8(0xdfu8));
            let mut t = arch::vorrq_u8(
                arch::vcltq_u8(v_, arch::vdupq_n_u8(0x41)),
                arch::vcgtq_u8(v_, arch::vdupq_n_u8(0x5a)),
            );

            // Numbers
            let n = arch::vorrq_u8(
                arch::vcltq_u8(v, arch::vdupq_n_u8(0x30)),
                arch::vcgtq_u8(v, arch::vdupq_n_u8(0x39)),
            );
            t = arch::vandq_u8(t, n);

            // -
            let n = arch::vceqq_u8(v, arch::vdupq_n_u8(b'-'));
            t = arch::vbicq_u8(t, n);

            let v1 = movemask(t).trailing_zeros();
            let v2 = movemask(st).trailing_zeros();

            if v1 < v2 {
                // Non-matching character before space or tab
                return Err(i + v1 as usize);
            } else if v2 < 16 {
                // Space or tab
                return Ok(i + v2 as usize);
            }
            debug_assert_eq!(v1, 16);
            debug_assert_eq!(v2, 16);

            i += 16;
        }

        // Tail
        for i in i..c.len() {
            match *get_unchecked(c, i) {
                b'a'..=b'z' | b'A'..=b'Z' | b'0'..=b'9' => (),
                b'-' if i != 0 => (),
                b' ' | b'\t' => return Ok(i),
                _ => return Err(i),
            }
        }
    }

    Ok(s.len())
}

#[target_feature(enable = "neon")]
pub(crate) fn check_argument(s: &str) -> Option<usize> {
    // SAFETY: It's more ergonomic to wrap the entire function in unsafe :D
    unsafe {
        let mut i = 0usize;
        let c = from_ref(s.as_bytes());

        // Should be impossible even with maximal allocation.
        // Rust don't allow pointer offset > isize::MAX.
        // But we do sanity check anyway.
        debug_assert_ne!(c.len(), usize::MAX);

        // Main
        let mut sp = true;
        while i + 15 < c.len() {
            let v = arch::vld1q_u8(get_unchecked(c, i));

            // Null and newline test
            let z = movemask(arch::vorrq_u8(
                arch::vceqq_u8(v, arch::vdupq_n_u8(0)),
                arch::vceqq_u8(v, arch::vdupq_n_u8(b'\n')),
            ));

            // Space and tab
            let t = arch::vorrq_u8(
                arch::vceqq_u8(v, arch::vdupq_n_u8(b' ')),
                arch::vceqq_u8(v, arch::vdupq_n_u8(b'\t')),
            );
            let mut t = movemask(t);

            // Two space or tab
            let t_ = t << 1 | sp as u16;
            sp = (t >> 15) != 0;
            t &= t_;
            t |= z;

            if let v @ 0..=15 = t.trailing_zeros() {
                return Some(i + v as usize);
            }

            i += 16;
        }

        // Tail
        for i in i..c.len() {
            sp = match (*get_unchecked(c, i), sp) {
                (b'\0' | b'\n', _) => return Some(i),
                (b' ' | b'\t', false) => true,
                (b' ' | b'\t', true) => return Some(i),
                _ => false,
            };
        }

        if sp { Some(s.len()) } else { None }
    }
}

#[target_feature(enable = "neon")]
pub(crate) fn check_object_keyword(s: &str) -> Option<usize> {
    // SAFETY: It's more ergonomic to wrap the entire function in unsafe :D
    unsafe {
        let mut i = 0usize;
        let c = from_ref(s.as_bytes());

        // Should be impossible even with maximal allocation.
        // Rust don't allow pointer offset > isize::MAX.
        // But we do sanity check anyway.
        debug_assert_ne!(c.len(), usize::MAX);

        // Main
        let mut sp = true;
        while i + 15 < c.len() {
            let v = arch::vld1q_u8(get_unchecked(c, i));

            // Space and tab
            let st = movemask(arch::vorrq_u8(
                arch::vceqq_u8(v, arch::vdupq_n_u8(b' ')),
                arch::vceqq_u8(v, arch::vdupq_n_u8(b'\t')),
            ));

            // A-Z and a-z
            let v_ = arch::vandq_u8(v, arch::vdupq_n_u8(0xdfu8));
            let alpha = arch::vorrq_u8(
                arch::vcltq_u8(v_, arch::vdupq_n_u8(0x41)),
                arch::vcgtq_u8(v_, arch::vdupq_n_u8(0x5a)),
            );

            // Numbers
            let n = arch::vorrq_u8(
                arch::vcltq_u8(v, arch::vdupq_n_u8(0x30)),
                arch::vcgtq_u8(v, arch::vdupq_n_u8(0x39)),
            );
            let alnum = movemask(arch::vandq_u8(alpha, n));

            // -
            let dash = movemask(arch::vceqq_u8(v, arch::vdupq_n_u8(b'-')));

            // Space or tab followed by space, tab, or -
            let t_ = st << 1 | sp as u16;
            sp = (st >> 15) != 0;
            let t = (st | dash) & t_ | (alnum & !(st | dash));

            if let v @ 0..=15 = t.trailing_zeros() {
                return Some(i + v as usize);
            }

            i += 16;
        }

        // Tail
        for i in i..c.len() {
            sp = match (sp, *get_unchecked(c, i)) {
                (_, b'a'..=b'z' | b'A'..=b'Z' | b'0'..=b'9') | (false, b'-') => false,
                (false, b' ') => true,
                _ => return Some(i),
            };
        }

        if sp { Some(s.len()) } else { None }
    }
}

#[target_feature(enable = "neon")]
pub(crate) fn check_object_content(s: &str) -> Option<usize> {
    // SAFETY: It's more ergonomic to wrap the entire function in unsafe :D
    unsafe {
        let mut i = 0usize;
        let c = from_ref(s.as_bytes());

        // Should be impossible even with maximal allocation.
        // Rust don't allow pointer offset > isize::MAX.
        // But we do sanity check anyway.
        debug_assert_ne!(c.len(), usize::MAX);

        // Main
        while i + 15 < c.len() {
            let v = arch::vld1q_u8(get_unchecked(c, i));

            // +, /, =
            let mut t = arch::vorrq_u8(
                arch::vceqq_u8(
                    arch::vorrq_u8(v, arch::vdupq_n_u8(0x04)),
                    arch::vdupq_n_u8(0x2f),
                ),
                arch::vceqq_u8(v, arch::vdupq_n_u8(b'=')),
            );

            // A-Z and a-z
            let v_ = arch::vandq_u8(v, arch::vdupq_n_u8(0xdfu8));
            let n = arch::vorrq_u8(
                arch::vcltq_u8(v_, arch::vdupq_n_u8(0x41)),
                arch::vcgtq_u8(v_, arch::vdupq_n_u8(0x5a)),
            );
            t = arch::vbicq_u8(n, t);

            // Numbers
            let n = arch::vorrq_u8(
                arch::vcltq_u8(v, arch::vdupq_n_u8(0x30)),
                arch::vcgtq_u8(v, arch::vdupq_n_u8(0x39)),
            );
            t = arch::vandq_u8(t, n);

            if let v @ 0..=15 = movemask(t).trailing_zeros() {
                return Some(i + v as usize);
            }

            i += 16;
        }

        // Tail
        (i..c.len()).find(|&i| !matches!(*get_unchecked(c, i), b'a'..=b'z' | b'A'..=b'Z' | b'0'..=b'9' | b'+' | b'/' | b'='))
    }
}
