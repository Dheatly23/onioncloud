use std::ptr::from_ref;

use super::super::get_unchecked;
use super::arch;

#[target_feature(enable = "sse2")]
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
            let v = arch::_mm_loadu_si128(get_unchecked(c, i).cast());

            if i == 0 && arch::_mm_extract_epi16(v, 0) & 0xff == 0x2d {
                // First character is -
                return Err(0);
            }

            // Space and tab
            let st = arch::_mm_or_si128(
                arch::_mm_cmpeq_epi8(v, arch::_mm_set1_epi8(b' ' as _)),
                arch::_mm_cmpeq_epi8(v, arch::_mm_set1_epi8(b'\t' as _)),
            );

            // A-Z and a-z
            let v_ = arch::_mm_and_si128(v, arch::_mm_set1_epi8(0xdfu8 as _));
            let mut t = arch::_mm_or_si128(
                arch::_mm_cmplt_epi8(v_, arch::_mm_set1_epi8(0x41)),
                arch::_mm_cmpgt_epi8(v_, arch::_mm_set1_epi8(0x5a)),
            );

            // Numbers
            let n = arch::_mm_or_si128(
                arch::_mm_cmplt_epi8(v, arch::_mm_set1_epi8(0x30)),
                arch::_mm_cmpgt_epi8(v, arch::_mm_set1_epi8(0x39)),
            );
            t = arch::_mm_and_si128(t, n);

            // -
            let n = arch::_mm_cmpeq_epi8(v, arch::_mm_set1_epi8(b'-' as _));
            t = arch::_mm_andnot_si128(n, t);

            let v1 = (arch::_mm_movemask_epi8(t) as u16).trailing_zeros();
            let v2 = (arch::_mm_movemask_epi8(st) as u16).trailing_zeros();

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

#[target_feature(enable = "sse2")]
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
            let v = arch::_mm_loadu_si128(get_unchecked(c, i).cast());

            // Null test
            let z =
                arch::_mm_movemask_epi8(arch::_mm_cmpeq_epi8(v, arch::_mm_setzero_si128())) as u16;

            // Space and tab
            let t = arch::_mm_or_si128(
                arch::_mm_cmpeq_epi8(v, arch::_mm_set1_epi8(b' ' as _)),
                arch::_mm_cmpeq_epi8(v, arch::_mm_set1_epi8(b'\t' as _)),
            );
            let mut t = arch::_mm_movemask_epi8(t) as u16;

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
                (b'\0', _) => return Some(i),
                (b' ' | b'\t', false) => true,
                (b' ' | b'\t', true) => return Some(i),
                _ => false,
            };
        }

        if sp { Some(s.len()) } else { None }
    }
}

#[target_feature(enable = "sse2")]
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
            let v = arch::_mm_loadu_si128(get_unchecked(c, i).cast());

            // Space and tab
            let st = arch::_mm_movemask_epi8(arch::_mm_or_si128(
                arch::_mm_cmpeq_epi8(v, arch::_mm_set1_epi8(b' ' as _)),
                arch::_mm_cmpeq_epi8(v, arch::_mm_set1_epi8(b'\t' as _)),
            )) as u16;

            // A-Z and a-z
            let v_ = arch::_mm_and_si128(v, arch::_mm_set1_epi8(0xdfu8 as _));
            let alpha = arch::_mm_or_si128(
                arch::_mm_cmplt_epi8(v_, arch::_mm_set1_epi8(0x41)),
                arch::_mm_cmpgt_epi8(v_, arch::_mm_set1_epi8(0x5a)),
            );

            // Numbers
            let n = arch::_mm_or_si128(
                arch::_mm_cmplt_epi8(v, arch::_mm_set1_epi8(0x30)),
                arch::_mm_cmpgt_epi8(v, arch::_mm_set1_epi8(0x39)),
            );
            let alnum = arch::_mm_movemask_epi8(arch::_mm_and_si128(alpha, n)) as u16;

            // -
            let dash =
                arch::_mm_movemask_epi8(arch::_mm_cmpeq_epi8(v, arch::_mm_set1_epi8(b'-' as _)))
                    as u16;

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

#[target_feature(enable = "sse2")]
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
            let v = arch::_mm_loadu_si128(get_unchecked(c, i).cast());

            // +, /, =
            let mut t = arch::_mm_or_si128(
                arch::_mm_cmpeq_epi8(
                    arch::_mm_or_si128(v, arch::_mm_set1_epi8(0x04)),
                    arch::_mm_set1_epi8(0x2f),
                ),
                arch::_mm_cmpeq_epi8(v, arch::_mm_set1_epi8(b'=' as _)),
            );

            // A-Z and a-z
            let v_ = arch::_mm_and_si128(v, arch::_mm_set1_epi8(0xdfu8 as _));
            let n = arch::_mm_or_si128(
                arch::_mm_cmplt_epi8(v_, arch::_mm_set1_epi8(0x41)),
                arch::_mm_cmpgt_epi8(v_, arch::_mm_set1_epi8(0x5a)),
            );
            t = arch::_mm_andnot_si128(t, n);

            // Numbers
            let n = arch::_mm_or_si128(
                arch::_mm_cmplt_epi8(v, arch::_mm_set1_epi8(0x30)),
                arch::_mm_cmpgt_epi8(v, arch::_mm_set1_epi8(0x39)),
            );
            t = arch::_mm_and_si128(t, n);

            if let v @ 0..=15 = (arch::_mm_movemask_epi8(t) as u16).trailing_zeros() {
                return Some(i + v as usize);
            }

            i += 16;
        }

        // Tail
        (i..c.len()).find(|&i| !matches!(*get_unchecked(c, i), b'a'..=b'z' | b'A'..=b'Z' | b'0'..=b'9' | b'+' | b'/' | b'='))
    }
}
