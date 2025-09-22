use std::ptr::from_ref;

use super::super::get_unchecked;
use super::arch;

#[target_feature(enable = "avx2")]
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
        while i + 31 < c.len() {
            let v = arch::_mm256_loadu_si256(get_unchecked(c, i).cast());

            if i == 0 && arch::_mm256_extract_epi8(v, 0) as u8 == 0x2d {
                // First character is -
                return Err(0);
            }

            // Space and tab
            let st = arch::_mm256_or_si256(
                arch::_mm256_cmpeq_epi8(v, arch::_mm256_set1_epi8(b' ' as _)),
                arch::_mm256_cmpeq_epi8(v, arch::_mm256_set1_epi8(b'\t' as _)),
            );

            // A-Z and a-z
            let v_ = arch::_mm256_and_si256(v, arch::_mm256_set1_epi8(0xdfu8 as _));
            let mut t = arch::_mm256_or_si256(
                arch::_mm256_cmpgt_epi8(arch::_mm256_set1_epi8(0x41), v_),
                arch::_mm256_cmpgt_epi8(v_, arch::_mm256_set1_epi8(0x5a)),
            );

            // Numbers
            let n = arch::_mm256_or_si256(
                arch::_mm256_cmpgt_epi8(arch::_mm256_set1_epi8(0x30), v),
                arch::_mm256_cmpgt_epi8(v, arch::_mm256_set1_epi8(0x39)),
            );
            t = arch::_mm256_and_si256(t, n);

            // -
            let n = arch::_mm256_cmpeq_epi8(v, arch::_mm256_set1_epi8(b'-' as _));
            t = arch::_mm256_andnot_si256(n, t);

            let v1 = (arch::_mm256_movemask_epi8(t) as u32).trailing_zeros();
            let v2 = (arch::_mm256_movemask_epi8(st) as u32).trailing_zeros();

            if v1 < v2 {
                // Non-matching character before space or tab
                return Err(i + v1 as usize);
            } else if v2 < 32 {
                // Space or tab
                return Ok(i + v2 as usize);
            }
            debug_assert_eq!(v1, 32);
            debug_assert_eq!(v2, 32);

            i += 32;
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

#[target_feature(enable = "avx2")]
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
        while i + 31 < c.len() {
            let v = arch::_mm256_loadu_si256(get_unchecked(c, i).cast());

            // Null test
            let z = arch::_mm256_movemask_epi8(arch::_mm256_cmpeq_epi8(
                v,
                arch::_mm256_setzero_si256(),
            )) as u32;

            // Space and tab
            let t = arch::_mm256_or_si256(
                arch::_mm256_cmpeq_epi8(v, arch::_mm256_set1_epi8(b' ' as _)),
                arch::_mm256_cmpeq_epi8(v, arch::_mm256_set1_epi8(b'\t' as _)),
            );
            let mut t = arch::_mm256_movemask_epi8(t) as u32;

            // Two space or tab
            let t_ = t << 1 | sp as u32;
            sp = (t >> 31) != 0;
            t &= t_;
            t |= z;

            if let v @ 0..=31 = t.trailing_zeros() {
                return Some(i + v as usize);
            }

            i += 32;
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

#[target_feature(enable = "avx2")]
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
        while i + 31 < c.len() {
            let v = arch::_mm256_loadu_si256(get_unchecked(c, i).cast());

            // Space and tab
            let st = arch::_mm256_movemask_epi8(arch::_mm256_or_si256(
                arch::_mm256_cmpeq_epi8(v, arch::_mm256_set1_epi8(b' ' as _)),
                arch::_mm256_cmpeq_epi8(v, arch::_mm256_set1_epi8(b'\t' as _)),
            )) as u32;

            // A-Z and a-z
            let v_ = arch::_mm256_and_si256(v, arch::_mm256_set1_epi8(0xdfu8 as _));
            let alpha = arch::_mm256_or_si256(
                arch::_mm256_cmpgt_epi8(arch::_mm256_set1_epi8(0x41), v_),
                arch::_mm256_cmpgt_epi8(v_, arch::_mm256_set1_epi8(0x5a)),
            );

            // Numbers
            let n = arch::_mm256_or_si256(
                arch::_mm256_cmpgt_epi8(arch::_mm256_set1_epi8(0x30), v),
                arch::_mm256_cmpgt_epi8(v, arch::_mm256_set1_epi8(0x39)),
            );
            let alnum = arch::_mm256_movemask_epi8(arch::_mm256_and_si256(alpha, n)) as u32;

            // -
            let dash = arch::_mm256_movemask_epi8(arch::_mm256_cmpeq_epi8(
                v,
                arch::_mm256_set1_epi8(b'-' as _),
            )) as u32;

            // Space or tab followed by space, tab, or -
            let t_ = st << 1 | sp as u32;
            sp = (st >> 31) != 0;
            let t = (st | dash) & t_ | (alnum & !(st | dash));

            if let v @ 0..=31 = t.trailing_zeros() {
                return Some(i + v as usize);
            }

            i += 32;
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

#[target_feature(enable = "avx2")]
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
        while i + 31 < c.len() {
            let v = arch::_mm256_loadu_si256(get_unchecked(c, i).cast());

            // +, /, =
            let mut t = arch::_mm256_or_si256(
                arch::_mm256_cmpeq_epi8(
                    arch::_mm256_or_si256(v, arch::_mm256_set1_epi8(0x04)),
                    arch::_mm256_set1_epi8(0x2f),
                ),
                arch::_mm256_cmpeq_epi8(v, arch::_mm256_set1_epi8(b'=' as _)),
            );

            // A-Z and a-z
            let v_ = arch::_mm256_and_si256(v, arch::_mm256_set1_epi8(0xdfu8 as _));
            let n = arch::_mm256_or_si256(
                arch::_mm256_cmpgt_epi8(arch::_mm256_set1_epi8(0x41), v_),
                arch::_mm256_cmpgt_epi8(v_, arch::_mm256_set1_epi8(0x5a)),
            );
            t = arch::_mm256_andnot_si256(t, n);

            // Numbers
            let n = arch::_mm256_or_si256(
                arch::_mm256_cmpgt_epi8(arch::_mm256_set1_epi8(0x30), v),
                arch::_mm256_cmpgt_epi8(v, arch::_mm256_set1_epi8(0x39)),
            );
            t = arch::_mm256_and_si256(t, n);

            if let v @ 0..=31 = (arch::_mm256_movemask_epi8(t) as u32).trailing_zeros() {
                return Some(i + v as usize);
            }

            i += 32;
        }

        // Tail
        (i..c.len()).find(|&i| !matches!(*get_unchecked(c, i), b'a'..=b'z' | b'A'..=b'Z' | b'0'..=b'9' | b'+' | b'/' | b'='))
    }
}
