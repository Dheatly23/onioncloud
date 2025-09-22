//! WASM SIMD variant.
#![cfg(all(target_family = "wasm", target_feature = "simd128"))]

use std::arch::wasm32 as arch;
use std::ptr::from_ref;

use super::get_unchecked;

#[target_feature(enable = "simd128")]
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
            let v = arch::v128_load(get_unchecked(c, i).cast());

            if i == 0 && arch::u8x16_extract_lane(v, 0) == 0x2d {
                // First character is -
                return Err(0);
            }

            // Space and tab
            let st = arch::v128_or(
                arch::u8x16_eq(v, arch::u8x16_splat(b' ')),
                arch::u8x16_eq(v, arch::u8x16_splat(b'\t')),
            );

            // A-Z and a-z
            let v_ = arch::v128_and(v, arch::u8x16_splat(0xdfu8));
            let mut t = arch::v128_or(
                arch::u8x16_lt(v_, arch::u8x16_splat(0x41)),
                arch::u8x16_gt(v_, arch::u8x16_splat(0x5a)),
            );

            // Numbers
            let n = arch::v128_or(
                arch::u8x16_lt(v, arch::u8x16_splat(0x30)),
                arch::u8x16_gt(v, arch::u8x16_splat(0x39)),
            );
            t = arch::v128_and(t, n);

            // -
            let n = arch::u8x16_eq(v, arch::u8x16_splat(b'-'));
            t = arch::v128_andnot(t, n);

            let v1 = arch::u8x16_bitmask(t).trailing_zeros();
            let v2 = arch::u8x16_bitmask(st).trailing_zeros();

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

#[target_feature(enable = "simd128")]
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
            let v = arch::v128_load(get_unchecked(c, i).cast());

            // Null test
            let z = arch::u8x16_bitmask(arch::u8x16_eq(v, arch::u8x16_splat(0)));

            // Space and tab
            let t = arch::v128_or(
                arch::u8x16_eq(v, arch::u8x16_splat(b' ')),
                arch::u8x16_eq(v, arch::u8x16_splat(b'\t')),
            );
            let mut t = arch::u8x16_bitmask(t);

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

#[target_feature(enable = "simd128")]
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
            let v = arch::v128_load(get_unchecked(c, i).cast());

            // Space and tab
            let st = arch::u8x16_bitmask(arch::v128_or(
                arch::u8x16_eq(v, arch::u8x16_splat(b' ')),
                arch::u8x16_eq(v, arch::u8x16_splat(b'\t')),
            ));

            // A-Z and a-z
            let v_ = arch::v128_and(v, arch::u8x16_splat(0xdfu8));
            let alpha = arch::v128_or(
                arch::u8x16_lt(v_, arch::u8x16_splat(0x41)),
                arch::u8x16_gt(v_, arch::u8x16_splat(0x5a)),
            );

            // Numbers
            let n = arch::v128_or(
                arch::u8x16_lt(v, arch::u8x16_splat(0x30)),
                arch::u8x16_gt(v, arch::u8x16_splat(0x39)),
            );
            let alnum = arch::u8x16_bitmask(arch::v128_and(alpha, n));

            // -
            let dash = arch::u8x16_bitmask(arch::u8x16_eq(v, arch::u8x16_splat(b'-')));

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

#[target_feature(enable = "simd128")]
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
            let v = arch::v128_load(get_unchecked(c, i).cast());

            // +, /, =
            let mut t = arch::v128_or(
                arch::u8x16_eq(
                    arch::v128_or(v, arch::u8x16_splat(0x04)),
                    arch::u8x16_splat(0x2f),
                ),
                arch::u8x16_eq(v, arch::u8x16_splat(b'=')),
            );

            // A-Z and a-z
            let v_ = arch::v128_and(v, arch::u8x16_splat(0xdfu8));
            let n = arch::v128_or(
                arch::u8x16_lt(v_, arch::u8x16_splat(0x41)),
                arch::u8x16_gt(v_, arch::u8x16_splat(0x5a)),
            );
            t = arch::v128_andnot(n, t);

            // Numbers
            let n = arch::v128_or(
                arch::u8x16_lt(v, arch::u8x16_splat(0x30)),
                arch::u8x16_gt(v, arch::u8x16_splat(0x39)),
            );
            t = arch::v128_and(t, n);

            if let v @ 0..=15 = arch::u8x16_bitmask(t).trailing_zeros() {
                return Some(i + v as usize);
            }

            i += 16;
        }

        // Tail
        (i..c.len()).find(|&i| !matches!(*get_unchecked(c, i), b'a'..=b'z' | b'A'..=b'Z' | b'0'..=b'9' | b'+' | b'/' | b'='))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use super::super::generic as reference;
    use super::super::tests::aligned_str;

    use proptest::prelude::*;

    proptest! {
        #[test]
        fn test_check_line((s, _o) in aligned_str()) {
            //dbg!(_o, s.as_bytes());
            assert_eq!(reference::check_line(&s), check_line(&s));
        }

        #[test]
        fn test_check_argument((s, _o) in aligned_str().prop_filter("string is empty", |(s, _)| !s.is_empty())) {
            //dbg!(_o, s.as_bytes());
            assert_eq!(reference::check_argument(&s), check_argument(&s));
        }

        #[test]
        fn test_check_object_keyword((s, _o) in aligned_str()) {
            //dbg!(_o, s.as_bytes());
            assert_eq!(reference::check_object_keyword(&s), check_object_keyword(&s));
        }

        #[test]
        fn test_check_object_content((s, _o) in aligned_str()) {
            //dbg!(_o, s.as_bytes());
            assert_eq!(reference::check_object_content(&s), check_object_content(&s));
        }
    }
}
