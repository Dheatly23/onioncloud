//! WASM SIMD variant.
#![cfg(all(target_family = "wasm", target_feature = "simd128"))]

use std::arch::wasm32 as arch;
use std::fmt::{Formatter, Result as FmtResult};
use std::mem::transmute;
use std::ptr::{NonNull, from_ref};

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
        while i + 16 <= c.len() {
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
pub(crate) fn proto_keyword(s: &str) -> Result<usize, usize> {
    // SAFETY: It's more ergonomic to wrap the entire function in unsafe :D
    unsafe {
        let mut i = 0usize;
        let c = from_ref(s.as_bytes());

        // Should be impossible even with maximal allocation.
        // Rust don't allow pointer offset > isize::MAX.
        // But we do sanity check anyway.
        debug_assert_ne!(c.len(), usize::MAX);

        // Main
        while i + 16 <= c.len() {
            let v = arch::v128_load(get_unchecked(c, i).cast());

            if i == 0 && matches!(arch::u8x16_extract_lane(v, 0), b'-' | b'=') {
                // First character is - or =
                return Err(0);
            }

            // =
            let eq = arch::u8x16_eq(v, arch::u8x16_splat(b'='));

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
            let v2 = arch::u8x16_bitmask(eq).trailing_zeros();

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
                b'=' if i != 0 => return Ok(i),
                _ => return Err(i),
            }
        }
    }

    Err(s.len())
}

#[target_feature(enable = "simd128")]
pub(crate) fn pt_keyword(s: &str) -> Result<usize, usize> {
    // SAFETY: It's more ergonomic to wrap the entire function in unsafe :D
    unsafe {
        let mut i = 0usize;
        let c = from_ref(s.as_bytes());

        // Should be impossible even with maximal allocation.
        // Rust don't allow pointer offset > isize::MAX.
        // But we do sanity check anyway.
        debug_assert_ne!(c.len(), usize::MAX);

        // Main
        while i + 16 <= c.len() {
            let v = arch::v128_load(get_unchecked(c, i).cast());

            if i == 0 {
                let v_ = arch::u8x16_bitmask(arch::u8x16_eq(
                    arch::u64x2_shuffle < 0,
                    0 > (v, arch::u8x16_splat(0)),
                    arch::u8x16(
                        b'<', b'O', b'R', b'>', b'=', 0, 0, 0, b'<', b'?', b'?', b'>', b'=', 0, 0,
                        0,
                    ),
                )) & 0x1f1f;
                if v_ as u8 == 0x1f || (v_ >> 8) as u8 == 0x1f {
                    // String is lead by <OR>= or <??>=
                    return Ok(4);
                } else if matches!(arch::u8x16_extract_lane(v, 0), b'-' | b'=') {
                    // First character is - or =
                    return Err(0);
                }
            }

            // =
            let eq = arch::u8x16_eq(v, arch::u8x16_splat(b'='));

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
            let v2 = arch::u8x16_bitmask(eq).trailing_zeros();

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

        if i == 0 {
            let s = str::from_utf8_unchecked(&*c);
            if s.starts_with("<??>=") || s.starts_with("<OR>=") {
                // String is lead by <OR>= or <??>=
                return Ok(4);
            }
        }

        // Tail
        for i in i..c.len() {
            match *get_unchecked(c, i) {
                b'a'..=b'z' | b'A'..=b'Z' | b'0'..=b'9' => (),
                b'-' if i != 0 => (),
                b'=' if i != 0 => return Ok(i),
                _ => return Err(i),
            }
        }
    }

    Err(s.len())
}

#[target_feature(enable = "simd128")]
pub(crate) fn next_non_ws(s: &str) -> usize {
    // SAFETY: It's more ergonomic to wrap the entire function in unsafe :D
    unsafe {
        let mut i = 0usize;
        let c = from_ref(s.as_bytes());

        // Should be impossible even with maximal allocation.
        // Rust don't allow pointer offset > isize::MAX.
        // But we do sanity check anyway.
        debug_assert_ne!(c.len(), usize::MAX);

        // Main
        while i + 16 < c.len() {
            let v = arch::v128_load(get_unchecked(c, i).cast());

            // Space and tab
            let t = arch::u8x16_bitmask(arch::v128_and(
                arch::u8x16_ne(v, arch::u8x16_splat(b' ')),
                arch::u8x16_ne(v, arch::u8x16_splat(b'\t')),
            ));
            if let v @ 0..=15 = t.trailing_zeros() {
                return i + v as usize;
            }

            i += 16;
        }

        // Tail
        for i in i..c.len() {
            if !matches!(*get_unchecked(c, i), b' ' | b'\t') {
                return i;
            }
        }
    }

    s.len()
}

#[target_feature(enable = "simd128")]
pub(crate) fn check_argument(s: &str) -> Option<usize> {
    if matches!(s.as_bytes().first(), Some(b' ' | b'\t')) {
        return Some(0);
    }

    // SAFETY: It's more ergonomic to wrap the entire function in unsafe :D
    unsafe {
        let mut i = 0usize;
        let c = from_ref(s.as_bytes());

        // Should be impossible even with maximal allocation.
        // Rust don't allow pointer offset > isize::MAX.
        // But we do sanity check anyway.
        debug_assert_ne!(c.len(), usize::MAX);

        // Main
        while i + 16 < c.len() {
            let v = arch::v128_load(get_unchecked(c, i).cast());

            // Null and newline test
            let t = arch::u8x16_bitmask(arch::v128_or(
                arch::u8x16_eq(v, arch::u8x16_splat(0)),
                arch::u8x16_eq(v, arch::u8x16_splat(b'\n')),
            ));
            if let v @ 0..=15 = t.trailing_zeros() {
                return Some(i + v as usize);
            }

            i += 16;
        }

        // Tail
        for i in i..c.len() {
            if matches!(*get_unchecked(c, i), b'\0' | b'\n') {
                return Some(i);
            }
        }
    }

    if matches!(s.as_bytes().last(), Some(b' ' | b'\t')) {
        return Some(s.len() - 1);
    }

    None
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

#[derive(Clone, Copy)]
pub(crate) struct ArgIterInner<'a> {
    s: &'a str,
    i: usize,
    e: usize,
    bs: u16,
    be: u16,
}

impl ArgIterInner<'_> {
    #[target_feature(enable = "simd128")]
    #[inline]
    fn process_batch(v: *const u8) -> u16 {
        let v = unsafe { arch::v128_load(v.cast()) };
        // Space and tab
        arch::u8x16_bitmask(arch::v128_or(
            arch::u8x16_eq(v, arch::u8x16_splat(b' ')),
            arch::u8x16_eq(v, arch::u8x16_splat(b'\t')),
        ))
    }

    #[target_feature(enable = "simd128")]
    fn forward(&mut self, ws: bool) {
        let c = from_ref(self.s.as_bytes());
        // SAFETY: It's more ergonomic to wrap the entire function in unsafe :D
        unsafe {
            // Main
            while self.i < self.e && (self.i & !15) + 16 <= c.len() {
                let o = self.i & 15;
                if o == 0 {
                    // Load batch
                    self.bs = Self::process_batch(get_unchecked(c, self.i));
                }

                let o =
                    (if ws { self.bs } else { !self.bs } & u16::MAX << o).trailing_zeros() as usize;
                // If o is 16 it will advance i
                self.i = (self.i & !15) + o;
                if o < 16 {
                    return;
                }
            }

            // Tail
            while self.i < self.e {
                if matches!(*get_unchecked(c, self.i), b' ' | b'\t') ^ !ws {
                    return;
                }
                self.i += 1;
            }
        }
    }

    #[target_feature(enable = "simd128")]
    fn backward(&mut self, ws: bool) {
        let c = from_ref(self.s.as_bytes());
        // SAFETY: It's more ergonomic to wrap the entire function in unsafe :D
        unsafe {
            // Head
            while self.i < self.e && self.e > c.len() & !15 {
                if matches!(*get_unchecked(c, self.e - 1), b' ' | b'\t') ^ !ws {
                    return;
                }
                self.e -= 1;
            }

            // Main
            while self.i < self.e {
                let o = self.e.wrapping_neg() & 15;
                if o == 0 {
                    // Load batch
                    self.e -= 16;
                    self.be = Self::process_batch(get_unchecked(c, self.e));
                }

                let o = (if ws { self.be } else { !self.be } & (u16::MAX >> o)).leading_zeros()
                    as usize;
                // If o is 16 it will advance e
                self.e = (self.e & !15) + (16 - o);
                if o < 16 {
                    return;
                }
            }
        }
    }
}

impl<'a> From<&'a str> for ArgIterInner<'a> {
    #[target_feature(enable = "simd128")]
    fn from(s: &'a str) -> Self {
        Self {
            s,
            i: 0,
            e: s.len(),
            bs: 0,
            be: 0,
        }
    }
}

impl Debug for ArgIterInner<'_> {
    #[target_feature(enable = "simd128")]
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        f.debug_struct("ArgIterInner")
            .field("i", &self.i)
            .field("e", &self.e)
            .field("bs", &self.bs)
            .field("be", &self.be)
            .field("sp", &self.s.get(self.i..self.e))
            .finish_non_exhaustive()
    }
}

impl<'a> Iterator for ArgIterInner<'a> {
    type Item = &'a str;

    #[target_feature(enable = "simd128")]
    fn next(&mut self) -> Option<Self::Item> {
        let s = self.start_ix();
        let e = self.end_ix();
        debug_assert!(s <= e, "{s} > {e}");

        if s >= e {
            return None;
        }

        self.forward(true);
        let m = self.start_ix();
        debug_assert!(m <= e, "{m} > {e}");
        debug_assert!(m >= s, "{m} < {s}");
        if m < e {
            // Skip whitespace
            self.forward(false);
        }

        // SAFETY: Indices are valid
        unsafe { Some(self.s.get_unchecked(s..m)) }
    }

    #[target_feature(enable = "simd128")]
    fn size_hint(&self) -> (usize, Option<usize>) {
        if self.end_ix() <= self.start_ix() {
            (0, Some(0))
        } else {
            (1, None)
        }
    }
}

impl DoubleEndedIterator for ArgIterInner<'_> {
    #[target_feature(enable = "simd128")]
    fn next_back(&mut self) -> Option<Self::Item> {
        let s = self.start_ix();
        let e = self.end_ix();
        debug_assert!(s <= e, "{s} > {e}");

        if s >= e {
            return None;
        }

        self.backward(true);
        let m = self.end_ix();
        debug_assert!(m >= s, "{m} < {s}");
        debug_assert!(m <= e, "{m} > {e}");
        if m > s {
            // Skip whitespace
            self.backward(false);
        }

        // SAFETY: Indices are valid
        unsafe { Some(self.s.get_unchecked(m..e)) }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use super::super::generic as reference;
    use super::super::tests::{aligned_arg_str, aligned_str};

    use proptest::prelude::*;

    #[test]
    fn test_pt_keyword_must_pass() {
        assert_eq!(pt_keyword("<OR>=a"), Ok(4));
        assert_eq!(pt_keyword("<??>=a"), Ok(4));
        assert_eq!(pt_keyword("<OR>=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"), Ok(4));
        assert_eq!(pt_keyword("<??>=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"), Ok(4));
    }

    proptest! {
        #[test]
        fn test_check_line((s, _o) in aligned_str()) {
            //dbg!(_o, s.as_bytes());
            assert_eq!(reference::check_line(&s), check_line(&s));
        }

        #[test]
        fn test_proto_keyword((s, _o) in aligned_str()) {
            //dbg!(_o, s.as_bytes());
            assert_eq!(reference::proto_keyword(&s), proto_keyword(&s));
        }

        #[test]
        fn test_pt_keyword((s, _o) in aligned_str()) {
            //dbg!(_o, s.as_bytes());
            assert_eq!(reference::pt_keyword(&s), pt_keyword(&s));
        }

        #[test]
        fn test_next_non_ws((s, _o) in aligned_str()) {
            //dbg!(_o, s.as_bytes());
            assert_eq!(reference::next_non_ws(&s), next_non_ws(&s));
        }

        #[test]
        fn test_check_argument((s, _o) in aligned_str()) {
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

        #[test]
        fn test_arg_iter((s, _o) in aligned_arg_str()) {
            //dbg!(_o, &*s);

            let mut it = ArgIterInner::from(&*s);
            for (i, r) in reference::ArgIterInner::from(&*s).enumerate() {
                let Some(t) = it.next() else {
                    panic!("iterator should produce at least {i} items")
                };
                //dbg!(t);
                assert_eq!(r, t, "mismatch at index {i}");
            }
            if let Some(t) = it.next() {
                panic!("iterator should stop, got {t:?}")
            }

            let mut it = ArgIterInner::from(&*s).rev();
            for (i, r) in reference::ArgIterInner::from(&*s).rev().enumerate() {
                let Some(t) = it.next() else {
                    panic!("iterator should produce at least {i} items")
                };
                //dbg!(t);
                assert_eq!(r, t, "mismatch at index {i}");
            }
            if let Some(t) = it.next() {
                panic!("iterator should stop, got {t:?}")
            }
        }
    }
}
