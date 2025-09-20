//! 64-bit universal SIMD variant.

use std::ptr::from_ref;

/// Stable implementation of `pointer::get_unchecked`.
#[track_caller]
unsafe fn get_unchecked<T>(p: *const [T], i: usize) -> *const T {
    debug_assert!(i < p.len());
    unsafe { (p as *const T).add(i) }
}

/// Test less than or equals.
///
/// # Parameters
///
/// Two u8x8 with highest bit set to 0.
///
/// # Result
///
/// A u8x8 with MSB set if and only if a <= c. Other bits are undefined.
#[inline(always)]
const fn test_le_c<const C: u64>(a: u64) -> u64 {
    (C | 0x8080_8080_8080_8080).wrapping_sub(a)
}

/// Test greater than.
///
/// # Parameters
///
/// Two u8x8 with highest bit set to 0.
///
/// # Result
///
/// A u8x8 with MSB set if and only if a >= c. Other bits are undefined.
#[inline(always)]
const fn test_gt_c<const C: u64>(a: u64) -> u64 {
    (0x7f7f_7f7f_7f7f_7f7f - (C & 0x7f7f_7f7f_7f7f_7f7f)).wrapping_add(a)
}

/// Test equals.
///
/// # Parameters
///
/// Two u8x8.
///
/// # Result
///
/// A u8x8 with MSB set if and only if a == c. Other bits are undefined.
#[inline(always)]
const fn test_eq_c<const C: u64>(a: u64) -> u64 {
    let v = a ^ !C;
    let v = v & v << 4;
    let v = v & v << 2;
    v & v << 1
}

/// Test not equals.
///
/// # Parameters
///
/// Two u8x8.
///
/// # Result
///
/// A u8x8 with MSB set if and only if a != c. Other bits are undefined.
#[inline(always)]
const fn test_ne_c<const C: u64>(a: u64) -> u64 {
    let v = a ^ C;
    let v = v | v << 4;
    let v = v | v << 2;
    v | v << 1
}

pub(crate) fn check_line(s: &str) -> Result<usize, usize> {
    #[inline(always)]
    fn f(c: u8, i: usize) -> Option<Result<usize, usize>> {
        match c {
            b'a'..=b'z' | b'A'..=b'Z' | b'0'..=b'9' => None,
            b'-' if i != 0 => None,
            b' ' | b'\t' => Some(Ok(i)),
            _ => Some(Err(i)),
        }
    }

    // SAFETY: It's more ergonomic to wrap the entire function in unsafe :D
    unsafe {
        let mut i = 0usize;
        let c = from_ref(s.as_bytes());

        // Should be impossible even with maximal allocation.
        // Rust don't allow pointer offset > isize::MAX.
        // But we do sanity check anyway.
        debug_assert_ne!(c.len(), usize::MAX);

        if c.addr() & 7 != 0 {
            // Head
            i = 8 - (c.addr() & 7);
            for i in 0..i {
                if i >= c.len() {
                    break;
                }
                let Some(r) = f(*get_unchecked(c, i), i) else {
                    continue;
                };
                return r;
            }
        }

        debug_assert_eq!(c.addr().wrapping_add(i) & 7, 0);

        // Main
        while i + 7 < c.len() {
            let v = u64::from_le(*get_unchecked(c, i).cast::<u64>());

            if i == 0 && v & 0xff == 0x2d {
                // First character is -
                return Err(0);
            }

            // Space and tab
            let st = test_eq_c::<0x2020_2020_2020_2020>(v) | test_eq_c::<0x0909_0909_0909_0909>(v);
            //dbg!(st);

            // A-Z and a-z
            let v_ = v & 0x5f5f_5f5f_5f5f_5f5f;
            let mut t =
                test_le_c::<0x4040_4040_4040_4040>(v_) | test_gt_c::<0x5a5a_5a5a_5a5a_5a5a>(v_);
            //dbg!(t);

            // Numbers
            let v_ = v & 0x7f7f_7f7f_7f7f_7f7f;
            let n = test_le_c::<0x2f2f_2f2f_2f2f_2f2f>(v_) | test_gt_c::<0x3939_3939_3939_3939>(v_);
            t &= n;
            //dbg!(n);

            // -
            let n = test_ne_c::<0x2d2d_2d2d_2d2d_2d2d>(v);
            t &= n;
            //dbg!(n);

            // Lane is >= 128
            t |= v;
            //dbg!(t);

            let o1 = (t & 0x8080_8080_8080_8080).trailing_zeros();
            debug_assert!(o1 == 64 || o1 % 8 == 7);
            let v1 = o1 / 8;
            let o2 = (st & 0x8080_8080_8080_8080).trailing_zeros();
            debug_assert!(o2 == 64 || o2 % 8 == 7);
            let v2 = o2 / 8;

            if v1 < v2 {
                // Non-matching character before space or tab
                return Err(i + v1 as usize);
            } else if v2 < 8 {
                // Space or tab
                return Ok(i + v2 as usize);
            }
            debug_assert_eq!(v1, 8);
            debug_assert_eq!(v2, 8);

            i += 8;
        }

        // Tail
        for i in i..c.len() {
            let Some(r) = f(*get_unchecked(c, i), i) else {
                continue;
            };
            return r;
        }
    }

    Ok(s.len())
}

pub(crate) fn check_argument(s: &str) -> Option<usize> {
    #[inline(always)]
    fn f(c: u8, i: usize, sp: &mut bool) -> Option<usize> {
        *sp = match (c, *sp) {
            (b'\0', _) => return Some(i),
            (b' ' | b'\t', false) => true,
            (b' ' | b'\t', true) => return Some(i),
            _ => false,
        };
        None
    }

    // SAFETY: It's more ergonomic to wrap the entire function in unsafe :D
    unsafe {
        let mut i = 0usize;
        let mut sp = true;
        let c = from_ref(s.as_bytes());

        // Should be impossible even with maximal allocation.
        // Rust don't allow pointer offset > isize::MAX.
        // But we do sanity check anyway.
        debug_assert_ne!(c.len(), usize::MAX);

        if c.addr() & 7 != 0 {
            // Head
            i = 8 - (c.addr() & 7);
            for i in 0..i {
                if i >= c.len() {
                    break;
                }
                if let r @ Some(_) = f(*get_unchecked(c, i), i, &mut sp) {
                    return r;
                }
            }
        }

        debug_assert_eq!(c.addr().wrapping_add(i) & 7, 0);

        // Main
        let mut sp = if sp { 128 } else { 0u8 };
        while i + 7 < c.len() {
            let v = u64::from_le(*get_unchecked(c, i).cast::<u64>());

            // Null test
            let z = test_eq_c::<0>(v) & 0x8080_8080_8080_8080;
            //dbg!(t);

            // Space and tab
            let mut t =
                test_eq_c::<0x2020_2020_2020_2020>(v) | test_eq_c::<0x0909_0909_0909_0909>(v);
            t &= 0x8080_8080_8080_8080;
            //dbg!(t);

            // Two space or tab
            debug_assert!(sp == 128 || sp == 0);
            let t_ = t << 8 | sp as u64;
            //dbg!(t_, sp);
            sp = (t >> (64 - 8)) as _;
            t &= t_;

            let o = (t | z).trailing_zeros();
            debug_assert!(o == 64 || o % 8 == 7);
            if let v @ 0..=7 = o / 8 {
                return Some(i + v as usize);
            }

            i += 8;
        }

        // Tail
        let mut sp = sp != 0;
        for i in i..c.len() {
            if let r @ Some(_) = f(*get_unchecked(c, i), i, &mut sp) {
                return r;
            }
        }

        if sp { Some(s.len()) } else { None }
    }
}

pub(crate) fn check_object_keyword(s: &str) -> Option<usize> {
    #[inline(always)]
    fn f(c: u8, i: usize, sp: &mut bool) -> Option<usize> {
        *sp = match (*sp, c) {
            (_, b'a'..=b'z' | b'A'..=b'Z' | b'0'..=b'9') | (false, b'-') => false,
            (false, b' ') => true,
            _ => return Some(i),
        };
        None
    }

    // SAFETY: It's more ergonomic to wrap the entire function in unsafe :D
    unsafe {
        let mut i = 0usize;
        let mut sp = true;
        let c = from_ref(s.as_bytes());

        // Should be impossible even with maximal allocation.
        // Rust don't allow pointer offset > isize::MAX.
        // But we do sanity check anyway.
        debug_assert_ne!(c.len(), usize::MAX);

        if c.addr() & 7 != 0 {
            // Head
            i = 8 - (c.addr() & 7);
            for i in 0..i {
                if i >= c.len() {
                    break;
                }
                if let r @ Some(_) = f(*get_unchecked(c, i), i, &mut sp) {
                    return r;
                }
            }
        }

        debug_assert_eq!(c.addr().wrapping_add(i) & 7, 0);

        // Main
        let mut sp = if sp { 128 } else { 0 };
        while i + 7 < c.len() {
            let v = u64::from_le(*get_unchecked(c, i).cast::<u64>());

            // Space and tab
            let mut st =
                test_eq_c::<0x2020_2020_2020_2020>(v) | test_eq_c::<0x0909_0909_0909_0909>(v);
            //dbg!(st);

            // -
            let dash = test_eq_c::<0x2d2d_2d2d_2d2d_2d2d>(v);
            //dbg!(dash);

            // A-Z and a-z
            let v_ = v & 0x5f5f_5f5f_5f5f_5f5f;
            let mut alnum =
                test_le_c::<0x4040_4040_4040_4040>(v_) | test_gt_c::<0x5a5a_5a5a_5a5a_5a5a>(v_);
            //dbg!(alnum);

            // Numbers
            let v_ = v & 0x7f7f_7f7f_7f7f_7f7f;
            let n = test_le_c::<0x2f2f_2f2f_2f2f_2f2f>(v_) | test_gt_c::<0x3939_3939_3939_3939>(v_);
            alnum &= n;
            //dbg!(n);

            alnum &= !(dash | st);

            // Lane is >= 128
            alnum |= v;
            alnum &= 0x8080_8080_8080_8080;
            //dbg!(alnum);

            // Space or tab followed by space, tab, or -
            debug_assert!(sp == 128 || sp == 0);
            st &= 0x8080_8080_8080_8080;
            let t_ = st << 8 | sp as u64;
            //dbg!(t_, sp);
            sp = (st >> (64 - 8)) as _;
            let t = (st | dash & 0x8080_8080_8080_8080) & t_ | alnum;

            let o = t.trailing_zeros();
            debug_assert!(o == 64 || o % 8 == 7);
            if let v @ 0..=7 = o / 8 {
                return Some(i + v as usize);
            }

            i += 8;
        }

        // Tail
        let mut sp = sp != 0;
        for i in i..c.len() {
            if let r @ Some(_) = f(*get_unchecked(c, i), i, &mut sp) {
                return r;
            }
        }

        if sp { Some(s.len()) } else { None }
    }
}

pub(crate) fn check_object_content(s: &str) -> Option<usize> {
    #[inline(always)]
    fn f(c: u8) -> bool {
        !matches!(c, b'a'..=b'z' | b'A'..=b'Z' | b'0'..=b'9' | b'+' | b'/' | b'=')
    }

    // SAFETY: It's more ergonomic to wrap the entire function in unsafe :D
    unsafe {
        let mut i = 0usize;
        let c = from_ref(s.as_bytes());

        // Should be impossible even with maximal allocation.
        // Rust don't allow pointer offset > isize::MAX.
        // But we do sanity check anyway.
        debug_assert_ne!(c.len(), usize::MAX);

        if c.addr() & 7 != 0 {
            // Head
            i = 8 - (c.addr() & 7);
            for i in 0..i {
                if i >= c.len() {
                    break;
                }
                if f(*get_unchecked(c, i)) {
                    return Some(i);
                }
            }
        }

        debug_assert_eq!(c.addr().wrapping_add(i) & 7, 0);

        // Main
        while i + 7 < c.len() {
            let v = u64::from_le(*get_unchecked(c, i).cast::<u64>());

            // +, /, =
            let mut t = test_ne_c::<0x2f2f_2f2f_2f2f_2f2f>(v | 0x0404_0404_0404_0404)
                & test_ne_c::<0x3d3d_3d3d_3d3d_3d3d>(v);
            //dbg!(t);

            // A-Z and a-z
            let v_ = v & 0x5f5f_5f5f_5f5f_5f5f;
            let n = test_le_c::<0x4040_4040_4040_4040>(v_) | test_gt_c::<0x5a5a_5a5a_5a5a_5a5a>(v_);
            t &= n;
            //dbg!(n);

            // Numbers
            let v_ = v & 0x7f7f_7f7f_7f7f_7f7f;
            let n = test_le_c::<0x2f2f_2f2f_2f2f_2f2f>(v_) | test_gt_c::<0x3939_3939_3939_3939>(v_);
            t &= n;
            //dbg!(n);

            // Lane is >= 128
            t |= v;
            //dbg!(t);

            let o = (t & 0x8080_8080_8080_8080).trailing_zeros();
            debug_assert!(o == 64 || o % 8 == 7);
            if let v @ 0..=7 = o / 8 {
                return Some(i + v as usize);
            }

            i += 8;
        }

        // Tail
        for i in i..c.len() {
            if f(*get_unchecked(c, i)) {
                return Some(i);
            }
        }
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::parse::netdoc::check::generic as reference;
    use crate::parse::netdoc::check::tests::aligned_str;

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
