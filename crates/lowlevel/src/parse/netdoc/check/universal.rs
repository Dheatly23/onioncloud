//! 64-bit universal SIMD variant.
#![allow(dead_code)]

use std::marker::PhantomData;
use std::ptr::{NonNull, from_ref, slice_from_raw_parts};

use super::get_unchecked;

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
        while i + 8 <= c.len() {
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

pub(crate) fn proto_keyword(s: &str) -> Result<usize, usize> {
    #[inline(always)]
    fn f(c: u8, i: usize) -> Option<Result<usize, usize>> {
        match c {
            b'a'..=b'z' | b'A'..=b'Z' | b'0'..=b'9' => None,
            b'-' if i != 0 => None,
            b'=' if i != 0 => Some(Ok(i)),
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
        while i + 8 <= c.len() {
            let v = u64::from_le(*get_unchecked(c, i).cast::<u64>());

            if i == 0 && matches!(v as u8, b'-' | b'=') {
                // First character is - or =
                return Err(0);
            }

            // =
            let eq = test_eq_c::<0x3d3d_3d3d_3d3d_3d3d>(v);
            //dbg!(eq);

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
            let o2 = (eq & 0x8080_8080_8080_8080).trailing_zeros();
            debug_assert!(o2 == 64 || o2 % 8 == 7);
            let v2 = o2 / 8;

            if v1 < v2 {
                // Non-matching character before =
                return Err(i + v1 as usize);
            } else if v2 < 8 {
                // =
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

    Err(s.len())
}

pub(crate) fn next_non_ws(s: &str) -> usize {
    #[inline(always)]
    fn f(c: u8, i: usize) -> Option<usize> {
        match c {
            b' ' | b'\t' => None,
            _ => Some(i),
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
                if let Some(r) = f(*get_unchecked(c, i), i) {
                    return r;
                }
            }
        }

        debug_assert_eq!(c.addr().wrapping_add(i) & 7, 0);

        // Main
        while i + 8 <= c.len() {
            let v = u64::from_le(*get_unchecked(c, i).cast::<u64>());

            // Space and tab test
            let t = test_ne_c::<0x2020_2020_2020_2020>(v)
                & test_ne_c::<0x0909_0909_0909_0909>(v)
                & 0x8080_8080_8080_8080;
            let o = t.trailing_zeros() / 8;
            if o < 8 {
                return i + o as usize;
            }

            i += 8;
        }

        // Tail
        for i in i..c.len() {
            if let Some(r) = f(*get_unchecked(c, i), i) {
                return r;
            }
        }
    }

    s.len()
}

pub(crate) fn check_argument(s: &str) -> Option<usize> {
    if matches!(s.as_bytes().first(), Some(b' ' | b'\t')) {
        return Some(0);
    }

    #[inline(always)]
    fn f(c: u8, i: usize) -> Option<usize> {
        match c {
            b'\0' | b'\n' => Some(i),
            _ => None,
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
                if let r @ Some(_) = f(*get_unchecked(c, i), i) {
                    return r;
                }
            }
        }

        debug_assert_eq!(c.addr().wrapping_add(i) & 7, 0);

        // Main
        while i + 8 <= c.len() {
            let v = u64::from_le(*get_unchecked(c, i).cast::<u64>());

            // Null and newline test
            let t =
                (test_eq_c::<0>(v) | test_eq_c::<0x0a0a_0a0a_0a0a_0a0a>(v)) & 0x8080_8080_8080_8080;
            let o = t.trailing_zeros() / 8;
            if o < 8 {
                return Some(i + o as usize);
            }

            i += 8;
        }

        // Tail
        for i in i..c.len() {
            if let r @ Some(_) = f(*get_unchecked(c, i), i) {
                return r;
            }
        }
    }

    if matches!(s.as_bytes().last(), Some(b' ' | b'\t')) {
        return Some(s.len() - 1);
    }

    None
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
        while i + 8 <= c.len() {
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
        while i + 8 <= c.len() {
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

#[derive(Debug, Clone, Copy)]
pub(crate) struct ArgIterInner<'a> {
    p: NonNull<u8>,
    #[cfg(debug_assertions)]
    l: usize,
    i: usize,
    e: usize,
    bs: u8,
    be: u8,
    os: u8,
    oe: u8,
    t: u8,
    _p: PhantomData<&'a str>,
}

impl<'a> From<&'a str> for ArgIterInner<'a> {
    fn from(s: &'a str) -> Self {
        let p = NonNull::from(s.as_bytes()).cast();
        Self {
            p,
            #[cfg(debug_assertions)]
            l: s.len(),
            i: 0,
            e: s.len(),
            bs: 0,
            be: 0,
            os: 8,
            oe: 8,
            t: (p.as_ptr().addr().wrapping_neg() & 7) as u8,
            _p: PhantomData,
        }
    }
}

impl ArgIterInner<'_> {
    #[inline(always)]
    fn process_batch(v: u64) -> u8 {
        // Space and tab
        let t = ((test_eq_c::<0x2020_2020_2020_2020>(v) | test_eq_c::<0x0909_0909_0909_0909>(v))
            >> 7)
            & 0x0101_0101_0101_0101;
        let t = t as u32 | (t >> (32 - 4)) as u32;
        let t = t as u16 | (t >> (16 - 2)) as u16;
        t as u8 | (t >> (8 - 1)) as u8
    }

    fn forward(&mut self, ws: bool) {
        let e = self.end_ix();
        while self.i < e {
            // SAFETY: It's more ergonomic to wrap the entire function in unsafe :D
            unsafe {
                if self.i & 7 == self.t as usize {
                    // Main
                    while self.i + 8 <= e {
                        if self.os == 8 {
                            // Load batch
                            debug_assert_eq!(self.p.as_ptr().add(self.i).addr() & 7, 0);
                            let v = u64::from_le(*self.p.as_ptr().add(self.i).cast::<u64>());
                            self.bs = Self::process_batch(v);
                            self.os = 0;
                        }

                        self.os = (if ws { self.bs } else { !self.bs } & 0xff << self.os)
                            .trailing_zeros() as _;
                        if self.os < 8 {
                            return;
                        }
                        self.i += 8;
                    }
                }

                debug_assert_eq!(self.os, 8);
                // Head and tail
                while self.i < e {
                    if matches!(*self.p.as_ptr().add(self.i), b' ' | b'\t') ^ !ws {
                        return;
                    }
                    self.i += 1;
                    // Break when pointer is aligned
                    if self.i & 7 == self.t as usize {
                        break;
                    }
                }
            }
        }
    }

    fn backward(&mut self, ws: bool) {
        let i = self.start_ix();
        while i < self.e {
            // SAFETY: It's more ergonomic to wrap the entire function in unsafe :D
            unsafe {
                if self.e & 7 == self.t as usize {
                    // Main
                    while let Some(e) = self.e.checked_sub(8)
                        && i <= e
                    {
                        if self.oe == 8 {
                            // Load batch
                            debug_assert_eq!(self.p.as_ptr().add(self.e - 8).addr() & 7, 0);
                            let v = u64::from_be(*self.p.as_ptr().add(self.e - 8).cast::<u64>());
                            self.be = Self::process_batch(v);
                            self.oe = 0;
                        }

                        self.oe = (if ws { self.be } else { !self.be } & 0xff << self.oe)
                            .trailing_zeros() as _;
                        if self.oe < 8 {
                            return;
                        }
                        self.e -= 8;
                    }
                }

                debug_assert_eq!(self.oe, 8);
                // Head and tail
                while i < self.e {
                    if matches!(*self.p.as_ptr().add(self.e - 1), b' ' | b'\t') ^ !ws {
                        return;
                    }
                    self.e -= 1;
                    // Break when pointer is aligned
                    if self.e & 7 == self.t as usize {
                        break;
                    }
                }
            }
        }
    }

    fn start_ix(&self) -> usize {
        self.i + (self.os & 7) as usize
    }

    fn end_ix(&self) -> usize {
        self.e - (self.oe & 7) as usize
    }
}

impl<'a> Iterator for ArgIterInner<'a> {
    type Item = &'a str;

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

        #[cfg(debug_assertions)]
        {
            debug_assert!(s <= self.l, "{s} > {}", self.l);
            debug_assert!(m <= self.l, "{m} > {}", self.l);
        }

        // SAFETY: Indices are valid
        unsafe {
            let s = &*slice_from_raw_parts(self.p.as_ptr().add(s), m - s);
            if cfg!(debug_assertions) {
                str::from_utf8(s).unwrap();
            }
            Some(str::from_utf8_unchecked(s))
        }
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        if self.end_ix() <= self.start_ix() {
            (0, Some(0))
        } else {
            (1, None)
        }
    }
}

impl<'a> DoubleEndedIterator for ArgIterInner<'a> {
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

        #[cfg(debug_assertions)]
        {
            debug_assert!(s <= self.l, "{s} > {}", self.l);
            debug_assert!(m <= self.l, "{m} > {}", self.l);
        }

        // SAFETY: Indices are valid
        unsafe {
            let s = &*slice_from_raw_parts(self.p.as_ptr().add(m), e - m);
            if cfg!(debug_assertions) {
                str::from_utf8(s).unwrap();
            }
            Some(str::from_utf8_unchecked(s))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use super::super::generic as reference;
    use super::super::tests::{aligned_arg_str, aligned_str};

    use proptest::prelude::*;

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
