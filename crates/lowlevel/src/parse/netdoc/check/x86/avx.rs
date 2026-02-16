use std::fmt::{Formatter, Result as FmtResult};
use std::mem::transmute;
use std::ptr::{NonNull, from_ref};

use super::super::get_unchecked;
use super::{IterUnion, arch};

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
        while i + 32 <= c.len() {
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
        while i + 32 <= c.len() {
            let v = arch::_mm256_loadu_si256(get_unchecked(c, i).cast());

            if i == 0 && matches!(arch::_mm256_extract_epi8(v, 0) as u8, b'-' | b'=') {
                // First character is - or =
                return Err(0);
            }

            // =
            let eq = arch::_mm256_cmpeq_epi8(v, arch::_mm256_set1_epi8(b'=' as _));

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
            let v2 = (arch::_mm256_movemask_epi8(eq) as u32).trailing_zeros();

            if v1 < v2 {
                // Non-matching character before =
                return Err(i + v1 as usize);
            } else if v2 < 32 {
                // =
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
                b'=' if i != 0 => return Ok(i),
                _ => return Err(i),
            }
        }
    }

    Err(s.len())
}

#[target_feature(enable = "avx2")]
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
        while i + 32 <= c.len() {
            let v = arch::_mm256_loadu_si256(get_unchecked(c, i).cast());

            if i == 0 {
                let v_ = arch::_mm_movemask_epi8(arch::_mm_cmpeq_epi8(
                    arch::_mm_shuffle_epi32(arch::_mm256_extractf128_si256(v, 0), 0b01_00_01_00),
                    arch::_mm_setr_epi8(
                        b'<' as _, b'O' as _, b'R' as _, b'>' as _, b'=' as _, 0, 0, 0, b'<' as _,
                        b'?' as _, b'?' as _, b'>' as _, b'=' as _, 0, 0, 0,
                    ),
                )) as u32 as u16
                    & 0x1f1f;
                if v_ as u8 == 0x1f || (v_ >> 8) as u8 == 0x1f {
                    // String is lead by <OR>= or <??>=
                    return Ok(4);
                } else if matches!(arch::_mm256_extract_epi8(v, 0) as u8, b'0'..=b'9' | b'=') {
                    // First character is 0-9 or =
                    return Err(0);
                }
            }

            // =
            let eq = arch::_mm256_cmpeq_epi8(v, arch::_mm256_set1_epi8(b'=' as _));

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

            // _
            let n = arch::_mm256_cmpeq_epi8(v, arch::_mm256_set1_epi8(b'_' as _));
            t = arch::_mm256_andnot_si256(n, t);

            let v1 = (arch::_mm256_movemask_epi8(t) as u32).trailing_zeros();
            let v2 = (arch::_mm256_movemask_epi8(eq) as u32).trailing_zeros();

            if v1 < v2 {
                // Non-matching character before =
                return Err(i + v1 as usize);
            } else if v2 < 32 {
                // =
                return Ok(i + v2 as usize);
            }
            debug_assert_eq!(v1, 32);
            debug_assert_eq!(v2, 32);

            i += 32;
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
                b'a'..=b'z' | b'A'..=b'Z' | b'_' => (),
                b'0'..=b'9' if i != 0 => (),
                b'=' if i != 0 => return Ok(i),
                _ => return Err(i),
            }
        }
    }

    Err(s.len())
}

#[target_feature(enable = "avx2")]
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
        while i + 32 <= c.len() {
            let v = arch::_mm256_loadu_si256(get_unchecked(c, i).cast());

            // Space and tab
            let t = !arch::_mm256_movemask_epi8(arch::_mm256_or_si256(
                arch::_mm256_cmpeq_epi8(v, arch::_mm256_set1_epi8(b' ' as _)),
                arch::_mm256_cmpeq_epi8(v, arch::_mm256_set1_epi8(b'\t' as _)),
            )) as u32;
            if let v @ 0..=31 = t.trailing_zeros() {
                return i + v as usize;
            }

            i += 32;
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

#[target_feature(enable = "avx2")]
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
        while i + 32 <= c.len() {
            let v = arch::_mm256_loadu_si256(get_unchecked(c, i).cast());

            // Null and newline test
            let t = arch::_mm256_movemask_epi8(arch::_mm256_or_si256(
                arch::_mm256_cmpeq_epi8(v, arch::_mm256_setzero_si256()),
                arch::_mm256_cmpeq_epi8(v, arch::_mm256_set1_epi8(b'\n' as _)),
            )) as u32;
            if let v @ 0..=31 = t.trailing_zeros() {
                return Some(i + v as usize);
            }

            i += 32;
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
        while i + 32 <= c.len() {
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
        while i + 32 <= c.len() {
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

#[derive(Clone, Copy)]
pub(crate) struct ArgIterInner {
    s: &'static str,
    i: usize,
    e: usize,
    bs: u32,
    be: u32,
}

impl ArgIterInner {
    #[target_feature(enable = "avx2")]
    #[inline]
    fn process_batch(v: *const u8) -> u32 {
        let v = unsafe { arch::_mm256_loadu_si256(v.cast()) };
        // Space and tab
        arch::_mm256_movemask_epi8(arch::_mm256_or_si256(
            arch::_mm256_cmpeq_epi8(v, arch::_mm256_set1_epi8(b' ' as _)),
            arch::_mm256_cmpeq_epi8(v, arch::_mm256_set1_epi8(b'\t' as _)),
        )) as _
    }

    #[target_feature(enable = "avx2")]
    fn forward(&mut self, ws: bool) {
        let c = from_ref(self.s.as_bytes());
        // SAFETY: It's more ergonomic to wrap the entire function in unsafe :D
        unsafe {
            // Main
            while self.i < self.e && (self.i & !31) + 32 <= c.len() {
                let o = self.i & 31;
                if o == 0 {
                    // Load batch
                    self.bs = Self::process_batch(get_unchecked(c, self.i));
                }

                let o =
                    (if ws { self.bs } else { !self.bs } & u32::MAX << o).trailing_zeros() as usize;
                // If o is 32 it will advance i
                self.i = (self.i & !31) + o;
                if o < 32 {
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

    #[target_feature(enable = "avx2")]
    fn backward(&mut self, ws: bool) {
        let c = from_ref(self.s.as_bytes());
        // SAFETY: It's more ergonomic to wrap the entire function in unsafe :D
        unsafe {
            // Head
            while self.i < self.e && self.e > c.len() & !31 {
                if matches!(*get_unchecked(c, self.e - 1), b' ' | b'\t') ^ !ws {
                    return;
                }
                self.e -= 1;
            }

            // Main
            while self.i < self.e {
                let o = self.e.wrapping_neg() & 31;
                if o == 0 {
                    // Load batch
                    self.e -= 32;
                    self.be = Self::process_batch(get_unchecked(c, self.e));
                }

                let o = (if ws { self.be } else { !self.be } & (u32::MAX >> o)).leading_zeros()
                    as usize;
                // If o is 32 it will advance e
                self.e = (self.e & !31) + (32 - o);
                if o < 32 {
                    return;
                }
            }
        }
    }
}

#[target_feature(enable = "avx2")]
pub(crate) fn new(s: &str) -> IterUnion {
    IterUnion {
        avx: ArgIterInner {
            s: unsafe { transmute::<&str, &'static str>(s) },
            i: 0,
            e: s.len(),
            bs: 0,
            be: 0,
        },
    }
}

#[target_feature(enable = "avx2")]
pub(crate) fn fmt(it: NonNull<IterUnion>, f: &mut Formatter<'_>) -> FmtResult {
    let p = unsafe { &(*it.as_ptr()).avx };
    f.debug_struct("ArgIterInner")
        .field("i", &p.i)
        .field("e", &p.e)
        .field("bs", &p.bs)
        .field("be", &p.be)
        .field("sp", &p.s.get(p.i..p.e))
        .finish_non_exhaustive()
}

#[target_feature(enable = "avx2")]
pub(crate) fn next(it: NonNull<IterUnion>) -> Option<NonNull<str>> {
    // SAFETY: It's more ergonomic to wrap the entire function in unsafe :D
    unsafe {
        let p = &mut (*it.as_ptr()).avx;

        let s = p.i;
        let e = p.e;
        debug_assert!(s <= e, "{s} > {e}");

        if s >= e {
            return None;
        }

        p.forward(true);
        let m = p.i;
        debug_assert!(m <= e, "{m} > {e}");
        debug_assert!(m >= s, "{m} < {s}");
        if m < e {
            // Skip whitespace
            p.forward(false);
        }

        Some(p.s.get_unchecked(s..m).into())
    }
}

#[target_feature(enable = "avx2")]
pub(crate) fn size_hint(it: NonNull<IterUnion>) -> (usize, Option<usize>) {
    // SAFETY: It's more ergonomic to wrap the entire function in unsafe :D
    unsafe {
        let p = &mut (*it.as_ptr()).avx;
        if p.e <= p.i { (0, Some(0)) } else { (1, None) }
    }
}

#[target_feature(enable = "avx2")]
pub(crate) fn next_back(it: NonNull<IterUnion>) -> Option<NonNull<str>> {
    // SAFETY: It's more ergonomic to wrap the entire function in unsafe :D
    unsafe {
        let p = &mut (*it.as_ptr()).avx;

        let s = p.i;
        let e = p.e;
        debug_assert!(s <= e, "{s} > {e}");

        if s >= e {
            return None;
        }

        p.backward(true);
        let m = p.e;
        debug_assert!(m >= s, "{m} < {s}");
        debug_assert!(m <= e, "{m} > {e}");
        if m > s {
            // Skip whitespace
            p.backward(false);
        }

        Some(p.s.get_unchecked(m..e).into())
    }
}
