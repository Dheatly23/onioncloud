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
        while i + 16 <= c.len() {
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
            let v = arch::vld1q_u8(get_unchecked(c, i));

            if i == 0 && matches!(arch::vgetq_lane_u8(v, 0), b'-' | b'=') {
                // First character is - or =
                return Err(0);
            }

            // =
            let eq = arch::vceqq_u8(v, arch::vdupq_n_u8(b'='));

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
            let v2 = movemask(eq).trailing_zeros();

            if v1 < v2 {
                // Non-matching character before =
                return Err(i + v1 as usize);
            } else if v2 < 16 {
                // =
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
            let v = arch::vld1q_u8(get_unchecked(c, i));

            if i == 0 {
                const C: [u8; 16] = b"<OR>=\0\0\0<??>=\0\0\0";
                let v_ = movemask(arch::vceqq_u8(
                    arch::vreinterpretq_u64_u8(arch::vdupq_laneq_u64(
                        arch::vreinterpretq_u8_u64(v),
                        0b01_00_01_00,
                    )),
                    arch::vld1q_u8(from_ref(&C).cast()),
                )) as u32 as u16
                    & 0x1f1f;
                if v_ as u8 == 0x1f || (v_ >> 8) as u8 == 0x1f {
                    // String is lead by <OR>= or <??>=
                    return Ok(4);
                } else if matches!(arch::vgetq_lane_u8(v, 0), b'0'..=b'9' | b'=') {
                    // First character is 0-9 or =
                    return Err(0);
                }
            }

            // =
            let eq = arch::vceqq_u8(v, arch::vdupq_n_u8(b'='));

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

            // _
            let n = arch::vceqq_u8(v, arch::vdupq_n_u8(b'_'));
            t = arch::vbicq_u8(t, n);

            let v1 = movemask(t).trailing_zeros();
            let v2 = movemask(eq).trailing_zeros();

            if v1 < v2 {
                // Non-matching character before =
                return Err(i + v1 as usize);
            } else if v2 < 16 {
                // =
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
                b' ' | b'\t' => return Ok(i),
                _ => return Err(i),
            }
        }
    }

    Ok(s.len())
}

#[target_feature(enable = "neon")]
pub(crate) fn next_non_ws(s: &str) -> Option<usize> {
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
        while i + 16 <= c.len() {
            let v = arch::vld1q_u8(get_unchecked(c, i));

            // Space and tab
            let t = movemask(arch::vandq_u8(
                arch::vcntq_u8(v, arch::vdupq_n_u8(b' ')),
                arch::vcntq_u8(v, arch::vdupq_n_u8(b'\t')),
            ));
            if let v @ 0..=15 = t.trailing_zeros() {
                return Some(i + v as usize);
            }

            i += 16;
        }

        // Tail
        for i in i..c.len() {
            if !matches!(*get_unchecked(c, i), b' ' | b'\t') {
                return Some(i);
            }
        }
    }

    s.len()
}

#[target_feature(enable = "neon")]
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
        let mut sp = true;
        while i + 16 <= c.len() {
            let v = arch::vld1q_u8(get_unchecked(c, i));

            // Null and newline test
            let t = movemask(arch::vorrq_u8(
                arch::vceqq_u8(v, arch::vdupq_n_u8(0)),
                arch::vceqq_u8(v, arch::vdupq_n_u8(b'\n')),
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
        while i + 16 <= c.len() {
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
        while i + 16 <= c.len() {
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

#[derive(Clone, Copy)]
pub(crate) struct ArgIterInner {
    s: &'static str,
    i: usize,
    e: usize,
    bs: u16,
    be: u16,
}

impl ArgIterInner {
    #[target_feature(enable = "neon")]
    #[inline]
    fn process_batch(v: *const u8) -> u16 {
        let v = unsafe { arch::vld1q_u8(v) };
        // Space and tab
        movemask(arch::vorrq_u8(
            arch::vceqq_u8(v, arch::vdup1_n_u8(b' ')),
            arch::vceqq_u8(v, arch::vdup1_n_u8(b'\t')),
        ))
    }

    #[target_feature(enable = "neon")]
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

    #[target_feature(enable = "neon")]
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

#[target_feature(enable = "neon")]
pub(crate) fn new(s: &str) -> IterUnion {
    IterUnion {
        neon: ArgIterInner {
            s: unsafe { transmute::<&str, &'static str>(s) },
            i: 0,
            e: s.len(),
            bs: 0,
            be: 0,
        },
    }
}

#[target_feature(enable = "neon")]
pub(crate) fn fmt(it: NonNull<IterUnion>, f: &mut Formatter<'_>) -> FmtResult {
    let p = unsafe { &(*it.as_ptr()).neon };
    f.debug_struct("ArgIterInner")
        .field("i", &p.i)
        .field("e", &p.e)
        .field("bs", &p.bs)
        .field("be", &p.be)
        .field("sp", &p.s.get(p.i..p.e))
        .finish_non_exhaustive()
}

#[target_feature(enable = "neon")]
pub(crate) fn next(it: NonNull<IterUnion>) -> Option<NonNull<str>> {
    // SAFETY: It's more ergonomic to wrap the entire function in unsafe :D
    unsafe {
        let p = &mut (*it.as_ptr()).neon;

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

#[target_feature(enable = "neon")]
pub(crate) fn size_hint(it: NonNull<IterUnion>) -> (usize, Option<usize>) {
    // SAFETY: It's more ergonomic to wrap the entire function in unsafe :D
    unsafe {
        let p = &mut (*it.as_ptr()).neon;
        if p.e <= p.i { (0, Some(0)) } else { (1, None) }
    }
}

#[target_feature(enable = "neon")]
pub(crate) fn next_back(it: NonNull<IterUnion>) -> Option<NonNull<str>> {
    // SAFETY: It's more ergonomic to wrap the entire function in unsafe :D
    unsafe {
        let p = &mut (*it.as_ptr()).neon;

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
