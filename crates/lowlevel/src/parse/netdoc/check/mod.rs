mod aarch64;
mod generic;
mod universal;
mod wasm;
mod x86;

use std::fmt::{Formatter, Result as FmtResult};
use std::ptr::NonNull;

cfg_if::cfg_if! {
    if #[cfg(any(target_arch = "x86", target_arch = "x86_64"))] {
        pub(crate) use x86::*;
    } else if #[cfg(target_arch = "aarch64")] {
        pub(crate) use aarch64::*;
    } else if #[cfg(all(target_family = "wasm", target_feature = "simd128"))] {
        pub(crate) use wasm::*;
    } else if #[cfg(any(target_pointer_width = "32", target_pointer_width = "16"))] {
        pub(crate) use generic::*;
    } else {
        pub(crate) use universal::*;
    }
}

/// Stable implementation of `pointer::get_unchecked`.
#[track_caller]
#[inline(always)]
unsafe fn get_unchecked<T>(p: *const [T], i: usize) -> *const T {
    debug_assert!(i < p.len());
    unsafe { (p as *const T).add(i) }
}

#[allow(dead_code, clippy::type_complexity)]
struct FPtrs<It> {
    check_line: fn(s: &str) -> Result<usize, usize>,
    proto_keyword: fn(s: &str) -> Result<usize, usize>,
    next_non_ws: fn(s: &str) -> usize,
    check_argument: fn(s: &str) -> Option<usize>,
    check_object_keyword: fn(s: &str) -> Option<usize>,
    check_object_content: fn(s: &str) -> Option<usize>,
    new: fn(s: &str) -> It,
    fmt: fn(it: NonNull<It>, f: &mut Formatter<'_>) -> FmtResult,
    next: fn(it: NonNull<It>) -> Option<NonNull<str>>,
    size_hint: fn(it: NonNull<It>) -> (usize, Option<usize>),
    next_back: fn(it: NonNull<It>) -> Option<NonNull<str>>,
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::fmt::Debug;
    use std::mem::MaybeUninit;
    use std::ops::Deref;
    use std::ptr::copy_nonoverlapping;
    use std::slice::from_raw_parts;

    use proptest::prelude::*;

    pub(crate) struct AlignedStr {
        arr: Box<[MaybeUninit<u8>]>,
        off: u8,
    }

    impl Deref for AlignedStr {
        type Target = str;

        fn deref(&self) -> &str {
            let len = self.arr.len() - 31;
            let off = self.off as usize;

            // SAFETY: Array must be 7 + string length and offset is < 32
            unsafe {
                let p = self.arr.as_ptr().cast::<u8>().add(off);
                str::from_utf8_unchecked(from_raw_parts(p, len))
            }
        }
    }

    impl Debug for AlignedStr {
        fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
            write!(f, "{:?}", &**self)
        }
    }

    pub(crate) fn align_str(
        s: impl Strategy<Value = String>,
    ) -> impl Strategy<Value = (AlignedStr, u8)> {
        (s, 0..=31u8).prop_map(|(s, off)| {
            let mut arr = Box::new_uninit_slice(s.len() + 31);

            let p = arr.as_mut_ptr().cast::<u8>();
            let o = off.wrapping_sub(p.addr() as _) & 31;

            // SAFETY: Slice is non-overlapping and offset is < 32
            unsafe { copy_nonoverlapping(s.as_ptr(), p.add(o as usize), s.len()) }

            let s = AlignedStr { arr, off: o };
            let p: &str = &s;
            assert_eq!(p.as_bytes().as_ptr().cast::<u8>().addr() & 31, off as usize);

            (s, off)
        })
    }

    pub(crate) fn aligned_str() -> impl Strategy<Value = (AlignedStr, u8)> {
        align_str(any::<String>())
    }

    pub(crate) fn aligned_arg_str() -> impl Strategy<Value = (AlignedStr, u8)> {
        align_str("[^\0\n \t]+([ \t]+[^\0\n \t]+)*")
    }
}
