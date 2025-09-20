mod generic;
mod universal;

#[cfg(any(target_pointer_width = "32", target_pointer_width = "16"))]
pub(crate) use generic::*;
#[cfg(not(any(target_pointer_width = "32", target_pointer_width = "16")))]
pub(crate) use universal::*;

#[cfg(test)]
mod tests {
    use std::fmt::{Debug, Formatter, Result as FmtResult};
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
            let len = self.arr.len() - 7;
            let off = self.off as usize;

            // SAFETY: Array must be 7 + string length and offset is < 8
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

    pub(crate) fn aligned_str() -> impl Strategy<Value = (AlignedStr, u8)> {
        (any::<String>(), 0..=7u8).prop_map(|(s, off)| {
            let mut arr = Box::new_uninit_slice(s.len() + 7);

            // SAFETY: Slice is non-overlapping and offset is < 8
            unsafe {
                copy_nonoverlapping(
                    s.as_ptr(),
                    arr.as_mut_ptr().cast::<u8>().add(off as usize),
                    s.len(),
                )
            }

            (AlignedStr { arr, off }, off)
        })
    }
}
