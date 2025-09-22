//! aarch64 SIMD variant.
#![cfg(target_arch = "aarch64")]

mod neon;

#[cfg(target_arch = "aarch64")]
use std::arch::aarch64 as arch;
use std::arch::is_aarch64_feature_detected;
use std::ptr::{NonNull, null_mut};
use std::sync::atomic::{AtomicPtr, Ordering::*};

use super::{FPtrs, universal};

static FP: AtomicPtr<FPtrs> = AtomicPtr::new(null_mut());

fn get_fptr() -> NonNull<FPtrs> {
    if let Some(p) = NonNull::new(FP.load(Acquire)) {
        return p;
    }

    let p = NonNull::from(if is_aarch64_feature_detected!("neon") {
        // SAFETY: NEON is enabled
        static FP: FPtrs = unsafe {
            FPtrs {
                check_line: |v| neon::check_line(v),
                check_argument: |v| neon::check_argument(v),
                check_object_keyword: |v| neon::check_object_keyword(v),
                check_object_content: |v| neon::check_object_content(v),
            }
        };
        &FP
    } else {
        static FP: FPtrs = FPtrs {
            check_line: universal::check_line,
            check_argument: universal::check_argument,
            check_object_keyword: universal::check_object_keyword,
            check_object_content: universal::check_object_content,
        };
        &FP
    });

    FP.store(p.as_ptr(), Release);
    p
}

pub(crate) fn check_line(s: &str) -> Result<usize, usize> {
    unsafe { (get_fptr().as_ref().check_line)(s) }
}

pub(crate) fn check_argument(s: &str) -> Option<usize> {
    unsafe { (get_fptr().as_ref().check_argument)(s) }
}

pub(crate) fn check_object_keyword(s: &str) -> Option<usize> {
    unsafe { (get_fptr().as_ref().check_object_keyword)(s) }
}

pub(crate) fn check_object_content(s: &str) -> Option<usize> {
    unsafe { (get_fptr().as_ref().check_object_content)(s) }
}

#[cfg(test)]
mod tests {
    use super::*;

    use super::super::generic as reference;

    use proptest::prelude::*;

    #[test]
    fn test_check_line() {
        let is_neon = is_aarch64_feature_detected!("neon");

        if is_neon {
            proptest!(|(s: String)| {
                let r = reference::check_line(&s);
                if is_neon {
                    assert_eq!(r, unsafe { neon::check_line(&s) });
                }
            });
        }
    }

    #[test]
    fn test_check_argument() {
        let is_neon = is_aarch64_feature_detected!("neon");

        if is_neon {
            proptest!(|(s: String)| {
                let r = reference::check_argument(&s);
                if is_neon {
                    assert_eq!(r, unsafe { neon::check_argument(&s) });
                }
            });
        }
    }

    #[test]
    fn test_check_object_keyword() {
        let is_neon = is_aarch64_feature_detected!("neon");

        if is_neon {
            proptest!(|(s: String)| {
                let r = reference::check_object_keyword(&s);
                if is_neon {
                    assert_eq!(r, unsafe { neon::check_object_keyword(&s) });
                }
            });
        }
    }

    #[test]
    fn test_check_object_content() {
        let is_neon = is_aarch64_feature_detected!("neon");

        if is_neon {
            proptest!(|(s: String)| {
                let r = reference::check_object_content(&s);
                if is_neon {
                    assert_eq!(r, unsafe { neon::check_object_content(&s) });
                }
            });
        }
    }
}
