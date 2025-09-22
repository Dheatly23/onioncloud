//! x86 SIMD variant.
#![cfg(any(target_arch = "x86", target_arch = "x86_64"))]

mod sse;

use std::arch::is_x86_feature_detected;
#[cfg(target_arch = "x86")]
use std::arch::x86 as arch;
#[cfg(target_arch = "x86_64")]
use std::arch::x86_64 as arch;
use std::ptr::{NonNull, null_mut};
use std::sync::atomic::{AtomicPtr, Ordering::*};

use super::{FPtrs, universal};

static FP: AtomicPtr<FPtrs> = AtomicPtr::new(null_mut());

fn get_fptr() -> NonNull<FPtrs> {
    if let Some(p) = NonNull::new(FP.load(Acquire)) {
        return p;
    }

    let p = NonNull::from(if is_x86_feature_detected!("sse2") {
        // SAFETY: SSSE3 is enabled
        static FP: FPtrs = unsafe {
            FPtrs {
                check_line: |v| sse::check_line(v),
                check_argument: |v| sse::check_argument(v),
                check_object_keyword: |v| sse::check_object_keyword(v),
                check_object_content: |v| sse::check_object_content(v),
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
        let is_sse = is_x86_feature_detected!("sse2");

        if is_sse {
            proptest!(|(s: String)| {
                let r = reference::check_line(&s);
                if is_sse {
                    assert_eq!(r, check_line(&s));
                }
            });
        }
    }

    #[test]
    fn test_check_argument() {
        let is_sse = is_x86_feature_detected!("sse2");

        if is_sse {
            proptest!(|(s in any::<String>().prop_filter("string is empty", |s| !s.is_empty()))| {
                let r = reference::check_argument(&s);
                if is_sse {
                    assert_eq!(r, check_argument(&s));
                }
            });
        }
    }

    #[test]
    fn test_check_object_keyword() {
        let is_sse = is_x86_feature_detected!("sse2");

        if is_sse {
            proptest!(|(s: String)| {
                let r = reference::check_object_keyword(&s);
                if is_sse {
                    assert_eq!(r, check_object_keyword(&s));
                }
            });
        }
    }

    #[test]
    fn test_check_object_content() {
        let is_sse = is_x86_feature_detected!("sse2");

        if is_sse {
            proptest!(|(s: String)| {
                let r = reference::check_object_content(&s);
                if is_sse {
                    assert_eq!(r, check_object_content(&s));
                }
            });
        }
    }
}
