//! aarch64 SIMD variant.
#![cfg(target_arch = "aarch64")]

mod neon;

#[cfg(target_arch = "aarch64")]
use std::arch::aarch64 as arch;
use std::arch::is_aarch64_feature_detected;
use std::fmt::{Debug, Formatter, Result as FmtResult};
use std::marker::PhantomData;
use std::mem::transmute;
use std::ptr::{NonNull, null_mut};
use std::sync::atomic::{AtomicPtr, Ordering::*};

use super::universal;

type FPtrs = super::FPtrs<IterUnion>;

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
                proto_keyword: |v| neon::proto_keyword(v),
                pt_keyword: |v| neon::pt_keyword(v),
                next_non_ws: |v| neon::next_non_ws(v),
                check_argument: |v| neon::check_argument(v),
                check_object_keyword: |v| neon::check_object_keyword(v),
                check_object_content: |v| neon::check_object_content(v),
                new: |v| neon::new(v),
                fmt: |v, f| neon::fmt(v, f),
                next: |v| neon::next(v),
                size_hint: |v| neon::size_hint(v),
                next_back: |v| neon::next_back(v),
            }
        };
        &FP
    } else {
        static FP: FPtrs = FPtrs {
            check_line: universal::check_line,
            proto_keyword: universal::proto_keyword,
            pt_keyword: universal::pt_keyword,
            next_non_ws: universal::next_non_ws,
            check_argument: universal::check_argument,
            check_object_keyword: universal::check_object_keyword,
            check_object_content: universal::check_object_content,
            new,
            fmt,
            next,
            size_hint,
            next_back,
        };
        &FP
    });

    FP.store(p.as_ptr(), Release);
    p
}

pub(crate) fn check_line(s: &str) -> Result<usize, usize> {
    unsafe { (get_fptr().as_ref().check_line)(s) }
}

pub(crate) fn proto_keyword(s: &str) -> Result<usize, usize> {
    unsafe { (get_fptr().as_ref().proto_keyword)(s) }
}

pub(crate) fn pt_keyword(s: &str) -> Result<usize, usize> {
    unsafe { (get_fptr().as_ref().pt_keyword)(s) }
}

pub(crate) fn next_non_ws(s: &str) -> usize {
    unsafe { (get_fptr().as_ref().next_non_ws)(s) }
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

fn new(s: &str) -> IterUnion {
    IterUnion {
        universal: unsafe { transmute::<&str, &'static str>(s).into() },
    }
}

fn fmt(it: NonNull<IterUnion>, f: &mut Formatter<'_>) -> FmtResult {
    unsafe { Debug::fmt(&(*it.as_ptr()).universal, f) }
}

fn next(it: NonNull<IterUnion>) -> Option<NonNull<str>> {
    unsafe { (*it.as_ptr()).universal.next().map(NonNull::from) }
}

fn size_hint(it: NonNull<IterUnion>) -> (usize, Option<usize>) {
    unsafe { (*it.as_ptr()).universal.size_hint() }
}

fn next_back(it: NonNull<IterUnion>) -> Option<NonNull<str>> {
    unsafe { (*it.as_ptr()).universal.next_back().map(NonNull::from) }
}

#[derive(Copy)]
union IterUnion {
    universal: universal::ArgIterInner<'static>,
    neon: neon::ArgIterInner,
}

impl Clone for IterUnion {
    fn clone(&self) -> Self {
        *self
    }
}

#[derive(Clone, Copy)]
pub(crate) struct ArgIterInner<'a> {
    inner: IterUnion,
    _p: PhantomData<&'a str>,
}

impl<'a> From<&'a str> for ArgIterInner<'a> {
    fn from(s: &'a str) -> Self {
        Self {
            inner: unsafe { (get_fptr().as_ref().new)(s) },
            _p: PhantomData,
        }
    }
}

impl Debug for ArgIterInner<'_> {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        unsafe { (get_fptr().as_ref().fmt)((&self.inner).into(), f) }
    }
}

impl<'a> Iterator for ArgIterInner<'a> {
    type Item = &'a str;

    fn next(&mut self) -> Option<Self::Item> {
        unsafe { (get_fptr().as_ref().next)((&self.inner).into()).map(|v| &*v.as_ptr()) }
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        unsafe { (get_fptr().as_ref().size_hint)((&self.inner).into()) }
    }
}

impl<'a> DoubleEndedIterator for ArgIterInner<'a> {
    fn next_back(&mut self) -> Option<Self::Item> {
        unsafe { (get_fptr().as_ref().next_back)((&self.inner).into()).map(|v| &*v.as_ptr()) }
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
        if is_aarch64_feature_detected!("neon") {
            unsafe {
                assert_eq!(neon::pt_keyword("<OR>=a"), Ok(4));
                assert_eq!(neon::pt_keyword("<??>=a"), Ok(4));
                assert_eq!(
                    neon::pt_keyword("<OR>=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
                    Ok(4)
                );
                assert_eq!(
                    neon::pt_keyword("<??>=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
                    Ok(4)
                );
            }
        }
    }

    #[test]
    fn test_check_line() {
        let is_neon = is_aarch64_feature_detected!("neon");

        if is_neon {
            proptest!(|((s, _o) in aligned_str())| {
                let r = reference::check_line(&s);
                if is_neon {
                    assert_eq!(r, unsafe { neon::check_line(&s) });
                }
            });
        }
    }

    #[test]
    fn test_proto_keyword() {
        let is_neon = is_aarch64_feature_detected!("neon");

        if is_neon {
            proptest!(|((s, _o) in aligned_str())| {
                let r = reference::proto_keyword(&s);
                if is_neon {
                    assert_eq!(r, unsafe { neon::proto_keyword(&s) });
                }
            });
        }
    }

    #[test]
    fn test_next_non_ws() {
        let is_neon = is_aarch64_feature_detected!("neon");

        if is_neon {
            proptest!(|((s, _o) in aligned_str())| {
                let r = reference::next_non_ws(&s);
                if is_neon {
                    assert_eq!(r, unsafe { neon::next_non_ws(&s) });
                }
            });
        }
    }

    #[test]
    fn test_check_argument() {
        let is_neon = is_aarch64_feature_detected!("neon");

        if is_neon {
            proptest!(|((s, _o) in aligned_str())| {
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
            proptest!(|((s, _o) in aligned_str())| {
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
            proptest!(|((s, _o) in aligned_str())| {
                let r = reference::check_object_content(&s);
                if is_neon {
                    assert_eq!(r, unsafe { neon::check_object_content(&s) });
                }
            });
        }
    }

    #[test]
    fn test_arg_iter() {
        let is_neon = is_aarch64_feature_detected!("neon");

        if is_neon {
            proptest!(|((s, _o) in aligned_arg_str())| unsafe {
                //dbg!(_o, s.as_bytes());
                if is_neon {
                    let mut it = neon::new(&s);
                    for (i, r) in reference::ArgIterInner::from(&*s).enumerate() {
                        let Some(t) = neon::next((&mut it).into()).map(|s| &*s.as_ptr()) else {
                            panic!("iterator should produce at least {i} items")
                        };
                        //dbg!(t);
                        assert_eq!(r, t, "mismatch at index {i}");
                    }
                    if let Some(t) = neon::next((&mut it).into()).map(|s| &*s.as_ptr()) {
                        panic!("iterator should stop, got {t:?}")
                    }

                    let mut it = neon::new(&s);
                    for (i, r) in reference::ArgIterInner::from(&*s).rev().enumerate() {
                        let Some(t) = neon::next_back((&mut it).into()).map(|s| &*s.as_ptr()) else {
                            panic!("iterator should produce at least {i} items")
                        };
                        //dbg!(t);
                        assert_eq!(r, t, "mismatch at index {i}");
                    }
                    if let Some(t) = neon::next_back((&mut it).into()).map(|s| &*s.as_ptr()) {
                        panic!("iterator should stop, got {t:?}")
                    }
                }
            });
        }
    }
}
