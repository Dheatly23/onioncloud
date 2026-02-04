//! x86 SIMD variant.
#![cfg(any(target_arch = "x86", target_arch = "x86_64"))]

mod avx;
mod sse;

use std::arch::is_x86_feature_detected;
#[cfg(target_arch = "x86")]
use std::arch::x86 as arch;
#[cfg(target_arch = "x86_64")]
use std::arch::x86_64 as arch;
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

    let p = NonNull::from(if is_x86_feature_detected!("avx2") {
        // SAFETY: AVX2 is enabled
        static FP: FPtrs = unsafe {
            FPtrs {
                check_line: |v| avx::check_line(v),
                proto_keyword: |v| avx::proto_keyword(v),
                next_non_ws: |v| avx::next_non_ws(v),
                check_argument: |v| avx::check_argument(v),
                check_object_keyword: |v| avx::check_object_keyword(v),
                check_object_content: |v| avx::check_object_content(v),
                new: |v| avx::new(v),
                fmt: |v, f| avx::fmt(v, f),
                next: |v| avx::next(v),
                size_hint: |v| avx::size_hint(v),
                next_back: |v| avx::next_back(v),
            }
        };
        &FP
    } else if is_x86_feature_detected!("sse2") {
        // SAFETY: SSE2 is enabled
        static FP: FPtrs = unsafe {
            FPtrs {
                check_line: |v| sse::check_line(v),
                proto_keyword: |v| sse::proto_keyword(v),
                next_non_ws: |v| sse::next_non_ws(v),
                check_argument: |v| sse::check_argument(v),
                check_object_keyword: |v| sse::check_object_keyword(v),
                check_object_content: |v| sse::check_object_content(v),
                new: |v| sse::new(v),
                fmt: |v, f| sse::fmt(v, f),
                next: |v| sse::next(v),
                size_hint: |v| sse::size_hint(v),
                next_back: |v| sse::next_back(v),
            }
        };
        &FP
    } else {
        static FP: FPtrs = FPtrs {
            check_line: universal::check_line,
            proto_keyword: universal::proto_keyword,
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
    sse: sse::ArgIterInner,
    avx: avx::ArgIterInner,
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
    fn test_check_line() {
        let is_sse = is_x86_feature_detected!("sse2");
        let is_avx = is_x86_feature_detected!("avx2");

        if is_sse || is_avx {
            proptest!(|((s, _o) in aligned_str())| {
                let r = reference::check_line(&s);
                if is_avx {
                    assert_eq!(r, unsafe { avx::check_line(&s) });
                }
                if is_sse {
                    assert_eq!(r, unsafe { sse::check_line(&s) });
                }
            });
        }
    }

    #[test]
    fn test_proto_keyword() {
        let is_sse = is_x86_feature_detected!("sse2");
        let is_avx = is_x86_feature_detected!("avx2");

        if is_sse || is_avx {
            proptest!(|((s, _o) in aligned_str())| {
                let r = reference::proto_keyword(&s);
                if is_avx {
                    assert_eq!(r, unsafe { avx::proto_keyword(&s) });
                }
                if is_sse {
                    assert_eq!(r, unsafe { sse::proto_keyword(&s) });
                }
            });
        }
    }

    #[test]
    fn test_next_non_ws() {
        let is_sse = is_x86_feature_detected!("sse2");
        let is_avx = is_x86_feature_detected!("avx2");

        if is_sse || is_avx {
            proptest!(|((s, _o) in aligned_str())| {
                let r = reference::next_non_ws(&s);
                if is_avx {
                    assert_eq!(r, unsafe { avx::next_non_ws(&s) });
                }
                if is_sse {
                    assert_eq!(r, unsafe { sse::next_non_ws(&s) });
                }
            });
        }
    }

    #[test]
    fn test_check_argument() {
        let is_sse = is_x86_feature_detected!("sse2");
        let is_avx = is_x86_feature_detected!("avx2");

        if is_sse || is_avx {
            proptest!(|((s, _o) in aligned_str())| {
                let r = reference::check_argument(&s);
                if is_avx {
                    assert_eq!(r, unsafe { avx::check_argument(&s) });
                }
                if is_sse {
                    assert_eq!(r, unsafe { sse::check_argument(&s) });
                }
            });
        }
    }

    #[test]
    fn test_check_object_keyword() {
        let is_sse = is_x86_feature_detected!("sse2");
        let is_avx = is_x86_feature_detected!("avx2");

        if is_sse || is_avx {
            proptest!(|((s, _o) in aligned_str())| {
                let r = reference::check_object_keyword(&s);
                if is_avx {
                    assert_eq!(r, unsafe { avx::check_object_keyword(&s) });
                }
                if is_sse {
                    assert_eq!(r, unsafe { sse::check_object_keyword(&s) });
                }
            });
        }
    }

    #[test]
    fn test_check_object_content() {
        let is_sse = is_x86_feature_detected!("sse2");
        let is_avx = is_x86_feature_detected!("avx2");

        if is_sse || is_avx {
            proptest!(|((s, _o) in aligned_str())| {
                let r = reference::check_object_content(&s);
                if is_avx {
                    assert_eq!(r, unsafe { avx::check_object_content(&s) });
                }
                if is_sse {
                    assert_eq!(r, unsafe { sse::check_object_content(&s) });
                }
            });
        }
    }

    #[test]
    fn test_arg_iter() {
        let is_sse = is_x86_feature_detected!("sse2");
        let is_avx = is_x86_feature_detected!("avx2");

        if is_sse || is_avx {
            proptest!(|((s, _o) in aligned_arg_str())| unsafe {
                //dbg!(_o, s.as_bytes());
                if is_avx {
                    let mut it = avx::new(&s);
                    for (i, r) in reference::ArgIterInner::from(&*s).enumerate() {
                        let Some(t) = avx::next((&mut it).into()).map(|s| &*s.as_ptr()) else {
                            panic!("iterator should produce at least {i} items")
                        };
                        //dbg!(t);
                        assert_eq!(r, t, "mismatch at index {i}");
                    }
                    if let Some(t) = avx::next((&mut it).into()).map(|s| &*s.as_ptr()) {
                        panic!("iterator should stop, got {t:?}")
                    }

                    let mut it = avx::new(&s);
                    for (i, r) in reference::ArgIterInner::from(&*s).rev().enumerate() {
                        let Some(t) = avx::next_back((&mut it).into()).map(|s| &*s.as_ptr()) else {
                            panic!("iterator should produce at least {i} items")
                        };
                        //dbg!(t);
                        assert_eq!(r, t, "mismatch at index {i}");
                    }
                    if let Some(t) = avx::next_back((&mut it).into()).map(|s| &*s.as_ptr()) {
                        panic!("iterator should stop, got {t:?}")
                    }
                }
                if is_sse {
                    let mut it = sse::new(&s);
                    for (i, r) in reference::ArgIterInner::from(&*s).enumerate() {
                        let Some(t) = sse::next((&mut it).into()).map(|s| &*s.as_ptr()) else {
                            panic!("iterator should produce at least {i} items")
                        };
                        //dbg!(t);
                        assert_eq!(r, t, "mismatch at index {i}");
                    }
                    if let Some(t) = sse::next((&mut it).into()).map(|s| &*s.as_ptr()) {
                        panic!("iterator should stop, got {t:?}")
                    }

                    let mut it = sse::new(&s);
                    for (i, r) in reference::ArgIterInner::from(&*s).rev().enumerate() {
                        let Some(t) = sse::next_back((&mut it).into()).map(|s| &*s.as_ptr()) else {
                            panic!("iterator should produce at least {i} items")
                        };
                        //dbg!(t);
                        assert_eq!(r, t, "mismatch at index {i}");
                    }
                    if let Some(t) = sse::next_back((&mut it).into()).map(|s| &*s.as_ptr()) {
                        panic!("iterator should stop, got {t:?}")
                    }
                }
            });
        }
    }
}
