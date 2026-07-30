use std::mem::ManuallyDrop;
use std::ptr::NonNull;
#[cfg(not(feature = "loom"))]
use std::sync::atomic;
use std::sync::atomic::Ordering::*;
use std::task::{RawWaker, RawWakerVTable, Waker};

#[cfg(feature = "loom")]
use loom::sync::atomic;

use crate::utils::{ArcLike, InnerArcLike};

cfg_select! {
    target_has_atomic = "64" => {
        struct InnerWaker {
            a: atomic::AtomicU64,
        }
    },
    _ => {
        struct InnerWaker {
            a: atomic::AtomicU32,
            b: atomic::AtomicU32,
        }
    }
}

impl InnerWaker {
    fn new() -> Self {
        cfg_select! {
            target_has_atomic = "64" => Self {
                a: atomic::AtomicU64::new(0),
            },
            _ => Self {
                a: atomic::AtomicU32::new(0),
                b: atomic::AtomicU32::new(0),
            }
        }
    }

    fn wake(&self, i: u8) {
        cfg_select! {
            target_has_atomic = "64" => {
                self.a.fetch_or(1u64.wrapping_shl(i.into()), Relaxed);
            },
            _ => {
                let p = if i < 32 { &self.a } else { &self.b };
                p.fetch_or(1u32.wrapping_shl(i.into()), Relaxed);
            }
        }
    }

    fn take_all(&self) -> u64 {
        cfg_select! {
            target_has_atomic = "64" => {
                self.a.swap(0, Relaxed)
            },
            _ => {
                let a = self.a.swap(0, Relaxed);
                let b = self.b.swap(0, Relaxed);
                a as u64 | ((b as u64) << 32)
            }
        }
    }
}

#[derive(Default)]
struct InnerSelector {
    sel: atomic::AtomicBool,
}

/// Selector for waker double buffer.
#[derive(Clone, Default)]
pub(crate) struct Selector(ArcLike<InnerSelector>);

impl Selector {
    pub(crate) fn get_switch(&self) -> bool {
        self.0.sel.load(Relaxed)
    }

    pub(crate) fn switch(&self) -> bool {
        self.0.sel.fetch_xor(true, Relaxed)
    }
}

#[repr(align(64))]
struct InnerMultiWaker {
    sel: Selector,
    a: InnerWaker,
    b: InnerWaker,
}

/// Waker that contains multiple waker flags in it.
#[derive(Clone)]
pub(crate) struct MultiWaker(ArcLike<InnerMultiWaker>);

impl MultiWaker {
    pub(crate) fn new(selector: Selector) -> Self {
        Self(ArcLike::new(InnerMultiWaker {
            sel: selector,
            a: InnerWaker::new(),
            b: InnerWaker::new(),
        }))
    }

    pub(crate) fn take_flags(&self, left_bank: bool) -> u64 {
        let p = if left_bank { &self.0.a } else { &self.0.b };
        p.take_all()
    }

    pub(crate) fn wake_flag(&self, n: u8) {
        debug_assert!(n < 64, "n >= 64 (n = {n})");

        let inner = &*self.0;
        let bank = inner.sel.get_switch();
        let p = if bank { &inner.a } else { &inner.b };
        p.wake(n);
    }

    pub(crate) fn make_waker(&self, n: u8) -> Waker {
        debug_assert!(n < 64, "n >= 64 (n = {n})");

        let p = self
            .0
            .clone()
            .into_raw()
            .as_ptr()
            .cast_const()
            .map_addr(|a| a | (n & 63) as usize)
            .cast();
        // SAFETY: RawWaker is valid for waker.
        unsafe { Waker::from_raw(RawWaker::new(p, &VTABLE)) }
    }
}

unsafe fn from_ptr(p: *const ()) -> ArcLike<InnerMultiWaker> {
    // SAFETY: Pointer is points to valid InnerMultiWaker data with pointer tag.
    // It's caller's responsibility to not drop the return value unless they own the value.
    unsafe {
        ArcLike::from_raw(NonNull::new_unchecked(
            p.cast_mut()
                .cast::<InnerArcLike<InnerMultiWaker>>()
                .map_addr(|a| a & !63),
        ))
    }
}

#[cfg_attr(test, tracing::instrument(skip_all))]
unsafe fn clone_waker(p: *const ()) -> RawWaker {
    // SAFETY: Pointer is points to valid InnerMultiWaker data with pointer tag.
    // Also we're only borrowing value, so use ManuallyDrop to prevent drop.
    let r = unsafe { ManuallyDrop::new(from_ptr(p)) };
    RawWaker::new(ArcLike::clone(&r).into_raw().as_ptr().cast(), &VTABLE)
}

#[cfg_attr(test, tracing::instrument(skip_all))]
unsafe fn wake(p: *const ()) {
    let n = (p.addr() & 63) as u8;
    // SAFETY: Pointer is points to valid InnerMultiWaker data with pointer tag.
    // Also we're taking ownership.
    let r = unsafe { from_ptr(p) };
    let bank = r.sel.get_switch();
    let p = if bank { &r.a } else { &r.b };
    p.wake(n);

    #[cfg(test)]
    {
        tracing::trace!(
            addr = tracing::field::debug(r.get_raw()),
            bit = n,
            bank = if bank { "left" } else { "right" },
            "waking by value",
        );
    }
}

#[cfg_attr(test, tracing::instrument(skip_all))]
unsafe fn wake_ref(p: *const ()) {
    let n = (p.addr() & 63) as u8;
    // SAFETY: Pointer is points to valid InnerMultiWaker data with pointer tag.
    // Also we're only borrowing value, so use ManuallyDrop to prevent drop.
    let r = unsafe { ManuallyDrop::new(from_ptr(p)) };
    let bank = r.sel.get_switch();
    let p = if bank { &r.a } else { &r.b };
    p.wake(n);

    #[cfg(test)]
    {
        tracing::trace!(
            addr = tracing::field::debug(r.get_raw()),
            bit = n,
            bank = if bank { "left" } else { "right" },
            "waking by reference",
        );
    }
}

#[cfg_attr(test, tracing::instrument(skip_all))]
unsafe fn drop_waker(p: *const ()) {
    // SAFETY: Pointer is points to valid InnerMultiWaker data with pointer tag.
    unsafe {
        ArcLike::from_raw(NonNull::new_unchecked(
            p.cast_mut()
                .cast::<InnerArcLike<InnerMultiWaker>>()
                .map_addr(|a| a & !63),
        ));
    }
}

const VTABLE: RawWakerVTable = RawWakerVTable::new(clone_waker, wake, wake_ref, drop_waker);

#[cfg(test)]
mod tests {
    use super::*;

    use std::hint::black_box;

    use test_log::test;
    use tracing::instrument;

    use crate::utils::{get_drop_cnt, reset_drop_cnt, run_test};

    #[test]
    fn test_selector_create() {
        #[instrument]
        fn test() {
            reset_drop_cnt();
            black_box(Selector::default());
            assert_eq!(get_drop_cnt(), 1, "drop count mismatch");
        }

        run_test(test);
    }

    #[test]
    fn test_waker_create() {
        #[instrument]
        fn test() {
            reset_drop_cnt();
            black_box(MultiWaker::new(Selector::default()));
            assert_eq!(get_drop_cnt(), 2, "drop count mismatch");
        }

        run_test(test);
    }

    #[test]
    fn test_waker_clone() {
        #[instrument]
        fn test() {
            reset_drop_cnt();

            {
                let _w = black_box(MultiWaker::new(Selector::default()).make_waker(0));

                {
                    let _w = black_box(_w.clone());

                    {
                        let _w = black_box(_w.clone());
                    }

                    {
                        let _w = black_box(_w.clone());
                    }
                }

                {
                    let _w = black_box(_w.clone());
                }
            }

            assert_eq!(get_drop_cnt(), 2, "drop count mismatch");
        }

        run_test(test);
    }

    #[test]
    fn test_waker_clone_from() {
        #[instrument]
        fn test() {
            reset_drop_cnt();

            {
                let s = Selector::default();
                let _w1 = black_box(MultiWaker::new(s.clone()));
                let mut _w2 = black_box(MultiWaker::new(s.clone()));
                _w2.clone_from(&_w1);
            }

            assert_eq!(get_drop_cnt(), 3, "drop count mismatch");
        }

        run_test(test);
    }

    #[test]
    fn test_waker_wake() {
        #[instrument]
        fn test() {
            let w = MultiWaker::new(Selector::default());

            for i in 0..64 {
                w.make_waker(i).wake();
                assert_eq!(w.take_flags(false), 1u64 << i, "mismatch with flag bit {i}");
            }
        }

        run_test(test);
    }

    #[test]
    fn test_waker_wake_ref() {
        #[instrument]
        fn test() {
            let w = MultiWaker::new(Selector::default());

            for i in 0..64 {
                let t = w.make_waker(i);
                t.wake_by_ref();
                assert_eq!(w.take_flags(false), 1u64 << i, "mismatch with flag bit {i}");
            }
        }

        run_test(test);
    }

    #[test]
    fn test_waker_switch_wake() {
        #[instrument]
        fn test() {
            let s = Selector::default();
            let w = MultiWaker::new(s.clone());

            for i in 0..64 {
                w.make_waker(i).wake();
                assert_eq!(
                    w.take_flags(s.switch()),
                    1u64 << i,
                    "mismatch with flag bit {i}"
                );
            }
        }

        run_test(test);
    }

    #[cfg(feature = "loom")]
    #[test]
    fn test_waker_loom_parallel_wake() {
        #[instrument]
        fn test() {
            let s = Selector::default();
            let w = MultiWaker::new(s.clone());

            const BITS: [u8; 2] = [9, 11];
            let mask = BITS.iter().fold(0u64, |a, &v| a | (1u64 << v));

            let handles = BITS
                .iter()
                .map(|&v| {
                    let w = w.clone();
                    loom::thread::spawn(move || w.make_waker(v).wake())
                })
                .collect::<Vec<_>>();

            for _ in 0..BITS.len() + 2 {
                s.switch();
            }

            for h in handles {
                h.join().unwrap();
            }

            let r = w.take_flags(false) | w.take_flags(true);
            assert_eq!(r, mask);
            tracing::info!("done");
        }

        run_test(test);
    }
}
