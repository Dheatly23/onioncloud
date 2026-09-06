//! Standard cell cache.

use std::fmt::{Debug, Formatter, Result as FmtResult};
use std::ptr::null_mut;
#[cfg(not(feature = "loom"))]
use std::sync::Arc;
#[cfg(not(feature = "loom"))]
use std::sync::atomic::{AtomicPtr, AtomicU8, Ordering::*, fence};

#[cfg(feature = "loom")]
use loom::sync::Arc;
#[cfg(feature = "loom")]
use loom::sync::atomic::{AtomicPtr, AtomicU8, Ordering::*, fence};

use crate::cache::CellCache;
use crate::fixed::{FIXED_CELL_SIZE, FixedCell};

cfg_select! {
    feature = "loom" => {
        const LEN: usize = 8;
        const SHIFT: u32 = 0;
        const COUNT: usize = 1;
    }
    _ => {
        const LEN: usize = 256;
        const SHIFT: u32 = 4;
        const COUNT: usize = 4;
    }
}

struct Inner {
    start: AtomicU8,
    end: AtomicU8,

    arr: [AtomicPtr<[u8; FIXED_CELL_SIZE]>; LEN],
}

impl Drop for Inner {
    fn drop(&mut self) {
        for i in &self.arr {
            let p = i.load(Relaxed);
            if !p.is_null() {
                // SAFETY: Pointer comes from FixedCell.
                unsafe { drop(Box::from_raw(p)) };
            }
        }
    }
}

/// Standard cell cache.
///
/// [`Clone`] is a cheap refcount increase. User should not wrap it in another [`Arc`].
///
/// User **should not** rely on internal implementation details.
#[derive(Clone)]
pub struct StandardCellCache(Arc<Inner>);

impl Debug for StandardCellCache {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        f.write_str("StandardCellCache")
    }
}

impl Default for StandardCellCache {
    fn default() -> Self {
        Self(Arc::new(Inner {
            start: AtomicU8::new(0),
            end: AtomicU8::new(0),

            arr: cfg_select! {
                feature = "loom" => Default::default(),
                _ => [const { AtomicPtr::new(null_mut()) }; _],
            },
        }))
    }
}

impl CellCache for StandardCellCache {
    fn get_cached(&self) -> FixedCell {
        let inner = &*self.0;

        for _ in 0..COUNT {
            // Using relaxed because we only care about atomicity.
            let i = inner.end.fetch_add(1, Relaxed).rotate_left(SHIFT);

            // Unfortunately, there isn't compare not equal and swap.
            // So use relaxed here and acquire if we actually get the pointer.
            let p = inner.arr[i as usize % LEN].swap(null_mut(), Relaxed);
            if p.is_null() {
                continue;
            }

            // Using acquire to synchronize with cache_cell.
            fence(Acquire);

            // SAFETY: Pointer comes from FixedCell.
            let mut r = unsafe { FixedCell::from(Box::from_raw(p)) };
            r.data_mut().fill(0);
            return r;
        }

        FixedCell::default()
    }

    fn cache_cell(&self, cell: FixedCell) {
        struct S(*mut [u8; FIXED_CELL_SIZE]);

        impl Drop for S {
            fn drop(&mut self) {
                if !self.0.is_null() {
                    // SAFETY: Pointer comes from FixedCell.
                    unsafe { drop(Box::from_raw(self.0)) }
                }
            }
        }

        let inner = &*self.0;
        let mut p = S(Box::into_raw(cell.into_inner()));

        for _ in 0..COUNT {
            // Using relaxed because we only care about atomicity.
            let i = inner.start.fetch_add(1, Relaxed).rotate_left(SHIFT);

            // Using release to synchronize with get_cached.
            // Previous usage/writes is fenced here.
            if inner.arr[i as usize % LEN]
                .compare_exchange(null_mut(), p.0, Release, Relaxed)
                .is_ok()
            {
                p.0 = null_mut();
                return;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(not(feature = "loom"))]
    use std::thread::spawn;

    #[cfg(feature = "loom")]
    use loom::thread::spawn;

    use test_log::test;
    use tracing::{info, instrument};

    #[cfg(not(feature = "loom"))]
    #[test]
    fn test_standard_cell_cache() {
        let cache = StandardCellCache::default();

        for _ in 0..256 {
            cache.cache_cell(FixedCell::default());
        }

        for _ in 0..256 {
            let _ = cache.get_cached();
        }
    }

    #[test]
    fn test_standard_cell_cache_multithread() {
        #[instrument]
        fn run(cache: StandardCellCache, n: usize) {
            for _ in 0..n {
                cache.cache_cell(FixedCell::default());
            }

            for _ in 0..n {
                let _ = cache.get_cached();
            }
        }

        cfg_select! {
            feature = "loom" => {
                static CNT: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
                CNT.store(0, Relaxed);

                loom::model(|| {
                    let cache = StandardCellCache::default();

                    let h = (0..2).map(|_| {
                        let cache = cache.clone();
                        spawn(move || run(cache, 3))
                    }).collect::<Vec<_>>();

                    run(cache, 3);

                    for i in h {
                        i.join().unwrap();
                    }

                    if let n = CNT.fetch_add(1, Relaxed) && n % 1000 == 0 {
                        println!("Iteration {n} done!");
                    }
                });
            }
            _ => {
                info!("Start");
                let cache = StandardCellCache::default();

                let h = (0..8).map(|_| {
                    let cache = cache.clone();
                    spawn(move || run(cache, 256))
                }).collect::<Vec<_>>();

                for i in h {
                    i.join().unwrap();
                }

                info!("Done");
            }
        }
    }
}
