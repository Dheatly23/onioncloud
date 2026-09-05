//! Standard cell cache.

use std::fmt::{Debug, Formatter, Result as FmtResult};
use std::ptr::null_mut;
use std::sync::Arc;
use std::sync::atomic::{AtomicPtr, AtomicU8, Ordering::*, fence};

use crate::cache::CellCache;
use crate::fixed::{FIXED_CELL_SIZE, FixedCell};

struct Inner {
    start: AtomicU8,
    end: AtomicU8,

    arr: [AtomicPtr<[u8; FIXED_CELL_SIZE]>; 256],
}

impl Drop for Inner {
    fn drop(&mut self) {
        for i in self.arr.iter_mut() {
            let p = *i.get_mut();
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

            arr: [const { AtomicPtr::new(null_mut()) }; _],
        }))
    }
}

impl CellCache for StandardCellCache {
    fn get_cached(&self) -> FixedCell {
        let inner = &*self.0;

        for _ in 0..4 {
            // Using relaxed because we only care about atomicity.
            let i = inner.end.fetch_add(1, Relaxed).rotate_left(4);

            // Unfortunately, there isn't compare not equal and swap.
            // So use relaxed here and acquire if we actually get the pointer.
            let p = inner.arr[i as usize].swap(null_mut(), Relaxed);
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

        for _ in 0..4 {
            // Using relaxed because we only care about atomicity.
            let i = inner.start.fetch_add(1, Relaxed).rotate_left(4);

            // Using release to synchronize with get_cached.
            // Previous usage/writes is fenced here.
            if inner.arr[i as usize]
                .compare_exchange(null_mut(), p.0, Release, Relaxed)
                .is_ok()
            {
                p.0 = null_mut();
                return;
            }
        }
    }
}
