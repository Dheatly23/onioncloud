use std::cmp::{Eq, Ord, Ordering, PartialEq, PartialOrd};
use std::mem::ManuallyDrop;
use std::ops::{Deref, DerefMut};
#[cfg(test)]
use std::sync::atomic::{AtomicUsize, Ordering::*};

use crossbeam_queue::ArrayQueue;

use crate::cell::FixedCell;

/// Cell cache provider.
///
/// To improve memory usage, we recommend using a cache to temporarily store [`FixedCell`].
/// Unused cells should be returned into the cache, to be then reused somewhere else.
pub trait CellCache: Sync {
    /// Gets a [`FixedCell`], preferably from a cache.
    ///
    /// The behavior can be as simple as creating a new [`FixedCell`] every time.
    /// More advanced implementation should be using a global cache to manage cached cells.
    fn get_cached(&self) -> FixedCell;

    /// Returns cell into cache.
    ///
    /// The behavior can be as simple as dropping the cell.
    /// More advanced implementation should be caching it for a reasonable time.
    fn cache_cell(&self, cell: FixedCell);
}

impl<T> CellCache for T
where
    T: Deref + ?Sized + Sync,
    T::Target: CellCache,
{
    fn get_cached(&self) -> FixedCell {
        <T as Deref>::Target::get_cached(self)
    }

    fn cache_cell(&self, cell: FixedCell) {
        <T as Deref>::Target::cache_cell(self, cell)
    }
}

/// Null cell cache provider.
///
/// It does not cache anything, all cells are fresh and anything returned will be dropped.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct NullCellCache;

impl CellCache for NullCellCache {
    fn get_cached(&self) -> FixedCell {
        FixedCell::default()
    }

    fn cache_cell(&self, _: FixedCell) {}
}

/// Standard cell cache.
///
/// Should be put in an [`std::sync::Arc`] to be able to share it across threads.
/// Optionally, create a global cache to be used for all.
pub struct StandardCellCache {
    #[cfg(test)]
    drop_count: AtomicUsize,
    #[cfg(test)]
    alloc_count: AtomicUsize,
    buf: ArrayQueue<FixedCell>,
}

/// Creates cell cache with default 256 items.
impl Default for StandardCellCache {
    fn default() -> Self {
        Self::new(256)
    }
}

impl StandardCellCache {
    /// Create new [`StandardCellCache`].
    ///
    /// # Parameters
    /// - `size` : The size of the buffer. It will only cache cells up to it.
    pub fn new(size: usize) -> Self {
        Self {
            #[cfg(test)]
            drop_count: AtomicUsize::new(0),
            #[cfg(test)]
            alloc_count: AtomicUsize::new(0),
            buf: ArrayQueue::new(size),
        }
    }

    /// Gets amount of cells cached.
    pub fn len(&self) -> usize {
        self.buf.len()
    }

    /// Checks if cache is empty.
    pub fn is_empty(&self) -> bool {
        self.buf.is_empty()
    }
}

impl CellCache for StandardCellCache {
    fn get_cached(&self) -> FixedCell {
        // Needs it for test harness
        #[allow(clippy::manual_unwrap_or_default)]
        match self.buf.pop() {
            Some(v) => v,
            None => {
                #[cfg(test)]
                self.alloc_count.fetch_add(1, AcqRel);
                FixedCell::default()
            }
        }
    }

    fn cache_cell(&self, cell: FixedCell) {
        #[cfg(not(test))]
        let _ = self.buf.push(cell);

        #[cfg(test)]
        if self.buf.push(cell).is_err() {
            self.drop_count.fetch_add(1, AcqRel);
        }
    }
}

/// Type that wraps a cell to be cached.
///
/// When it drops, automatically caches cell.
#[derive(Clone)]
pub struct Cached<T: Into<FixedCell>, C: CellCache> {
    cache: C,
    cell: ManuallyDrop<T>,
}

impl<T: Into<FixedCell>, C: CellCache> Drop for Cached<T, C> {
    fn drop(&mut self) {
        // SAFETY: cell will not be accessed again.
        let cell = unsafe { ManuallyDrop::take(&mut self.cell) };
        self.cache.cache_cell(cell.into());
    }
}

impl<T: Into<FixedCell>, C: CellCache> Deref for Cached<T, C> {
    type Target = T;

    fn deref(&self) -> &T {
        &self.cell
    }
}

impl<T: Into<FixedCell>, C: CellCache> DerefMut for Cached<T, C> {
    fn deref_mut(&mut self) -> &mut T {
        &mut self.cell
    }
}

impl<T: Into<FixedCell> + PartialEq, C: CellCache> PartialEq for Cached<T, C> {
    fn eq(&self, rhs: &Self) -> bool {
        self.cell.eq(&rhs.cell)
    }
}

impl<T: Into<FixedCell> + PartialEq, C: CellCache> PartialEq<T> for Cached<T, C> {
    fn eq(&self, rhs: &T) -> bool {
        (*self.cell).eq(rhs)
    }
}

impl<T: Into<FixedCell> + Eq, C: CellCache> Eq for Cached<T, C> {}

impl<T: Into<FixedCell> + PartialOrd, C: CellCache> PartialOrd for Cached<T, C> {
    fn partial_cmp(&self, rhs: &Self) -> Option<Ordering> {
        self.cell.partial_cmp(&rhs.cell)
    }
}

impl<T: Into<FixedCell> + PartialOrd, C: CellCache> PartialOrd<T> for Cached<T, C> {
    fn partial_cmp(&self, rhs: &T) -> Option<Ordering> {
        (*self.cell).partial_cmp(rhs)
    }
}

impl<T: Into<FixedCell> + Ord, C: CellCache> Ord for Cached<T, C> {
    fn cmp(&self, rhs: &Self) -> Ordering {
        self.cell.cmp(&rhs.cell)
    }
}

impl<T: Into<FixedCell>, C: CellCache> Cached<T, C> {
    /// Create new [`Cached`].
    pub fn new(cache: C, value: T) -> Self {
        Self {
            cache,
            cell: ManuallyDrop::new(value),
        }
    }

    /// Get reference to cell cache.
    ///
    /// Useful for using cache for other cells.
    pub fn cache(this: &Self) -> &C {
        &this.cache
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::iter::repeat_with;
    use std::sync::{Arc, Barrier};
    use std::thread::spawn;

    const N_THREADS: usize = 12;

    fn helper_spawn_threads<T: Send + Sync + 'static>(
        data: Arc<T>,
        f: impl FnOnce(Arc<T>) + Send + Clone + 'static,
    ) {
        let handles = (1..N_THREADS)
            .map(|_| {
                let data = data.clone();
                let f = f.clone();
                spawn(move || f(data))
            })
            .collect::<Vec<_>>();

        f(data);

        for h in handles {
            h.join().unwrap();
        }
    }

    #[test]
    fn test_standard_pop_uncached() {
        let data = Arc::new(StandardCellCache::default());

        helper_spawn_threads(data.clone(), |data| {
            for _ in 0..10 {
                data.get_cached();
            }
        });

        assert_eq!(data.alloc_count.load(Acquire), 10 * N_THREADS);
        assert_eq!(data.drop_count.load(Acquire), 0);
    }

    #[test]
    fn test_standard_push_dropped() {
        let data = Arc::new((StandardCellCache::new(N_THREADS), Barrier::new(N_THREADS)));

        helper_spawn_threads(data.clone(), |data| {
            for _ in 0..10 {
                data.0.cache_cell(FixedCell::default());
            }
            data.1.wait();
            for _ in 0..10 {
                data.0.get_cached();
            }
        });

        assert_eq!(data.0.alloc_count.load(Acquire), 9 * N_THREADS);
        assert_eq!(data.0.drop_count.load(Acquire), 9 * N_THREADS);
    }

    #[test]
    fn test_standard_all_cached() {
        let data = Arc::new((StandardCellCache::default(), Barrier::new(N_THREADS)));

        helper_spawn_threads(data.clone(), |data| {
            for _ in 0..10 {
                data.0.cache_cell(FixedCell::default());
                data.1.wait();
                data.0.get_cached();
            }
        });

        assert_eq!(data.0.alloc_count.load(Acquire), 0);
        assert_eq!(data.0.drop_count.load(Acquire), 0);
    }

    struct TestCache {
        alloc: AtomicUsize,
        drop: AtomicUsize,
    }

    impl TestCache {
        fn new() -> Self {
            Self {
                alloc: AtomicUsize::new(0),
                drop: AtomicUsize::new(0),
            }
        }

        fn as_inner(&self) -> (usize, usize) {
            (self.alloc.load(Acquire), self.drop.load(Acquire))
        }
    }

    impl CellCache for TestCache {
        fn get_cached(&self) -> FixedCell {
            self.alloc.fetch_add(1, AcqRel);
            FixedCell::default()
        }

        fn cache_cell(&self, _: FixedCell) {
            self.drop.fetch_add(1, AcqRel);
        }
    }

    #[test]
    fn test_cached() {
        let data = Arc::new((TestCache::new(), Barrier::new(N_THREADS)));

        helper_spawn_threads(data.clone(), |data| {
            let mut v = repeat_with(|| Cached::new(&data.0, data.0.get_cached()))
                .take(10)
                .collect::<Vec<_>>();
            data.1.wait();
            v.truncate(5);
            data.1.wait();
            v.resize_with(15, || Cached::new(&data.0, data.0.get_cached()));
            data.1.wait();
        });

        assert_eq!(data.0.as_inner(), (20 * N_THREADS, 20 * N_THREADS));
    }
}
