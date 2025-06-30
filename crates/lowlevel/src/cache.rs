use std::borrow::{Borrow, BorrowMut};
use std::cmp::{Eq, Ord, Ordering, PartialEq, PartialOrd};
use std::fmt::{Debug, Display, Formatter, Result as FmtResult};
use std::hash::{Hash, Hasher};
use std::mem::ManuallyDrop;
use std::ops::{Deref, DerefMut};
#[cfg(test)]
use std::sync::atomic::{AtomicUsize, Ordering::*};

use crossbeam_queue::ArrayQueue;

use crate::cell::{Cell, FixedCell, TryFromCell};
use crate::errors;

/// Cell cache provider.
///
/// To improve memory usage, we recommend using a cache to temporarily store [`FixedCell`].
/// Unused cells should be returned into the cache, to be then reused somewhere else.
pub trait CellCache: Sync {
    /// Gets a [`FixedCell`], preferably from a cache.
    ///
    /// The behavior can be as simple as creating a new [`FixedCell`] every time.
    /// More advanced implementation should be using a global cache to manage cached cells.
    ///
    /// **⚠ Cell should be cleared of it's content before returning. ⚠**
    fn get_cached(&self) -> FixedCell;

    /// Returns cell into cache.
    ///
    /// The behavior can be as simple as dropping the cell.
    /// More advanced implementation should be caching it for a reasonable time.
    fn cache_cell(&self, cell: FixedCell);

    /// Helper function to cache a cell.
    ///
    /// Note that it requires [`Self`] to be [`Clone`], which is **not recommended** to be implemented.
    /// In effect, only [`Arc`](`std::sync::Arc`) wrapped cache can use it.
    ///
    /// # Example
    ///
    /// ```
    /// use std::sync::Arc;
    /// use onioncloud_lowlevel::cell::FixedCell;
    /// use onioncloud_lowlevel::cell::padding::Padding;
    /// use onioncloud_lowlevel::cache::{CellCache, StandardCellCache};
    ///
    /// let cache = Arc::new(StandardCellCache::default());
    /// let cell = cache.cache(FixedCell::default());
    /// ```
    fn cache<T>(&self, cell: T) -> Cached<T, Self>
    where
        T: Cachable,
        Self: Clone,
    {
        Cached::new(self.clone(), cell)
    }
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
            Some(mut v) => {
                v.data_mut().fill(0);
                v
            }
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

/// Trait for cacheable types.
pub trait Cachable {
    /// Maybe unwraps self into [`FixedCell`].
    ///
    /// If it returns [`None`], then the internal value is not cachable.
    fn maybe_into_fixed(self) -> Option<FixedCell>;
}

/// Auto-impl for [`Into`].
impl<T: Into<FixedCell>> Cachable for T {
    fn maybe_into_fixed(self) -> Option<FixedCell> {
        Some(self.into())
    }
}

/// Type that wraps a cell to be cached.
///
/// When it drops, automatically caches cell.
#[derive(Clone)]
pub struct Cached<T: Cachable, C: CellCache> {
    cache: ManuallyDrop<C>,
    cell: ManuallyDrop<T>,
}

impl<T: Cachable, C: CellCache> Drop for Cached<T, C> {
    fn drop(&mut self) {
        // SAFETY: cell will not be accessed nor moved.
        let cell = unsafe { ManuallyDrop::take(&mut self.cell) };
        if let Some(cell) = cell.maybe_into_fixed() {
            self.cache.cache_cell(cell);
        }
        // SAFETY: cache will not be accessed nor moved.
        unsafe { ManuallyDrop::drop(&mut self.cache) }
    }
}

impl<T: Cachable, C: CellCache> Deref for Cached<T, C> {
    type Target = T;

    fn deref(&self) -> &T {
        &self.cell
    }
}

impl<T: Cachable, C: CellCache> DerefMut for Cached<T, C> {
    fn deref_mut(&mut self) -> &mut T {
        &mut self.cell
    }
}

impl<T: Cachable, C: CellCache> AsRef<T> for Cached<T, C> {
    fn as_ref(&self) -> &T {
        &self.cell
    }
}

impl<T: Cachable, C: CellCache> AsMut<T> for Cached<T, C> {
    fn as_mut(&mut self) -> &mut T {
        &mut self.cell
    }
}

impl<T: Cachable, C: CellCache> Borrow<T> for Cached<T, C> {
    fn borrow(&self) -> &T {
        &self.cell
    }
}

impl<T: Cachable, C: CellCache> BorrowMut<T> for Cached<T, C> {
    fn borrow_mut(&mut self) -> &mut T {
        &mut self.cell
    }
}

impl<T, U, C1, C2> PartialEq<Cached<U, C2>> for Cached<T, C1>
where
    T: Cachable + PartialEq<U>,
    U: Cachable,
    C1: CellCache,
    C2: CellCache,
{
    fn eq(&self, rhs: &Cached<U, C2>) -> bool {
        self.cell.eq(&rhs.cell)
    }
}

impl<T: Cachable + Eq, C: CellCache> Eq for Cached<T, C> {}

impl<T, U, C1, C2> PartialOrd<Cached<U, C2>> for Cached<T, C1>
where
    T: Cachable + PartialOrd<U>,
    U: Cachable,
    C1: CellCache,
    C2: CellCache,
{
    fn partial_cmp(&self, rhs: &Cached<U, C2>) -> Option<Ordering> {
        self.cell.partial_cmp(&rhs.cell)
    }
}

impl<T: Cachable + Ord, C: CellCache> Ord for Cached<T, C> {
    fn cmp(&self, rhs: &Self) -> Ordering {
        self.cell.cmp(&rhs.cell)
    }
}

impl<T: Cachable + Debug, C: CellCache> Debug for Cached<T, C> {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        (*self.cell).fmt(f)
    }
}

impl<T: Cachable + Display, C: CellCache> Display for Cached<T, C> {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        (*self.cell).fmt(f)
    }
}

impl<T: Cachable + Hash, C: CellCache> Hash for Cached<T, C> {
    fn hash<H: Hasher>(&self, state: &mut H) {
        (*self.cell).hash(state)
    }
}

impl<T: Cachable, C: CellCache> Cached<T, C> {
    /// Create new [`Cached`].
    pub fn new(cache: C, value: T) -> Self {
        Self {
            cache: ManuallyDrop::new(cache),
            cell: ManuallyDrop::new(value),
        }
    }

    /// Get reference to cell cache.
    ///
    /// Useful for using cache for other cells.
    pub fn cache(this: &Self) -> &C {
        &this.cache
    }

    /// Split reference into cell cache and cell.
    ///
    /// Useful for using cache for other cells.
    pub fn split_mut(this: &mut Self) -> (&mut T, &C) {
        (&mut this.cell, &this.cache)
    }

    /// Unwraps into inner value without caching.
    ///
    /// Useful to manipulate inner value.
    ///
    /// # Example
    ///
    /// ```
    /// use std::sync::Arc;
    /// use onioncloud_lowlevel::cell::FixedCell;
    /// use onioncloud_lowlevel::cell::padding::Padding;
    /// use onioncloud_lowlevel::cache::{Cached, StandardCellCache};
    ///
    /// let cache = Arc::new(StandardCellCache::default());
    ///
    /// // Cache cell
    /// let cell = Cached::new(cache.clone(), FixedCell::default());
    ///
    /// // Unwraps inner cell (now it's uncached)
    /// let cell = Cached::into_inner(cell);
    ///
    /// // Re-cache cell
    /// let cell = Cached::new(cache.clone(), cell);
    /// ```
    pub fn into_inner(this: Self) -> T {
        Self::decompose(this).0
    }

    fn decompose(this: Self) -> (T, C) {
        // SAFETY: this will not be accessed nor moved after.
        // Prevent drop from being called by wrapping in ManuallyDrop.
        unsafe {
            let mut this = ManuallyDrop::new(this);
            (
                ManuallyDrop::take(&mut this.cell),
                ManuallyDrop::take(&mut this.cache),
            )
        }
    }

    /// Maps cell data.
    ///
    /// NOTE: This is an associated function instead of method.
    ///
    /// # Example
    ///
    /// ```
    /// use onioncloud_lowlevel::cell::FixedCell;
    /// use onioncloud_lowlevel::cell::padding::Padding;
    /// use onioncloud_lowlevel::cache::{Cached, StandardCellCache};
    ///
    /// let cell = Cached::new(StandardCellCache::default(), FixedCell::default());
    /// let cell = Cached::map(cell, Padding::new);
    /// ```
    pub fn map<U: Cachable>(this: Self, f: impl FnOnce(T) -> U) -> Cached<U, C> {
        let (cell, cache) = Self::decompose(this);
        Cached::new(cache, f(cell))
    }

    /// Maps from one type to another.
    ///
    /// This is only used because a blanket [`From`] impl conflicts with identity impl.
    ///
    /// # Example
    ///
    /// ```
    /// use onioncloud_lowlevel::cell::{Cell, FixedCell};
    /// use onioncloud_lowlevel::cell::padding::Padding;
    /// use onioncloud_lowlevel::cache::{Cached, StandardCellCache};
    ///
    /// let cell = Cached::new(StandardCellCache::default(), Padding::new(FixedCell::default()));
    /// let cell = Cached::map_into::<Cell>(cell);
    /// ```
    pub fn map_into<U: Cachable + From<T>>(this: Self) -> Cached<U, C> {
        Cached::map(this, U::from)
    }

    /// Try to map cell data.
    ///
    /// Due to [`Try`] trait being unstable, it only supports [`Result`].
    /// Within the closure, caching is done manually using reference to cache.
    ///
    /// NOTE: This is an associated function instead of method.
    ///
    /// # Example
    ///
    /// ```
    /// use onioncloud_lowlevel::cell::FixedCell;
    /// use onioncloud_lowlevel::cache::{Cached, CellCache, StandardCellCache};
    ///
    /// let cell = Cached::new(StandardCellCache::default(), FixedCell::default());
    ///
    /// // Example of error
    /// assert!(Cached::try_map(cell, |cell, cache| {
    ///     if false {
    ///         Ok(cell)
    ///     } else {
    ///         // Manually cache
    ///         cache.cache_cell(cell);
    ///
    ///         Err(())
    ///     }
    /// }).is_err());
    /// ```
    pub fn try_map<U: Cachable, E>(
        this: Self,
        f: impl FnOnce(T, &C) -> Result<U, E>,
    ) -> Result<Cached<U, C>, E> {
        let (cell, cache) = Self::decompose(this);
        let cell = f(cell, &cache)?;
        Ok(Cached::new(cache, cell))
    }
}

impl<T, C> Cached<Option<T>, C>
where
    T: Cachable,
    Option<T>: Cachable,
    C: CellCache,
{
    /// Transpose a [`Cached`] of [`Option`] to [`Option`] of [`Cached`].
    ///
    /// NOTE: This is an associated function instead of method.
    ///
    /// # Example
    ///
    /// ```
    /// use onioncloud_lowlevel::cell::{Cell, FixedCell};
    /// use onioncloud_lowlevel::cell::padding::Padding;
    /// use onioncloud_lowlevel::cache::{Cached, StandardCellCache};
    ///
    /// let cell = Cached::new(StandardCellCache::default(), Some(Cell::from(Padding::new(FixedCell::default()))));
    /// let cell = Cached::transpose(cell).unwrap();
    /// ```
    pub fn transpose(this: Self) -> Option<Cached<T, C>> {
        let (cell, cache) = Self::decompose(this);
        Some(Cached::new(cache, cell?))
    }
}

/// Similiar to [`crate::cell::cast`], but cached version.
pub fn cast<T: TryFromCell>(
    cell: &mut Cached<Option<Cell>, impl CellCache>,
) -> Result<Option<T>, errors::CellFormatError> {
    T::try_from_cell(&mut cell.cell)
}

#[cfg(test)]
pub(crate) use tests::*;

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

    pub(crate) struct TestCache {
        alloc: AtomicUsize,
        drop: AtomicUsize,
    }

    impl TestCache {
        pub(crate) fn new() -> Self {
            Self {
                alloc: AtomicUsize::new(0),
                drop: AtomicUsize::new(0),
            }
        }

        pub(crate) fn as_inner(&self) -> (usize, usize) {
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
