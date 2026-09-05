//! Caching [`FixedCell`] and cachable types.
//!
//! NOTE: Implemented here because it can't be split into separate crate.

mod standard;

use std::borrow::{Borrow, BorrowMut};
use std::cmp::{Eq, Ord, Ordering, PartialEq, PartialOrd};
use std::fmt::{Debug, Display, Formatter, Result as FmtResult};
use std::hash::{Hash, Hasher};
use std::mem::ManuallyDrop;
use std::ops::{Deref, DerefMut};

use crate::cell::{Cell, CellTy};
use crate::fixed::FixedCell;
use crate::typed::*;

pub use standard::StandardCellCache;

macro_rules! impl_cachable {
    ($($t:ty,)*) => {$(
        impl Cachable for $t {
            #[inline]
            fn cache<C: ?Sized + CellCache>(self, c: &C) {
                c.cache_cell(self.into());
            }
        }
    )*};
}

impl_cachable![
    Create2,
    CreateFast,
    Created2,
    CreatedFast,
    Destroy,
    Netinfo,
    Padding,
    PaddingNegotiate,
    Relay,
    RelayEarly,
];

/// Trait for cachable values.
pub trait Cachable {
    /// Caches value into [`CellCache`].
    fn cache<C: ?Sized + CellCache>(self, cache: &C);
}

/// Cell cache provider.
///
/// To improve memory usage, it's recommended using a cache to temporarily store [`FixedCell`].
/// Unused cells should be returned into the cache, to be then reused somewhere else.
pub trait CellCache {
    /// Gets a [`FixedCell`], preferably from a cache.
    ///
    /// The behavior can be as simple as creating a new [`FixedCell`] every time.
    /// More advanced implementation should be using a global cache to manage cached cells.
    ///
    /// **⚠ Cell should be cleared of it's content before returning. ⚠**
    #[must_use = "please use the cached FixedCell"]
    fn get_cached(&self) -> FixedCell;

    /// Returns cell into cache.
    ///
    /// The behavior can be as simple as dropping the cell.
    /// More advanced implementation should be caching it for a reasonable time.
    fn cache_cell(&self, cell: FixedCell);
}

/// Extension trait for [`CellCache`].
pub trait CellCacheExt: CellCache {
    /// Helper function to cache a cell.
    ///
    /// # Example
    ///
    /// ```
    /// use onioncloud_ll_cell::fixed::FixedCell;
    /// use onioncloud_ll_cell::cache::{CellCache, CellCacheExt, StandardCellCache};
    ///
    /// let cache = StandardCellCache::default();
    /// let cell = cache.cache(FixedCell::default());
    /// ```
    #[inline]
    fn cache<T>(&self, cell: T) -> Cached<T, Self>
    where
        T: Cachable,
        Self: Clone,
    {
        Cached::new(self.clone(), cell)
    }

    /// Helper function to cache a cell.
    ///
    /// Unlike [`CellCacheExt::cache`], it did not require `Self` to be [`Clone`].
    /// Great if you don't want overhead of cloning.
    ///
    /// # Example
    ///
    /// ```
    /// use onioncloud_ll_cell::fixed::FixedCell;
    /// use onioncloud_ll_cell::cache::{CellCache, CellCacheExt, StandardCellCache};
    ///
    /// let cache = StandardCellCache::default();
    /// let cell = cache.cache_b(FixedCell::default());
    /// ```
    #[inline]
    fn cache_b<T>(&self, cell: T) -> Cached<T, &Self>
    where
        T: Cachable,
    {
        Cached::new(self, cell)
    }

    /// Discard any value that implements [`Cachable`].
    ///
    /// Unlike [`Cached`], this do not allocate anything.
    #[inline]
    fn discard<T>(&self, cell: T)
    where
        T: Cachable,
    {
        cell.cache(self);
    }
}

impl<T: ?Sized + CellCache> CellCacheExt for T {}

macro_rules! cachable_impl_tuple {
    () => {};
    ($t1:ident $(, $t:ident)*) => {
        #[allow(non_snake_case)]
        /// Auto-impl for tuple.
        impl<$t1: Cachable $(, $t: Cachable)*> Cachable for ($t1, $($t),*) {
            fn cache<Cache: CellCache + ?Sized>(self, cache: &Cache) {
                let ($t1, $($t),*) = self;
                $t1.cache(cache);
                $($t.cache(cache);)*
            }
        }

        cachable_impl_tuple![$($t),*];
    };
}

cachable_impl_tuple![A, B, C, D, E, F, G, H, I, J, K, L];

/// Auto-impl for unit type.
impl Cachable for () {
    fn cache<C: CellCache + ?Sized>(self, _: &C) {}
}

/// Auto-impl for [`Option`].
impl<T: Cachable> Cachable for Option<T> {
    #[inline]
    fn cache<C: ?Sized + CellCache>(self, c: &C) {
        if let Some(t) = self {
            t.cache(c);
        }
    }
}

/// Auto-impl for [`Vec`].
impl<T: Cachable> Cachable for Vec<T> {
    fn cache<C: ?Sized + CellCache>(self, c: &C) {
        for t in self {
            t.cache(c);
        }
    }
}

/// Auto-impl for arrays.
impl<const N: usize, T: Cachable> Cachable for [T; N] {
    fn cache<C: ?Sized + CellCache>(self, c: &C) {
        for t in self {
            t.cache(c);
        }
    }
}

impl Cachable for FixedCell {
    #[inline]
    fn cache<C: ?Sized + CellCache>(self, c: &C) {
        c.cache_cell(self);
    }
}

impl Cachable for CellTy {
    #[inline]
    fn cache<C: ?Sized + CellCache>(self, c: &C) {
        if let Self::Fixed(t) = self {
            t.cache(c);
        }
    }
}

impl Cachable for Cell {
    #[inline]
    fn cache<C: ?Sized + CellCache>(self, c: &C) {
        self.data.cache(c);
    }
}

impl<T> CellCache for T
where
    T: Deref,
    T::Target: CellCache,
{
    #[inline]
    fn cache_cell(&self, cell: FixedCell) {
        <T::Target as CellCache>::cache_cell(&**self, cell);
    }

    #[inline]
    fn get_cached(&self) -> FixedCell {
        <T::Target as CellCache>::get_cached(&**self)
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
        struct S<'a, T>(&'a mut ManuallyDrop<T>);

        impl<T> Drop for S<'_, T> {
            fn drop(&mut self) {
                // SAFETY: value will not be accessed nor moved.
                unsafe { ManuallyDrop::drop(self.0) }
            }
        }

        let g = S(&mut self.cache);
        // SAFETY: cell will not be accessed nor moved.
        unsafe { ManuallyDrop::take(&mut self.cell).cache(&**g.0) }
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
    /// use onioncloud_ll_cell::fixed::FixedCell;
    /// use onioncloud_ll_cell::cache::{Cached, StandardCellCache};
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
    /// use onioncloud_ll_cell::fixed::FixedCell;
    /// use onioncloud_ll_cell::typed::Padding;
    /// use onioncloud_ll_cell::cache::{Cached, StandardCellCache};
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
    /// use onioncloud_ll_cell::fixed::FixedCell;
    /// use onioncloud_ll_cell::typed::Padding;
    /// use onioncloud_ll_cell::cell::Cell;
    /// use onioncloud_ll_cell::cache::{Cached, StandardCellCache};
    ///
    /// let cell = Cached::new(StandardCellCache::default(), Padding::new(FixedCell::default()));
    /// let cell = Cached::map_into::<Cell>(cell);
    /// ```
    pub fn map_into<U: Cachable + From<T>>(this: Self) -> Cached<U, C> {
        Cached::map(this, U::from)
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
    /// use onioncloud_ll_cell::cell::Cell;
    /// use onioncloud_ll_cell::fixed::FixedCell;
    /// use onioncloud_ll_cell::typed::Padding;
    /// use onioncloud_ll_cell::cache::{Cached, StandardCellCache};
    ///
    /// let cell = Cached::new(StandardCellCache::default(), Some(Cell::from(Padding::new(FixedCell::default()))));
    /// let cell = Cached::transpose(cell).unwrap();
    /// ```
    pub fn transpose(this: Self) -> Option<Cached<T, C>> {
        let (cell, cache) = Self::decompose(this);
        Some(Cached::new(cache, cell?))
    }
}
