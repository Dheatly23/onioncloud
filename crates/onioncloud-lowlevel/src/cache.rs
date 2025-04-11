use crossbeam_queue::ArrayQueue;

use crate::cell::FixedCell;
use crate::cell::dispatch::CellCache;

/// Standard cell cache.
///
/// Should be put in an [`std::sync::Arc`] to be able to share it across threads.
/// Optionally, create a global cache to be used for all.
pub struct StandardCellCache {
    buf: ArrayQueue<FixedCell>,
}

/// Creates cell cache with default 256 items.
impl Default for StandardCellCache {
    fn default() -> Self {
        Self::new(256)
    }
}

impl StandardCellCache {
    pub fn new(size: usize) -> Self {
        Self {
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
        self.buf.pop().unwrap_or_default()
    }

    fn cache_cell(&self, cell: FixedCell) {
        let _ = self.buf.push(cell);
    }
}
