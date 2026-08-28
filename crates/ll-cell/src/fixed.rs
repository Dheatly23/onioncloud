//! Defines [`FixedCell`].

use std::fmt::{Debug, Display, Formatter, Result as FmtResult, from_fn};

use base64ct::{Base64Unpadded, Encoding};

use crate::utils::encoded_len;

/// Size of [`FixedCell`] content.
pub const FIXED_CELL_SIZE: usize = 509;

/// A fixed-size cell.
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct FixedCell {
    inner: Box<[u8; FIXED_CELL_SIZE]>,
}

impl Default for FixedCell {
    fn default() -> Self {
        Self::new(Box::new([0; FIXED_CELL_SIZE]))
    }
}

impl Display for FixedCell {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        // Encode as base64
        const LEN: usize = encoded_len(FIXED_CELL_SIZE);
        let mut a = [0u8; LEN];
        let out = Base64Unpadded::encode(self.data(), &mut a).expect("conversion must never fail");
        f.write_str(out)
    }
}

impl Debug for FixedCell {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        f.debug_struct("FixedCell")
            .field("inner", &from_fn(|f| Display::fmt(self, f)))
            .finish()
    }
}

impl AsRef<[u8; FIXED_CELL_SIZE]> for FixedCell {
    fn as_ref(&self) -> &[u8; FIXED_CELL_SIZE] {
        self.data()
    }
}

impl AsMut<[u8; FIXED_CELL_SIZE]> for FixedCell {
    fn as_mut(&mut self) -> &mut [u8; FIXED_CELL_SIZE] {
        self.data_mut()
    }
}

impl AsRef<[u8]> for FixedCell {
    fn as_ref(&self) -> &[u8] {
        self.data()
    }
}

impl AsMut<[u8]> for FixedCell {
    fn as_mut(&mut self) -> &mut [u8] {
        self.data_mut()
    }
}

impl From<[u8; FIXED_CELL_SIZE]> for FixedCell {
    fn from(arr: [u8; FIXED_CELL_SIZE]) -> Self {
        Self::new(Box::new(arr))
    }
}

impl<'a> From<&'a [u8; FIXED_CELL_SIZE]> for FixedCell {
    fn from(arr: &'a [u8; FIXED_CELL_SIZE]) -> Self {
        Self::new(Box::new(*arr))
    }
}

impl From<Box<[u8; FIXED_CELL_SIZE]>> for FixedCell {
    fn from(data: Box<[u8; FIXED_CELL_SIZE]>) -> Self {
        Self::new(data)
    }
}

impl FixedCell {
    /// Create new [`FixedCell`].
    ///
    /// Argument:
    /// - `inner` : Cell data.
    #[inline]
    #[must_use]
    pub const fn new(inner: Box<[u8; FIXED_CELL_SIZE]>) -> Self {
        Self { inner }
    }

    /// Create [`FixedCell`] from a slice.
    ///
    /// If slice is smaller than [`FIXED_CELL_SIZE`], the rest of the bytes are set to 0.
    ///
    /// # Panics
    ///
    /// Panics if `data` is longer than [`FIXED_CELL_SIZE`].
    ///
    /// # Example
    ///
    /// ```
    /// # use onioncloud_ll_cell::fixed::FixedCell;
    /// // Create cell from data
    /// let cell = FixedCell::from_slice(b"test");
    /// ```
    ///
    /// ```should_panic
    /// # use onioncloud_ll_cell::fixed::{FixedCell, FIXED_CELL_SIZE};
    /// // Data is too long
    /// let cell = FixedCell::from_slice(&[100; FIXED_CELL_SIZE + 1]);
    /// ```
    #[must_use]
    pub fn from_slice(data: &[u8]) -> Self {
        assert!(
            data.len() <= FIXED_CELL_SIZE,
            "data is longer than FIXED_CELL_SIZE"
        );

        let mut a = [0u8; 509];
        a[..data.len()].copy_from_slice(data);
        Self::from(a)
    }

    /// Get reference into cell data.
    #[inline]
    #[must_use]
    pub fn data(&self) -> &[u8; FIXED_CELL_SIZE] {
        &self.inner
    }

    /// Get mutable reference into cell data.
    #[inline]
    pub fn data_mut(&mut self) -> &mut [u8; FIXED_CELL_SIZE] {
        &mut self.inner
    }

    /// Unwraps inner data.
    #[inline]
    #[must_use]
    pub fn into_inner(self) -> Box<[u8; FIXED_CELL_SIZE]> {
        self.inner
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use tracing::info;

    #[test_log::test]
    fn test_fixed_cell_display() {
        let cell = FixedCell::default();
        info!("Cell content: {cell}");
    }

    #[test_log::test]
    fn test_fixed_cell_debug() {
        let cell = FixedCell::default();
        info!(?cell, "Created cell");
    }

    #[test]
    #[should_panic(expected = "data is longer than FIXED_CELL_SIZE")]
    fn test_fixed_cell_from_slice_too_long() {
        FixedCell::from_slice(&[100; FIXED_CELL_SIZE + 1]);
    }
}
