//! Defines [`VariableCell`].

use std::fmt::{Debug, Display, Formatter, Result as FmtResult, from_fn};
use std::num::NonZeroUsize;

use crate::error::VariableCellTooLong;
use crate::fixed::{FIXED_CELL_SIZE, FixedCell};
use crate::utils::base64u_encode;

/// A variable-sized cell.
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct VariableCell {
    inner: Box<[u8]>,
}

impl Default for VariableCell {
    fn default() -> Self {
        Self::empty()
    }
}

impl Display for VariableCell {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        base64u_encode(self.data()).fmt(f)
    }
}

impl Debug for VariableCell {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        f.debug_struct("VariableCell")
            .field("inner", &from_fn(|f| Display::fmt(self, f)))
            .finish()
    }
}

impl AsRef<[u8]> for VariableCell {
    fn as_ref(&self) -> &[u8] {
        self.data()
    }
}

impl AsMut<[u8]> for VariableCell {
    fn as_mut(&mut self) -> &mut [u8] {
        self.data_mut()
    }
}

impl<'a> TryFrom<&'a [u8]> for VariableCell {
    type Error = VariableCellTooLong;

    fn try_from(v: &'a [u8]) -> Result<Self, Self::Error> {
        if let Some(len) = NonZeroUsize::new(v.len())
            && len.get() > 65535
        {
            return Err(VariableCellTooLong { len });
        }

        Ok(Self::new(Box::from(v)))
    }
}

impl TryFrom<Vec<u8>> for VariableCell {
    type Error = VariableCellTooLong;

    fn try_from(v: Vec<u8>) -> Result<Self, Self::Error> {
        if let Some(len) = NonZeroUsize::new(v.len())
            && len.get() > 65535
        {
            return Err(VariableCellTooLong { len });
        }

        Ok(Self::new(v.into_boxed_slice()))
    }
}

impl TryFrom<Box<[u8]>> for VariableCell {
    type Error = VariableCellTooLong;

    fn try_from(v: Box<[u8]>) -> Result<Self, Self::Error> {
        if let Some(len) = NonZeroUsize::new(v.len())
            && len.get() > 65535
        {
            return Err(VariableCellTooLong { len });
        }

        Ok(Self::new(v))
    }
}

/// Will only take the first 65535 elements.
impl FromIterator<u8> for VariableCell {
    fn from_iter<T: IntoIterator<Item = u8>>(it: T) -> Self {
        Self::new(it.into_iter().take(65535).collect())
    }
}

impl VariableCell {
    /// Create new `VariableCell`.
    ///
    /// # Panics
    ///
    /// Panics if `inner` is longer than 65535.
    #[inline]
    #[must_use]
    pub const fn new(inner: Box<[u8]>) -> Self {
        assert!(inner.len() < 65536);
        Self { inner }
    }

    /// Create an empty cell.
    #[must_use]
    pub fn empty() -> Self {
        Self::new(Box::new([]))
    }

    /// Gets reference into cell data.
    #[inline]
    #[must_use]
    pub fn data(&self) -> &[u8] {
        &self.inner
    }

    /// Gets mutable reference into cell data.
    #[inline]
    pub fn data_mut(&mut self) -> &mut [u8] {
        &mut self.inner
    }

    /// Unwraps inner data.
    #[inline]
    #[must_use]
    pub fn into_inner(self) -> Box<[u8]> {
        self.inner
    }

    /// Returns [`true`] if cell is empty.
    #[inline]
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }

    /// Returns cell data length.
    #[inline]
    #[must_use]
    pub fn len(&self) -> usize {
        self.inner.len()
    }

    /// Try to cast into [`FixedCell`].
    ///
    /// If cast fails, returns itself.
    pub fn try_into_fixed(self) -> Result<FixedCell, Self> {
        // Do the same thing as nightly Box::into_array
        if self.inner.len() == FIXED_CELL_SIZE {
            let ptr = Box::into_raw(self.inner).cast::<[u8; FIXED_CELL_SIZE]>();
            // SAFETY: Slice length is equal to array length.
            unsafe { Ok(FixedCell::new(Box::from_raw(ptr))) }
        } else {
            Err(self)
        }
    }
}
