//! Defines [`Cell`].

use std::fmt::{Debug, Formatter, Result as FmtResult};
use std::mem::ManuallyDrop;

use crate::error::{CellIsFixed, CellIsVariable};
use crate::fixed::FixedCell;
use crate::variable::VariableCell;

/// Cell data type.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum CellTy {
    /// Fixed-length cell.
    Fixed(FixedCell),
    /// Variable-length cell.
    Variable(VariableCell),
}

impl From<FixedCell> for CellTy {
    fn from(v: FixedCell) -> Self {
        Self::Fixed(v)
    }
}

impl From<VariableCell> for CellTy {
    fn from(v: VariableCell) -> Self {
        Self::Variable(v)
    }
}

impl CellTy {
    /// Returns [`true`] if cell is fixed-sized.
    #[inline]
    #[must_use]
    pub const fn is_fixed(&self) -> bool {
        matches!(self, Self::Fixed(_))
    }

    /// Returns [`true`] if cell is variable-sized.
    #[inline]
    #[must_use]
    pub const fn is_variable(&self) -> bool {
        matches!(self, Self::Variable(_))
    }

    /// Try to get [`FixedCell`] reference.
    #[inline]
    #[must_use]
    pub const fn as_fixed(&self) -> Option<&FixedCell> {
        match self {
            Self::Fixed(v) => Some(v),
            Self::Variable(_) => None,
        }
    }

    /// Try to get [`FixedCell`] mutable reference.
    #[inline]
    pub const fn as_fixed_mut(&mut self) -> Option<&mut FixedCell> {
        match self {
            Self::Fixed(v) => Some(v),
            Self::Variable(_) => None,
        }
    }

    /// Try to get [`VariableCell`] reference.
    #[inline]
    #[must_use]
    pub const fn as_variable(&self) -> Option<&VariableCell> {
        match self {
            Self::Variable(v) => Some(v),
            Self::Fixed(_) => None,
        }
    }

    /// Try to get [`VariableCell`] mutable reference.
    #[inline]
    pub const fn as_variable_mut(&mut self) -> Option<&mut VariableCell> {
        match self {
            Self::Variable(v) => Some(v),
            Self::Fixed(_) => None,
        }
    }

    /// Gets reference into cell data.
    #[inline]
    #[must_use]
    pub fn data(&self) -> &[u8] {
        match self {
            Self::Fixed(v) => v.as_ref(),
            Self::Variable(v) => v.as_ref(),
        }
    }

    /// Gets mutable reference into cell data.
    #[inline]
    pub fn data_mut(&mut self) -> &mut [u8] {
        match self {
            Self::Fixed(v) => v.as_mut(),
            Self::Variable(v) => v.as_mut(),
        }
    }
}

/// Cell header.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Hash)]
pub struct CellHeader {
    /// Cell type.
    pub command: u8,
    /// Circuit ID.
    pub circuit: u32,
}

/// A cell.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Cell {
    /// Cell header.
    pub header: CellHeader,
    /// Cell data.
    pub data: CellTy,
}

impl Default for Cell {
    fn default() -> Self {
        Self::empty_fixed()
    }
}

impl AsRef<[u8]> for Cell {
    fn as_ref(&self) -> &[u8] {
        self.data()
    }
}

impl AsMut<[u8]> for Cell {
    fn as_mut(&mut self) -> &mut [u8] {
        self.data_mut()
    }
}

impl Cell {
    /// Creates new cell.
    #[inline]
    pub fn new(header: CellHeader, data: impl Into<CellTy>) -> Self {
        Self {
            header,
            data: data.into(),
        }
    }

    /// Creates empty fixed-sized cell.
    #[must_use]
    pub fn empty_fixed() -> Self {
        Self::from_fixed(CellHeader::default(), FixedCell::default())
    }

    /// Creates fixed-sized cell.
    #[inline]
    #[must_use]
    pub const fn from_fixed(header: CellHeader, data: FixedCell) -> Self {
        Self {
            header,
            data: CellTy::Fixed(data),
        }
    }

    /// Creates variable-sized cell.
    #[inline]
    #[must_use]
    pub const fn from_variable(header: CellHeader, data: VariableCell) -> Self {
        Self {
            header,
            data: CellTy::Variable(data),
        }
    }

    /// Gets reference into cell data.
    #[inline]
    #[must_use]
    pub fn data(&self) -> &[u8] {
        self.data.data()
    }

    /// Gets mutable reference into cell data.
    #[inline]
    pub fn data_mut(&mut self) -> &mut [u8] {
        self.data.data_mut()
    }

    /// Returns [`true`] if cell is fixed-sized.
    #[inline]
    #[must_use]
    pub fn is_fixed(&self) -> bool {
        self.data.is_fixed()
    }

    /// Returns [`true`] if cell is variable-sized.
    #[inline]
    #[must_use]
    pub fn is_variable(&self) -> bool {
        self.data.is_variable()
    }

    /// Try to get [`FixedCell`] reference.
    #[inline]
    #[must_use]
    pub fn as_fixed(&self) -> Option<&FixedCell> {
        self.data.as_fixed()
    }

    /// Try to get [`FixedCell`] mutable reference.
    #[inline]
    pub fn as_fixed_mut(&mut self) -> Option<&mut FixedCell> {
        self.data.as_fixed_mut()
    }

    /// Try to get [`VariableCell`] reference.
    #[inline]
    #[must_use]
    pub fn as_variable(&self) -> Option<&VariableCell> {
        self.data.as_variable()
    }

    /// Try to get [`VariableCell`] mutable reference.
    #[inline]
    pub fn as_variable_mut(&mut self) -> Option<&mut VariableCell> {
        self.data.as_variable_mut()
    }
}

/// Trait for casting from [`Cell`].
///
/// # Implementer's Note
///
/// **[`Self::try_from_cell`] should not mutate nor drop the cell.**
/// If the cell does not match, it should return the cell back.
/// This allows user to match for multiple types.
///
/// # Errors
///
/// It **should not** return error if the [`command`](`CellHeader::command`) ID does not match.
/// If the command ID does not match, return `Ok(None)` instead.
pub trait TryFromCell: Sized {
    type Error;

    fn try_from_cell(cell: &mut Option<Cell>) -> Result<Option<Self>, Self::Error>;
}

/// Automatically returns [`Cell`] when dropped.
///
/// Useful to help implement [`TryFromCell`].
pub struct AutoReturnFixed<'a> {
    p: &'a mut Option<Cell>,
    h: CellHeader,
    c: ManuallyDrop<FixedCell>,
}

impl Drop for AutoReturnFixed<'_> {
    fn drop(&mut self) {
        // SAFETY: Cell is not dropped and there is no way of accessing it post-drop.
        unsafe { *self.p = Some(Cell::from_fixed(self.h, ManuallyDrop::take(&mut self.c))) }
    }
}

impl Debug for AutoReturnFixed<'_> {
    #[inline]
    fn fmt(&self, f: &mut Formatter) -> FmtResult {
        f.debug_struct("AutoReturnFixed")
            .field("header", &self.h)
            .field("data", &*self.c)
            .finish()
    }
}

impl<'a> AutoReturnFixed<'a> {
    /// Create new [`AutoReturnFixed`].
    ///
    /// If `ptr` is [`None`], it will return `Ok(None)`.
    ///
    /// # Errors
    ///
    /// Returns error if cell is variable-length.
    #[inline]
    pub fn new(ptr: &'a mut Option<Cell>) -> Result<Option<Self>, CellIsVariable> {
        match ptr.take() {
            Some(Cell {
                header: h,
                data: CellTy::Fixed(c),
            }) => Ok(Some(Self {
                p: ptr,
                h,
                c: ManuallyDrop::new(c),
            })),
            c @ Some(Cell {
                data: CellTy::Variable(_),
                ..
            }) => {
                *ptr = c;
                Err(CellIsVariable)
            }
            None => Ok(None),
        }
    }

    /// Gets reference to header.
    #[inline]
    #[must_use]
    pub fn header(&self) -> &CellHeader {
        &self.h
    }

    /// Gets reference to [`FixedCell`].
    #[inline]
    #[must_use]
    pub fn data(&self) -> &FixedCell {
        &self.c
    }

    /// Unwraps into inner.
    #[inline]
    #[must_use]
    pub fn into_inner(self) -> (CellHeader, FixedCell) {
        let h = self.h;
        let mut this = ManuallyDrop::new(self);
        // SAFETY: Cell is not dropped and self will not be dropped.
        (h, unsafe { ManuallyDrop::take(&mut this.c) })
    }
}

/// Automatically returns [`Cell`] when dropped.
///
/// Useful to help implement [`TryFromCell`].
pub struct AutoReturnVariable<'a> {
    p: &'a mut Option<Cell>,
    h: CellHeader,
    c: ManuallyDrop<VariableCell>,
}

impl Drop for AutoReturnVariable<'_> {
    fn drop(&mut self) {
        // SAFETY: Cell is not dropped and there is no way of accessing it post-drop.
        unsafe { *self.p = Some(Cell::from_variable(self.h, ManuallyDrop::take(&mut self.c))) }
    }
}

impl Debug for AutoReturnVariable<'_> {
    #[inline]
    fn fmt(&self, f: &mut Formatter) -> FmtResult {
        f.debug_struct("AutoReturnVariable")
            .field("header", &self.h)
            .field("data", &*self.c)
            .finish()
    }
}

impl<'a> AutoReturnVariable<'a> {
    /// Create new [`AutoReturnVariable`].
    ///
    /// If `ptr` is [`None`], it will return `Ok(None)`.
    ///
    /// # Errors
    ///
    /// Returns error if cell is fixed-length.
    #[inline]
    pub fn new(ptr: &'a mut Option<Cell>) -> Result<Option<Self>, CellIsFixed> {
        match ptr.take() {
            Some(Cell {
                header: h,
                data: CellTy::Variable(c),
            }) => Ok(Some(Self {
                p: ptr,
                h,
                c: ManuallyDrop::new(c),
            })),
            c @ Some(Cell {
                data: CellTy::Fixed(_),
                ..
            }) => {
                *ptr = c;
                Err(CellIsFixed)
            }
            None => Ok(None),
        }
    }

    /// Gets reference to header.
    #[inline]
    #[must_use]
    pub fn header(&self) -> &CellHeader {
        &self.h
    }

    /// Gets reference to [`VariableCell`].
    #[inline]
    #[must_use]
    pub fn data(&self) -> &VariableCell {
        &self.c
    }

    /// Unwraps into inner.
    #[inline]
    #[must_use]
    pub fn into_inner(self) -> (CellHeader, VariableCell) {
        let h = self.h;
        let mut this = ManuallyDrop::new(self);
        // SAFETY: Cell is not dropped and self will not be dropped.
        (h, unsafe { ManuallyDrop::take(&mut this.c) })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::assert_matches;
    use std::hint::black_box;

    #[test]
    fn test_auto_return_drop() {
        let mut cell = black_box(Some(Cell::empty_fixed()));
        let ar = black_box(AutoReturnFixed::new(&mut cell)).unwrap();
        drop(ar);
        assert_matches!(cell, Some(_));
    }

    #[test]
    fn test_auto_return_none() {
        let mut cell = black_box(None::<Cell>);
        let ar = black_box(AutoReturnFixed::new(&mut cell));
        assert_matches!(ar, None);
        drop(ar);
        assert_matches!(cell, None);
    }

    #[test]
    fn test_auto_return_take() {
        let mut cell = black_box(Some(Cell::default()));
        let ar = black_box(AutoReturnFixed::new(&mut cell)).unwrap();
        drop(ar.into_inner());
        assert_matches!(cell, None);
    }
}
