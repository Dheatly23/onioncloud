//! Defines [`Cell`].

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
    pub const fn is_fixed(&self) -> bool {
        matches!(self, Self::Fixed(_))
    }

    /// Returns [`true`] if cell is variable-sized.
    #[inline]
    pub const fn is_variable(&self) -> bool {
        matches!(self, Self::Variable(_))
    }

    /// Try to get [`FixedCell`] reference.
    #[inline]
    pub const fn as_fixed(&self) -> Option<&FixedCell> {
        match self {
            Self::Fixed(v) => Some(v),
            _ => None,
        }
    }

    /// Try to get [`FixedCell`] mutable reference.
    #[inline]
    pub const fn as_fixed_mut(&mut self) -> Option<&mut FixedCell> {
        match self {
            Self::Fixed(v) => Some(v),
            _ => None,
        }
    }

    /// Try to get [`VariableCell`] reference.
    #[inline]
    pub const fn as_variable(&self) -> Option<&VariableCell> {
        match self {
            Self::Variable(v) => Some(v),
            _ => None,
        }
    }

    /// Try to get [`VariableCell`] mutable reference.
    #[inline]
    pub const fn as_variable_mut(&mut self) -> Option<&mut VariableCell> {
        match self {
            Self::Variable(v) => Some(v),
            _ => None,
        }
    }

    /// Gets reference into cell data.
    #[inline]
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
    pub fn empty_fixed() -> Self {
        Self::from_fixed(CellHeader::default(), FixedCell::default())
    }

    /// Creates fixed-sized cell.
    #[inline]
    pub const fn from_fixed(header: CellHeader, data: FixedCell) -> Self {
        Self {
            header,
            data: CellTy::Fixed(data),
        }
    }

    /// Creates variable-sized cell.
    #[inline]
    pub const fn from_variable(header: CellHeader, data: VariableCell) -> Self {
        Self {
            header,
            data: CellTy::Variable(data),
        }
    }

    /// Gets reference into cell data.
    #[inline]
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
    pub fn is_fixed(&self) -> bool {
        self.data.is_fixed()
    }

    /// Returns [`true`] if cell is variable-sized.
    #[inline]
    pub fn is_variable(&self) -> bool {
        self.data.is_variable()
    }

    /// Try to get [`FixedCell`] reference.
    #[inline]
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
    pub fn as_variable(&self) -> Option<&VariableCell> {
        self.data.as_variable()
    }

    /// Try to get [`VariableCell`] mutable reference.
    #[inline]
    pub fn as_variable_mut(&mut self) -> Option<&mut VariableCell> {
        self.data.as_variable_mut()
    }
}
