//! Padding cell types.

use crate::cell::{AutoReturnFixed, AutoReturnVariable, Cell, CellHeader, TryFromCell};
use crate::error::{CellCastError, NonZeroCircID};
use crate::fixed::{FIXED_CELL_SIZE, FixedCell};
use crate::variable::VariableCell;

/// `PADDING` cell.
#[derive(Debug)]
pub struct Padding {
    cell: FixedCell,
}

impl TryFromCell for Padding {
    type Error = CellCastError;

    fn try_from_cell(cell: &mut Option<Cell>) -> Result<Option<Self>, Self::Error> {
        if let Some(cell) = AutoReturnFixed::new(cell)?
            && cell.header().command == Self::ID
        {
            if cell.header().circuit == 0 {
                Ok(Some(Self {
                    cell: cell.into_inner().1,
                }))
            } else {
                Err(NonZeroCircID.into())
            }
        } else {
            Ok(None)
        }
    }
}

impl From<Padding> for Cell {
    fn from(cell: Padding) -> Self {
        Self::from_fixed(
            CellHeader {
                command: Padding::ID,
                circuit: 0,
            },
            cell.into_inner(),
        )
    }
}

impl From<Padding> for FixedCell {
    #[inline]
    fn from(v: Padding) -> FixedCell {
        v.into_inner()
    }
}

impl AsRef<FixedCell> for Padding {
    #[inline]
    fn as_ref(&self) -> &FixedCell {
        self.inner()
    }
}

impl AsMut<FixedCell> for Padding {
    #[inline]
    fn as_mut(&mut self) -> &mut FixedCell {
        self.inner_mut()
    }
}

impl AsRef<[u8; FIXED_CELL_SIZE]> for Padding {
    #[inline]
    fn as_ref(&self) -> &[u8; FIXED_CELL_SIZE] {
        self.inner().data()
    }
}

impl AsMut<[u8; FIXED_CELL_SIZE]> for Padding {
    #[inline]
    fn as_mut(&mut self) -> &mut [u8; FIXED_CELL_SIZE] {
        self.inner_mut().data_mut()
    }
}

impl AsRef<[u8]> for Padding {
    #[inline]
    fn as_ref(&self) -> &[u8] {
        self.inner().data()
    }
}

impl AsMut<[u8]> for Padding {
    #[inline]
    fn as_mut(&mut self) -> &mut [u8] {
        self.inner_mut().data_mut()
    }
}

impl Padding {
    /// Cell ID of `PADDING`.
    pub const ID: u8 = 0;

    /// Creates new [`Padding`] cell.
    ///
    /// The content of `cell` does not matter, but user should fill it with padding bytes.
    #[inline]
    #[must_use]
    pub const fn new(cell: FixedCell) -> Self {
        Self { cell }
    }

    /// Gets reference to inner.
    #[inline]
    #[must_use]
    pub fn inner(&self) -> &FixedCell {
        &self.cell
    }

    /// Gets mutable reference to inner.
    #[inline]
    pub fn inner_mut(&mut self) -> &mut FixedCell {
        &mut self.cell
    }

    /// Unwraps into inner.
    #[inline]
    #[must_use]
    pub fn into_inner(self) -> FixedCell {
        self.cell
    }
}

/// `VPADDING` cell.
#[derive(Debug)]
pub struct VPadding {
    cell: VariableCell,
}

impl TryFromCell for VPadding {
    type Error = CellCastError;

    fn try_from_cell(cell: &mut Option<Cell>) -> Result<Option<Self>, Self::Error> {
        if let Some(cell) = AutoReturnVariable::new(cell)?
            && cell.header().command == Self::ID
        {
            if cell.header().circuit == 0 {
                Ok(Some(Self {
                    cell: cell.into_inner().1,
                }))
            } else {
                Err(NonZeroCircID.into())
            }
        } else {
            Ok(None)
        }
    }
}

impl From<VPadding> for Cell {
    fn from(cell: VPadding) -> Self {
        Self::from_variable(
            CellHeader {
                command: VPadding::ID,
                circuit: 0,
            },
            cell.into_inner(),
        )
    }
}

impl From<VPadding> for VariableCell {
    #[inline]
    fn from(v: VPadding) -> VariableCell {
        v.into_inner()
    }
}

impl AsRef<VariableCell> for VPadding {
    #[inline]
    fn as_ref(&self) -> &VariableCell {
        self.inner()
    }
}

impl AsMut<VariableCell> for VPadding {
    #[inline]
    fn as_mut(&mut self) -> &mut VariableCell {
        self.inner_mut()
    }
}

impl AsRef<[u8]> for VPadding {
    #[inline]
    fn as_ref(&self) -> &[u8] {
        self.inner().data()
    }
}

impl AsMut<[u8]> for VPadding {
    #[inline]
    fn as_mut(&mut self) -> &mut [u8] {
        self.inner_mut().data_mut()
    }
}

impl VPadding {
    /// Cell ID of `VPADDING`.
    pub const ID: u8 = 128;

    /// Creates new [`VPadding`] cell.
    ///
    /// The content of `cell` does not matter, but user should fill it with padding bytes.
    #[inline]
    #[must_use]
    pub const fn new(cell: VariableCell) -> Self {
        Self { cell }
    }

    /// Gets reference to inner.
    #[inline]
    #[must_use]
    pub fn inner(&self) -> &VariableCell {
        &self.cell
    }

    /// Gets mutable reference to inner.
    #[inline]
    pub fn inner_mut(&mut self) -> &mut VariableCell {
        &mut self.cell
    }

    /// Unwraps into inner.
    #[inline]
    #[must_use]
    pub fn into_inner(self) -> VariableCell {
        self.cell
    }
}
