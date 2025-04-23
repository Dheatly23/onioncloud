use rand::prelude::*;

use super::{
    Cell, CellHeader, CellLike, CellRef, FIXED_CELL_SIZE, FixedCell, TryFromCell, VariableCell,
    to_fixed, to_variable,
};
use crate::errors;

/// Represents a PADDING cell.
#[derive(Debug, Default, Clone, PartialEq, Eq, Hash)]
pub struct Padding(FixedCell);

impl AsRef<FixedCell> for Padding {
    fn as_ref(&self) -> &FixedCell {
        &self.0
    }
}

impl AsMut<FixedCell> for Padding {
    fn as_mut(&mut self) -> &mut FixedCell {
        &mut self.0
    }
}

impl From<Padding> for Cell {
    fn from(v: Padding) -> Cell {
        Cell::from_fixed(CellHeader::new(0, Padding::ID), v.into_inner())
    }
}

impl From<Padding> for FixedCell {
    fn from(v: Padding) -> FixedCell {
        v.into_inner()
    }
}

impl CellLike for Padding {
    fn circuit(&self) -> u32 {
        0
    }

    fn command(&self) -> u8 {
        Self::ID
    }

    fn cell(&self) -> CellRef<'_> {
        CellRef::Fixed(&self.0)
    }
}

impl Padding {
    /// PADDING command ID.
    pub const ID: u8 = 0;

    /// Create new PADDING cell.
    pub fn new(data: FixedCell) -> Self {
        Self(data)
    }

    /// Gets reference into padding data.
    pub fn data(&self) -> &[u8; FIXED_CELL_SIZE] {
        self.0.data()
    }

    /// Gets mutable reference into padding data.
    pub fn data_mut(&mut self) -> &mut [u8; FIXED_CELL_SIZE] {
        self.0.data_mut()
    }

    /// Unwraps into inner [`FixedCell`].
    pub fn into_inner(self) -> FixedCell {
        self.0
    }

    /// Randomize cell content.
    pub fn fill(&mut self) {
        ThreadRng::default().fill(self.data_mut());
    }
}

impl TryFromCell for Padding {
    fn try_from_cell(cell: &mut Option<Cell>) -> Result<Option<Self>, errors::CellFormatError> {
        let Some(
            c @ Cell {
                command: Self::ID, ..
            },
        ) = cell.as_ref()
        else {
            return Ok(None);
        };
        if c.circuit != 0 {
            return Err(errors::CellFormatError);
        }
        to_fixed(cell).map(|v| v.map(Self::new))
    }
}

/// Represents a VPADDING cell.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct VPadding(VariableCell);

impl AsRef<VariableCell> for VPadding {
    fn as_ref(&self) -> &VariableCell {
        &self.0
    }
}

impl AsMut<VariableCell> for VPadding {
    fn as_mut(&mut self) -> &mut VariableCell {
        &mut self.0
    }
}

impl From<VPadding> for Cell {
    fn from(v: VPadding) -> Cell {
        Cell::from_variable(CellHeader::new(0, VPadding::ID), v.into_inner())
    }
}

impl CellLike for VPadding {
    fn circuit(&self) -> u32 {
        0
    }

    fn command(&self) -> u8 {
        Self::ID
    }

    fn cell(&self) -> CellRef<'_> {
        CellRef::Variable(&self.0)
    }
}

impl VPadding {
    /// VPADDING command ID.
    pub const ID: u8 = 128;

    /// Create new VPADDING cell.
    pub fn new(data: VariableCell) -> Self {
        Self(data)
    }

    /// Create new VPADDING cell filled with random bytes.
    ///
    /// ```
    /// use onioncloud_lowlevel::cell::padding::VPadding;
    ///
    /// let cell = VPadding::with_size(16);
    ///
    /// assert_eq!(cell.data().len(), 16);
    ///
    /// // Cell content are randomized
    /// println!("{:?}", cell.data());
    /// ```
    pub fn with_size(n: u16) -> Self {
        // SAFETY: It will be filled by RNG. RNG should not depends on slice content.
        let mut data: Box<[u8]> = unsafe { Box::new_uninit_slice(n.into()).assume_init() };
        ThreadRng::default().fill(&mut data[..]);
        Self::new(VariableCell::new(data))
    }

    /// Gets reference into padding data.
    pub fn data(&self) -> &[u8] {
        self.0.data()
    }

    /// Gets mutable reference into padding data.
    pub fn data_mut(&mut self) -> &mut [u8] {
        self.0.data_mut()
    }

    /// Unwraps into inner [`VariableCell`].
    pub fn into_inner(self) -> VariableCell {
        self.0
    }

    /// Randomize cell content.
    pub fn fill(&mut self) {
        ThreadRng::default().fill(self.data_mut());
    }
}

impl TryFromCell for VPadding {
    fn try_from_cell(cell: &mut Option<Cell>) -> Result<Option<Self>, errors::CellFormatError> {
        let Some(
            c @ Cell {
                command: Self::ID, ..
            },
        ) = cell.as_ref()
        else {
            return Ok(None);
        };
        if c.circuit != 0 {
            return Err(errors::CellFormatError);
        }
        to_variable(cell).map(|v| v.map(Self::new))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use proptest::prelude::*;

    proptest! {
        #[test]
        fn test_vpadding_size(length in any::<u16>()) {
            let cell = VPadding::with_size(length);
            assert_eq!(cell.data().len(), length as usize);
        }
    }
}
