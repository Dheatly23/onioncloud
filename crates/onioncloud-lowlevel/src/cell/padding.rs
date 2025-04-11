use rand::prelude::*;

use super::{Cell, FIXED_CELL_SIZE, FixedCell, TryFromCell, VariableCell, to_fixed, to_variable};
use crate::errors;

/// Represents a PADDING cell.
#[derive(Default, Clone, PartialEq, Eq, Hash)]
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

impl Padding {
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
        let Some(c @ Cell { command: 0, .. }) = cell.as_ref() else {
            return Ok(None);
        };
        if c.circuit != 0 {
            return Err(errors::CellFormatError);
        }
        to_fixed(cell).map(|v| v.map(Self::new))
    }
}

/// Represents a VPADDING cell.
#[derive(Clone, PartialEq, Eq, Hash)]
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

impl VPadding {
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
    pub fn with_size(n: usize) -> Self {
        // SAFETY: It will be filled by RNG. RNG should not depends on slice content.
        let mut data: Box<[u8]> = unsafe { Box::new_uninit_slice(n).assume_init() };
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
        let Some(c @ Cell { command: 128, .. }) = cell.as_ref() else {
            return Ok(None);
        };
        if c.circuit != 0 {
            return Err(errors::CellFormatError);
        }
        to_variable(cell).map(|v| v.map(Self::new))
    }
}
