use crate::errors;

/// Size of [`FixedCell`] content.
pub const FIXED_CELL_SIZE: usize = 509;

/// A fixed-sized cell.
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct FixedCell {
    inner: Box<[u8; FIXED_CELL_SIZE]>,
}

impl Default for FixedCell {
    fn default() -> Self {
        Self {
            inner: Box::new([0; FIXED_CELL_SIZE]),
        }
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

impl From<[u8; FIXED_CELL_SIZE]> for FixedCell {
    fn from(arr: [u8; FIXED_CELL_SIZE]) -> Self {
        Self::new(Box::new(arr))
    }
}

impl<'a> TryFrom<&'a [u8]> for FixedCell {
    type Error = errors::InvalidLength;

    fn try_from(data: &'a [u8]) -> Result<Self, Self::Error> {
        data.get(..FIXED_CELL_SIZE)
            .and_then(|v| v.try_into().ok())
            .map(|v| Self::new(Box::new(v)))
            .ok_or(errors::InvalidLength)
    }
}

impl FixedCell {
    /// Creates new `FixedCell`.
    pub const fn new(inner: Box<[u8; FIXED_CELL_SIZE]>) -> Self {
        Self { inner }
    }

    /// Gets reference into cell data.
    pub fn data(&self) -> &[u8; FIXED_CELL_SIZE] {
        &self.inner
    }

    /// Gets mutable reference into cell data.
    pub fn data_mut(&mut self) -> &mut [u8; FIXED_CELL_SIZE] {
        &mut self.inner
    }

    /// Unwraps inner data.
    pub fn into_inner(self) -> Box<[u8; FIXED_CELL_SIZE]> {
        self.inner
    }
}

/// A variable-sized cell.
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct VariableCell {
    inner: Box<[u8]>,
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

impl<'a> From<&'a [u8]> for VariableCell {
    fn from(data: &'a [u8]) -> Self {
        Self::new(Box::from(data))
    }
}

impl From<Vec<u8>> for VariableCell {
    fn from(v: Vec<u8>) -> Self {
        Self::new(v.into())
    }
}

impl VariableCell {
    /// Creates new `VariableCell`.
    pub const fn new(inner: Box<[u8]>) -> Self {
        Self { inner }
    }

    /// Creates an empty cell.
    pub fn empty() -> Self {
        Self::new(Box::new([]))
    }

    /// Gets reference into cell data.
    pub fn data(&self) -> &[u8] {
        &self.inner
    }

    /// Gets mutable reference into cell data.
    pub fn data_mut(&mut self) -> &mut [u8] {
        &mut self.inner
    }

    /// Unwraps inner data.
    pub fn into_inner(self) -> Box<[u8]> {
        self.inner
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

pub struct Cell {
    pub channel: u32,
    pub command: u8,
    data: CellData,
}

enum CellData {
    Fixed(FixedCell),
    Variable(VariableCell),
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
    /// Creates empty fixed-sized cell.
    pub fn empty_fixed() -> Self {
        Self::from_fixed(0, 0, FixedCell::default())
    }

    /// Creates fixed-sized cell.
    pub const fn from_fixed(channel: u32, command: u8, data: FixedCell) -> Self {
        Self {
            channel,
            command,
            data: CellData::Fixed(data),
        }
    }

    /// Creates variable-sized cell.
    pub const fn from_variable(channel: u32, command: u8, data: VariableCell) -> Self {
        Self {
            channel,
            command,
            data: CellData::Variable(data),
        }
    }

    /// Gets reference into cell data.
    pub fn data(&self) -> &[u8] {
        match &self.data {
            CellData::Fixed(v) => &v.data()[..],
            CellData::Variable(v) => v.data(),
        }
    }

    /// Gets mutable reference into cell data.
    pub fn data_mut(&mut self) -> &mut [u8] {
        match &mut self.data {
            CellData::Fixed(v) => &mut v.data_mut()[..],
            CellData::Variable(v) => v.data_mut(),
        }
    }

    /// Try to get [`FixedCell`] reference.
    pub fn as_fixed(&self) -> Option<&FixedCell> {
        match &self.data {
            CellData::Fixed(v) => Some(v),
            _ => None,
        }
    }

    /// Try to get [`FixedCell`] mutable reference.
    pub fn as_fixed_mut(&mut self) -> Option<&mut FixedCell> {
        match &mut self.data {
            CellData::Fixed(v) => Some(v),
            _ => None,
        }
    }

    /// Try to get [`VariableCell`] reference.
    pub fn as_variable(&self) -> Option<&VariableCell> {
        match &self.data {
            CellData::Variable(v) => Some(v),
            _ => None,
        }
    }

    /// Try to get [`VariableCell`] mutable reference.
    pub fn as_variable_mut(&mut self) -> Option<&mut VariableCell> {
        match &mut self.data {
            CellData::Variable(v) => Some(v),
            _ => None,
        }
    }

    /// Try to unwrap into [`FixedCell`].
    pub fn into_fixed(self) -> Result<FixedCell, Self> {
        match self.data {
            CellData::Fixed(v) => Ok(v),
            _ => Err(self),
        }
    }

    /// Try to unwrap into [`VariableCell`].
    pub fn into_variable(self) -> Result<VariableCell, Self> {
        match self.data {
            CellData::Variable(v) => Ok(v),
            _ => Err(self),
        }
    }
}
