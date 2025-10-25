use rand::prelude::*;
use std::mem::{size_of, transmute};

use zerocopy::byteorder::big_endian::U16;
use zerocopy::{Immutable, IntoBytes, KnownLayout, TryFromBytes, Unaligned, try_transmute_ref};

use super::{
    Cell, CellHeader, CellLike, CellRef, FIXED_CELL_SIZE, FixedCell, TryFromCell, VariableCell,
    to_fixed, to_fixed_with, to_variable,
};
use crate::cache::{Cachable, CellCache};
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

impl Cachable for Padding {
    fn cache<C: CellCache + ?Sized>(self, cache: &C) {
        self.0.cache(cache);
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
        ThreadRng::default().fill(&mut self.data_mut()[..]);
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

impl Cachable for VPadding {
    fn cache<C: CellCache + ?Sized>(self, cache: &C) {
        self.0.cache(cache);
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

#[derive(TryFromBytes, IntoBytes, KnownLayout, Immutable, Unaligned)]
#[repr(u8)]
enum PaddingNegotiateData {
    V0(PaddingNegotiateV0) = 0,
}

#[derive(TryFromBytes, IntoBytes, KnownLayout, Immutable, Unaligned)]
#[repr(C)]
struct PaddingNegotiateV0 {
    cmd: PaddingNegotiateV0Cmd,
    lo_ms: U16,
    hi_ms: U16,
}

#[derive(TryFromBytes, IntoBytes, KnownLayout, Immutable, Unaligned)]
#[repr(u8)]
enum PaddingNegotiateV0Cmd {
    Stop = 1,
    Start = 2,
}

#[derive(TryFromBytes, IntoBytes, KnownLayout, Immutable, Unaligned)]
#[repr(C)]
struct PaddingNegotiatePadded {
    data: PaddingNegotiateData,
    pad: [u8; const { FIXED_CELL_SIZE - size_of::<PaddingNegotiateData>() }],
}

/// Represents a PADDING_NEGOTIATE cell.
#[derive(Debug, Default, Clone, PartialEq, Eq, Hash)]
pub struct PaddingNegotiate(FixedCell);

impl AsRef<FixedCell> for PaddingNegotiate {
    fn as_ref(&self) -> &FixedCell {
        &self.0
    }
}

impl AsMut<FixedCell> for PaddingNegotiate {
    fn as_mut(&mut self) -> &mut FixedCell {
        &mut self.0
    }
}

impl From<PaddingNegotiate> for Cell {
    fn from(v: PaddingNegotiate) -> Cell {
        Cell::from_fixed(CellHeader::new(0, PaddingNegotiate::ID), v.into_inner())
    }
}

impl From<PaddingNegotiate> for FixedCell {
    fn from(v: PaddingNegotiate) -> FixedCell {
        v.into_inner()
    }
}

impl TryFromCell for PaddingNegotiate {
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
        to_fixed_with(cell, Self::check).map(|v| v.map(|v| unsafe { Self::from_cell(v) }))
    }
}

impl CellLike for PaddingNegotiate {
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

impl PaddingNegotiate {
    /// PADDING_NEGOTIATE command ID.
    pub const ID: u8 = 12;

    /// Create new PADDING_NEGOTIATE cell from existing [`FixedCell`].
    ///
    /// # Safety
    ///
    /// Data must be a valid PADDING_NEGOTIATE cell.
    pub unsafe fn from_cell(data: FixedCell) -> Self {
        debug_assert!(Self::check(data.data()));
        Self(data)
    }

    /// Creates new PADDING_NEGOTIATE cell.
    ///
    /// # Parameters
    ///
    /// - `cell` : Cached [`FixedCell`].
    /// - `cmd` : Padding negotiation command.
    ///
    /// # Example
    ///
    /// ```
    /// use onioncloud_lowlevel::cell::padding::{PaddingNegotiate, NegotiateCommand, NegotiateCommandV0};
    ///
    /// let cell = PaddingNegotiate::new(Default::default(), NegotiateCommand::V0(NegotiateCommandV0::Stop));
    /// ```
    pub fn new(cell: FixedCell, cmd: NegotiateCommand) -> Self {
        let mut ret = Self(cell);
        ret.set(cmd);
        ret
    }

    /// Get padding negotiation command.
    pub fn get(&self) -> NegotiateCommand {
        // SAFETY: Data validity has been checked.
        let data =
            unsafe { transmute::<&[u8; FIXED_CELL_SIZE], &PaddingNegotiatePadded>(self.0.data()) };
        match data.data {
            PaddingNegotiateData::V0(PaddingNegotiateV0 {
                cmd: PaddingNegotiateV0Cmd::Stop,
                ..
            }) => NegotiateCommand::V0(NegotiateCommandV0::Stop),
            PaddingNegotiateData::V0(PaddingNegotiateV0 {
                cmd: PaddingNegotiateV0Cmd::Start,
                lo_ms,
                hi_ms,
            }) => NegotiateCommand::V0(NegotiateCommandV0::Start {
                low: lo_ms.get(),
                high: hi_ms.get(),
            }),
        }
    }

    /// Set padding negotiation command.
    pub fn set(&mut self, cmd: NegotiateCommand) {
        let data = match cmd {
            NegotiateCommand::V0(cmd) => PaddingNegotiateData::V0(match cmd {
                NegotiateCommandV0::Stop => PaddingNegotiateV0 {
                    cmd: PaddingNegotiateV0Cmd::Stop,
                    lo_ms: 0.into(),
                    hi_ms: 0.into(),
                },
                NegotiateCommandV0::Start { low, high } => PaddingNegotiateV0 {
                    cmd: PaddingNegotiateV0Cmd::Start,
                    lo_ms: low.into(),
                    hi_ms: high.into(),
                },
            }),
        };
        let data = data.as_bytes();
        self.0.data_mut()[..data.len()].copy_from_slice(data);
        debug_assert!(Self::check(self.0.data()));
    }

    /// Unwraps into inner [`FixedCell`].
    pub fn into_inner(self) -> FixedCell {
        self.0
    }

    fn check(data: &[u8; FIXED_CELL_SIZE]) -> bool {
        let Ok(PaddingNegotiatePadded { .. }) = try_transmute_ref!(data) else {
            return false;
        };
        true
    }
}

/// Padding negotiate commands.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum NegotiateCommand {
    /// Version 0 commands.
    V0(NegotiateCommandV0),
}

/// Padding negotiate commands (version 0).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum NegotiateCommandV0 {
    /// Stop padding.
    Stop,

    /// Start padding.
    Start {
        /// Low end of padding interval, in ms.
        low: u16,
        /// High end of padding interval, in ms.
        high: u16,
    },
}

#[cfg(test)]
mod tests {
    use super::*;

    use proptest::prelude::*;

    use crate::cell::{CellHeader, cast};

    #[test]
    fn test_padding_negotiate_err_version() {
        let mut cell = FixedCell::default();
        cell.data_mut()[0] = 1;
        let mut cell = Some(Cell::from_fixed(
            CellHeader::new(0, PaddingNegotiate::ID),
            cell,
        ));
        cast::<PaddingNegotiate>(&mut cell).unwrap_err();
    }

    #[test]
    fn test_padding_negotiate_err_command() {
        let mut cell = FixedCell::default();
        cell.data_mut()[1] = 3;
        let mut cell = Some(Cell::from_fixed(
            CellHeader::new(0, PaddingNegotiate::ID),
            cell,
        ));
        cast::<PaddingNegotiate>(&mut cell).unwrap_err();
    }

    #[test]
    fn test_padding_negotiate_err_zeros() {
        let mut cell = Some(Cell::from_fixed(
            CellHeader::new(0, PaddingNegotiate::ID),
            FixedCell::default(),
        ));
        cast::<PaddingNegotiate>(&mut cell).unwrap_err();
    }

    proptest! {
        #[test]
        fn test_vpadding_size(length in any::<u16>()) {
            let cell = VPadding::with_size(length);
            assert_eq!(cell.data().len(), length as usize);
        }

        #[test]
        fn test_padding_negotiate(
            data in prop_oneof![
                Just(()).prop_map(|_| NegotiateCommand::V0(NegotiateCommandV0::Stop)),
                (any::<u16>(), any::<u16>()).prop_map(|(low, high)| NegotiateCommand::V0(NegotiateCommandV0::Start { low, high })),
            ],
        ) {
            let cell = PaddingNegotiate::new(Default::default(), data.clone());
            assert_eq!(cell.get(), data);
        }
    }
}
