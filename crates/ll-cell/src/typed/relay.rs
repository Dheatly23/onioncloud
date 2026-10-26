//! `RELAY` and `RELAY_EARLY` cell type.

use std::num::NonZeroU32;

use crate::cell::{AutoReturnFixed, Cell, CellHeader, TryFromCell};
use crate::error::{CellCastError, ZeroCircID};
use crate::fixed::FixedCell;

/// `RELAY` cell.
///
/// See also: [spec](https://spec.torproject.org/tor-spec/routing-relay-cells.html#routing-relay-cells).
#[derive(Debug)]
pub struct Relay {
    /// Circuit ID.
    pub circuit: NonZeroU32,
    cell: FixedCell,
}

impl TryFromCell for Relay {
    type Error = CellCastError;

    fn try_from_cell(cell: &mut Option<Cell>) -> Result<Option<Self>, Self::Error> {
        if let Some(cell) = AutoReturnFixed::new(cell)?
            && cell.header().command == Self::ID
        {
            let circuit = NonZeroU32::new(cell.header().circuit).ok_or(ZeroCircID)?;
            Ok(Some(Self {
                circuit,
                cell: cell.into_inner().1,
            }))
        } else {
            Ok(None)
        }
    }
}

impl From<Relay> for Cell {
    fn from(cell: Relay) -> Self {
        Self::from_fixed(
            CellHeader {
                command: Relay::ID,
                circuit: cell.circuit.get(),
            },
            cell.into_inner(),
        )
    }
}

impl From<Relay> for FixedCell {
    #[inline]
    fn from(v: Relay) -> FixedCell {
        v.into_inner()
    }
}

impl AsRef<FixedCell> for Relay {
    #[inline]
    fn as_ref(&self) -> &FixedCell {
        self.inner()
    }
}

impl AsMut<FixedCell> for Relay {
    #[inline]
    fn as_mut(&mut self) -> &mut FixedCell {
        self.inner_mut()
    }
}

impl Relay {
    /// Cell ID of `RELAY`.
    pub const ID: u8 = 3;

    /// Creates new [`Relay`].
    #[must_use]
    pub fn new(circuit: NonZeroU32, cell: FixedCell) -> Self {
        Self { circuit, cell }
    }

    /// Gets reference to inner.
    #[inline]
    #[must_use]
    pub fn inner(&self) -> &FixedCell {
        &self.cell
    }

    /// Gets mutable reference to inner.
    #[inline]
    #[must_use]
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

/// `RELAY_EARLY` cell.
///
/// See also: [spec](https://spec.torproject.org/tor-spec/routing-relay-cells.html#routing-relay-cells).
#[derive(Debug)]
pub struct RelayEarly {
    /// Circuit ID.
    pub circuit: NonZeroU32,
    cell: FixedCell,
}

impl TryFromCell for RelayEarly {
    type Error = CellCastError;

    fn try_from_cell(cell: &mut Option<Cell>) -> Result<Option<Self>, Self::Error> {
        if let Some(cell) = AutoReturnFixed::new(cell)?
            && cell.header().command == Self::ID
        {
            let circuit = NonZeroU32::new(cell.header().circuit).ok_or(ZeroCircID)?;
            Ok(Some(Self {
                circuit,
                cell: cell.into_inner().1,
            }))
        } else {
            Ok(None)
        }
    }
}

impl From<RelayEarly> for Cell {
    fn from(cell: RelayEarly) -> Self {
        Self::from_fixed(
            CellHeader {
                command: RelayEarly::ID,
                circuit: cell.circuit.get(),
            },
            cell.into_inner(),
        )
    }
}

impl From<RelayEarly> for FixedCell {
    #[inline]
    fn from(v: RelayEarly) -> FixedCell {
        v.into_inner()
    }
}

impl AsRef<FixedCell> for RelayEarly {
    #[inline]
    fn as_ref(&self) -> &FixedCell {
        self.inner()
    }
}

impl AsMut<FixedCell> for RelayEarly {
    #[inline]
    fn as_mut(&mut self) -> &mut FixedCell {
        self.inner_mut()
    }
}

impl RelayEarly {
    /// Cell ID of `RELAY_EARLY`.
    pub const ID: u8 = 9;

    /// Creates new [`RelayEarly`].
    #[must_use]
    pub fn new(circuit: NonZeroU32, cell: FixedCell) -> Self {
        Self { circuit, cell }
    }

    /// Gets reference to inner.
    #[inline]
    #[must_use]
    pub fn inner(&self) -> &FixedCell {
        &self.cell
    }

    /// Gets mutable reference to inner.
    #[inline]
    #[must_use]
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

impl From<Relay> for RelayEarly {
    fn from(v: Relay) -> Self {
        Self {
            circuit: v.circuit,
            cell: v.cell,
        }
    }
}

impl From<RelayEarly> for Relay {
    fn from(v: RelayEarly) -> Self {
        Self {
            circuit: v.circuit,
            cell: v.cell,
        }
    }
}
