//! `DESTROY` cell type.

use std::fmt::{Debug, Formatter, Result as FmtResult};
use std::num::NonZeroU32;

use zerocopy::{
    FromBytes, Immutable, IntoBytes, KnownLayout, Unaligned, transmute_mut, transmute_ref,
};

use crate::cell::{AutoReturnFixed, Cell, CellHeader, TryFromCell};
use crate::error::{CellCastError, ZeroCircID};
use crate::fixed::{FIXED_CELL_SIZE, FixedCell};

/// `DESTROY` cell data.
#[derive(FromBytes, IntoBytes, Immutable, KnownLayout, Unaligned)]
#[repr(C)]
struct DestroyData {
    reason: u8,
    rest: [u8; const { FIXED_CELL_SIZE - 1 }],
}

/// `DESTROY` cell.
///
/// See also: [spec](https://spec.torproject.org/tor-spec/tearing-down-circuits.html#tearing-down-circuits).
pub struct Destroy {
    /// Circuit ID.
    pub circuit: NonZeroU32,
    cell: FixedCell,
}

impl Debug for Destroy {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        let reason = self.reason();
        let mut f = f.debug_struct("Destroy");
        if let Some(reason) = DestroyReason::from_reason(reason) {
            f.field("reason", &reason);
        } else {
            f.field("reason", &reason);
        }
        f.finish()
    }
}

impl TryFromCell for Destroy {
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

impl From<Destroy> for Cell {
    fn from(cell: Destroy) -> Self {
        Self::from_fixed(
            CellHeader {
                command: Destroy::ID,
                circuit: cell.circuit.get(),
            },
            cell.into_inner(),
        )
    }
}

impl From<Destroy> for FixedCell {
    #[inline]
    fn from(v: Destroy) -> FixedCell {
        v.into_inner()
    }
}

impl AsRef<FixedCell> for Destroy {
    #[inline]
    fn as_ref(&self) -> &FixedCell {
        self.inner()
    }
}

impl Destroy {
    /// Cell ID of `DESTROY`.
    pub const ID: u8 = 4;

    /// Creates new [`Destroy`].
    pub fn new(circuit: NonZeroU32, mut cell: FixedCell, reason: u8) -> Self {
        let p: &mut DestroyData = transmute_mut!(cell.data_mut());
        p.reason = reason;
        p.rest.fill(0);

        Self { circuit, cell }
    }

    /// Gets reference to inner.
    #[inline]
    #[must_use]
    pub fn inner(&self) -> &FixedCell {
        &self.cell
    }

    /// Unwraps into inner.
    #[inline]
    #[must_use]
    pub fn into_inner(self) -> FixedCell {
        self.cell
    }

    fn get_ref(&self) -> &DestroyData {
        transmute_ref!(self.cell.data())
    }

    fn get_mut(&mut self) -> &mut DestroyData {
        transmute_mut!(self.cell.data_mut())
    }

    /// Gets destroy reason.
    #[inline]
    #[must_use]
    pub fn reason(&self) -> u8 {
        self.get_ref().reason
    }

    /// Sets destroy reason.
    #[inline]
    pub fn set_reason(&mut self, reason: u8) {
        self.get_mut().reason = reason;
    }
}

/// Destroy reasons.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
#[non_exhaustive]
pub enum DestroyReason {
    /// No reason given.
    #[default]
    None,
    /// Tor protocol violation.
    Protocol,
    /// Internal error.
    Internal,
    /// A client sent a TRUNCATE command.
    Requested,
    /// Not currently operating; trying to save bandwidth.
    Hibernating,
    /// Out of memory, sockets, or circuit IDs.
    Resourcelimit,
    /// Unable to reach relay.
    Connectfailed,
    /// Connected to relay, but its OR identity was not as expected.
    OrIdentity,
    /// The OR connection that was carrying this circuit died.
    ChannelClosed,
    /// The circuit has expired for being dirty or old.
    Finished,
    /// Circuit construction took too long.
    Timeout,
    /// The circuit was destroyed w/o client TRUNCATE.
    Destroyed,
    /// Request for unknown hidden service.
    Nosuchservice,
}

impl From<DestroyReason> for u8 {
    #[inline]
    fn from(v: DestroyReason) -> u8 {
        v.into_u8()
    }
}

impl TryFrom<u8> for DestroyReason {
    type Error = u8;

    #[inline]
    fn try_from(v: u8) -> Result<Self, Self::Error> {
        Self::from_reason(v).ok_or(v)
    }
}

impl DestroyReason {
    #[inline]
    pub const fn from_reason(reason: u8) -> Option<Self> {
        match reason {
            0 => Some(Self::None),
            1 => Some(Self::Protocol),
            2 => Some(Self::Internal),
            3 => Some(Self::Requested),
            4 => Some(Self::Hibernating),
            5 => Some(Self::Resourcelimit),
            6 => Some(Self::Connectfailed),
            7 => Some(Self::OrIdentity),
            8 => Some(Self::ChannelClosed),
            9 => Some(Self::Finished),
            10 => Some(Self::Timeout),
            11 => Some(Self::Destroyed),
            12 => Some(Self::Nosuchservice),
            _ => None,
        }
    }

    #[inline]
    pub const fn into_u8(self) -> u8 {
        match self {
            Self::None => 0,
            Self::Protocol => 1,
            Self::Internal => 2,
            Self::Requested => 3,
            Self::Hibernating => 4,
            Self::Resourcelimit => 5,
            Self::Connectfailed => 6,
            Self::OrIdentity => 7,
            Self::ChannelClosed => 8,
            Self::Finished => 9,
            Self::Timeout => 10,
            Self::Destroyed => 11,
            Self::Nosuchservice => 12,
        }
    }
}
