use std::num::NonZeroU32;
use std::slice::from_ref;

use zerocopy::{Immutable, IntoBytes, KnownLayout, TryFromBytes, Unaligned};

use super::{Cell, CellHeader, CellLike, CellRef, FixedCell, TryFromCell, to_fixed};
use crate::errors;

/// Represents a DESTROY cell.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Destroy {
    pub circuit: NonZeroU32,
    cell: FixedCell,
}

impl From<Destroy> for Cell {
    fn from(v: Destroy) -> Cell {
        Cell::from_fixed(
            CellHeader::new(v.circuit.get(), Destroy::ID),
            v.into_inner(),
        )
    }
}

impl From<Destroy> for FixedCell {
    fn from(v: Destroy) -> FixedCell {
        v.into_inner()
    }
}

impl TryFromCell for Destroy {
    fn try_from_cell(cell: &mut Option<Cell>) -> Result<Option<Self>, errors::CellFormatError> {
        let Some(Cell {
            circuit: cid,
            command: Self::ID,
            ..
        }) = *cell
        else {
            return Ok(None);
        };
        let cid = NonZeroU32::new(cid).ok_or(errors::CellFormatError)?;
        to_fixed(cell).map(|v| v.map(|v| unsafe { Self::from_cell(cid, v) }))
    }
}

impl CellLike for Destroy {
    fn circuit(&self) -> u32 {
        self.circuit.get()
    }

    fn command(&self) -> u8 {
        Self::ID
    }

    fn cell(&self) -> CellRef<'_> {
        CellRef::Fixed(&self.cell)
    }
}

impl Destroy {
    /// DESTROY command ID.
    pub const ID: u8 = 10;

    /// Creates new DESTROY cell from existing [`FixedCell`].
    ///
    /// # Safety
    ///
    /// Data must be a valid DESTROY cell.
    pub unsafe fn from_cell(circuit: NonZeroU32, data: FixedCell) -> Self {
        Self {
            circuit,
            cell: data,
        }
    }

    /// Creates new DESTROY cell.
    ///
    /// # Parameters
    ///
    /// - `cell` : Cached [`FixedCell`].
    /// - `circuit` : Circuit ID.
    /// - `reason` : Destroy reason.
    pub fn new(mut cell: FixedCell, circuit: NonZeroU32, reason: DestroyReason) -> Self {
        cell.data_mut()[0] = reason as u8;

        // SAFETY: Data is valid
        unsafe { Self::from_cell(circuit, cell) }
    }

    /// Gets destroy reason.
    pub fn reason(&self) -> Result<DestroyReason, u8> {
        let b = &self.cell.data()[0];
        DestroyReason::try_read_from_bytes(from_ref(b)).map_err(|_| *b)
    }

    /// Unwraps into inner [`FixedCell`].
    pub fn into_inner(self) -> FixedCell {
        self.cell
    }
}

/// Destroy reason code.
///
/// See [spec](https://spec.torproject.org/tor-spec/tearing-down-circuits.html) for details.
#[derive(
    TryFromBytes,
    IntoBytes,
    KnownLayout,
    Immutable,
    Unaligned,
    Debug,
    Default,
    Clone,
    Copy,
    PartialEq,
    Eq,
    Hash,
)]
#[repr(u8)]
#[non_exhaustive]
pub enum DestroyReason {
    /// No reason given.
    #[default]
    None = 0,

    /// Tor protocol violation.
    Protocol = 1,

    /// Internal error.
    Internal = 2,

    /// TRUNCATE requested.
    Requested = 3,

    /// Client hibernating.
    Hibernating = 4,

    /// Resource limit reached.
    ResourceLimit = 5,

    /// Failed to connect to relay.
    ConnectFailed = 6,

    /// Connected to relay, but it's ID does not match.
    OrIdentity = 7,

    /// Channel to peer is closed.
    ChannelClosed = 8,

    /// Circuit expired.
    Finished = 9,

    /// Circuit construction timed out.
    Timeout = 10,

    /// Circuit destroyed by peer/client.
    ///
    /// Should be used instead of propagating reason code to prevent information leak.
    Destroyed = 11,

    /// Hidden service not found.
    NoSuchService = 12,
}

impl From<DestroyReason> for u8 {
    fn from(v: DestroyReason) -> u8 {
        v as _
    }
}
