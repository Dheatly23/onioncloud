//! `PADDING_NEGOTIATE` and `PADDING_NEGOTIATED` relay cell.
//!
//! See also: [spec](https://spec.torproject.org/padding-spec/circuit-level-padding.html#circuit-level-padding).

use std::mem::size_of;

use onioncloud_ll_cell::fixed::FixedCell;
use zerocopy::byteorder::big_endian::U32;
use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout, Unaligned, transmute_ref};

use crate::AutoReturnCell;
use crate::error::{CellCastError, CellFormatError, NonZeroStreamID};
use crate::traits::{DynRelayVersion, RelayVersion, TryFromRelay};
use crate::v0::V0;
use crate::v1::V1;

/// `PADDING_NEGOTIATE` relay ID.
pub const PADDING_NEGOTIATE_ID: u8 = 41;

/// `PADDING_NEGOTIATE` relay cell.
pub struct PaddingNegotiate<V = V0> {
    cell: FixedCell,
    version: V,
}

impl<V: DynRelayVersion> TryFromRelay<V> for PaddingNegotiate<V> {
    type Error = CellCastError;

    fn try_from_relay_versioned(
        version: V,
        cell: &mut Option<FixedCell>,
    ) -> Result<Option<Self>, Self::Error> {
        let Some(cell) = AutoReturnCell::new(cell) else {
            return Ok(None);
        };
        let c = cell.cell();
        if version.command(c) != PADDING_NEGOTIATE_ID {
            return Ok(None);
        }
        if version.stream_id(c) != 0 {
            return Err(NonZeroStreamID.into());
        }
        version
            .data_checked(c)
            .filter(|&s| check_padding_negotiate(s))
            .ok_or_else(CellFormatError::default)?;

        Ok(Some(Self {
            cell: cell.into_inner(),
            version,
        }))
    }
}

impl<V> From<PaddingNegotiate<V>> for FixedCell {
    #[inline]
    fn from(v: PaddingNegotiate<V>) -> FixedCell {
        v.into_inner()
    }
}

impl PaddingNegotiate<V0> {
    /// Create new [`PaddingNegotiate`] with relay version 0.
    #[inline]
    #[must_use]
    pub fn new_v0(cell: FixedCell, data: PaddingNegotiateData) -> Self {
        Self::new(cell, V0, data)
    }
}

impl PaddingNegotiate<V1> {
    /// Create new [`PaddingNegotiate`] with relay version 1.
    #[inline]
    #[must_use]
    pub fn new_v1(cell: FixedCell, data: PaddingNegotiateData) -> Self {
        Self::new(cell, V1, data)
    }
}

impl<V: DynRelayVersion> PaddingNegotiate<V> {
    /// Create new [`PaddingNegotiate`].
    ///
    /// # Panics
    ///
    /// Panics if data does not fit cell.
    #[must_use]
    pub fn new(mut cell: FixedCell, version: V, data: PaddingNegotiateData) -> Self {
        let t = version.data_padding_mut(&mut cell);
        let l: u16 = match data {
            PaddingNegotiateData::V0 {
                command,
                machine_ctr,
            } => {
                *<_>::mut_from_prefix(t).unwrap().0 =
                    PaddingNegotiateCellData::from_data(command, machine_ctr);
                size_of::<PaddingNegotiateCellData>() as _
            }
        };
        version.set_len(&mut cell, l);
        version.set_command(&mut cell, PADDING_NEGOTIATE_ID);
        version.set_stream_id(&mut cell, 0);
        debug_assert!(
            check_padding_negotiate(version.data(&cell)),
            "invalid cell format"
        );
        Self { cell, version }
    }

    /// Gets cell data.
    ///
    /// # Panics
    ///
    /// Panics if cell format is invalid.
    /// (Should not happen with typical relay version).
    #[inline]
    pub fn data_dyn(&self) -> Option<PaddingNegotiateData> {
        let d = self.version.data(&self.cell);
        if d.is_empty() {
            return None;
        }

        let t = CellWithPadding::<PaddingNegotiateCellData>::ref_from_bytes(d).unwrap();
        Some(t.data.to_data())
    }
}

impl<V: RelayVersion> PaddingNegotiate<V> {
    /// Gets cell data.
    ///
    /// # Panics
    ///
    /// Panics if cell format is invalid.
    /// (Should not happen with typical relay version).
    #[inline]
    pub fn data(&self) -> Option<PaddingNegotiateData> {
        if self.version.len(&self.cell) == 0 {
            return None;
        }

        let t: &CellWithPadding<PaddingNegotiateCellData> =
            transmute_ref!(self.version.data_padding(&self.cell));
        Some(t.data.to_data())
    }
}

impl<V> PaddingNegotiate<V> {
    /// Gets reference to relay version.
    #[inline]
    #[must_use]
    pub fn version(&self) -> &V {
        &self.version
    }

    /// Unwraps into inner cell.
    #[inline]
    #[must_use]
    pub fn into_inner(self) -> FixedCell {
        self.cell
    }
}

/// `PADDING_NEGOTIATED` relay ID.
pub const PADDING_NEGOTIATED_ID: u8 = 42;

/// `PADDING_NEGOTIATED` relay cell.
pub struct PaddingNegotiated<V = V0> {
    cell: FixedCell,
    version: V,
}

impl<V: DynRelayVersion> TryFromRelay<V> for PaddingNegotiated<V> {
    type Error = CellCastError;

    fn try_from_relay_versioned(
        version: V,
        cell: &mut Option<FixedCell>,
    ) -> Result<Option<Self>, Self::Error> {
        let Some(cell) = AutoReturnCell::new(cell) else {
            return Ok(None);
        };
        let c = cell.cell();
        if version.command(c) != PADDING_NEGOTIATED_ID {
            return Ok(None);
        }
        if version.stream_id(c) != 0 {
            return Err(NonZeroStreamID.into());
        }
        version
            .data_checked(c)
            .filter(|&s| check_padding_negotiate(s))
            .ok_or_else(CellFormatError::default)?;

        Ok(Some(Self {
            cell: cell.into_inner(),
            version,
        }))
    }
}

impl<V> From<PaddingNegotiated<V>> for FixedCell {
    #[inline]
    fn from(v: PaddingNegotiated<V>) -> FixedCell {
        v.into_inner()
    }
}

impl PaddingNegotiated<V0> {
    /// Create new [`PaddingNegotiated`] with relay version 0.
    #[inline]
    #[must_use]
    pub fn new_v0(cell: FixedCell, data: PaddingNegotiatedData) -> Self {
        Self::new(cell, V0, data)
    }
}

impl PaddingNegotiated<V1> {
    /// Create new [`PaddingNegotiated`] with relay version 1.
    #[inline]
    #[must_use]
    pub fn new_v1(cell: FixedCell, data: PaddingNegotiatedData) -> Self {
        Self::new(cell, V1, data)
    }
}

impl<V: DynRelayVersion> PaddingNegotiated<V> {
    /// Create new [`PaddingNegotiated`].
    ///
    /// # Panics
    ///
    /// Panics if data does not fit cell.
    #[must_use]
    pub fn new(mut cell: FixedCell, version: V, data: PaddingNegotiatedData) -> Self {
        let t = version.data_padding_mut(&mut cell);
        let l: u16 = match data {
            PaddingNegotiatedData::V0 {
                command,
                response,
                machine_ctr,
            } => {
                *<_>::mut_from_prefix(t).unwrap().0 =
                    PaddingNegotiatedCellData::from_data(command, response, machine_ctr);
                size_of::<PaddingNegotiatedCellData>() as _
            }
        };
        version.set_len(&mut cell, l);
        version.set_command(&mut cell, PADDING_NEGOTIATED_ID);
        version.set_stream_id(&mut cell, 0);
        debug_assert!(
            check_padding_negotiated(version.data(&cell)),
            "invalid cell format"
        );
        Self { cell, version }
    }

    /// Gets cell data.
    ///
    /// # Panics
    ///
    /// Panics if cell format is invalid.
    /// (Should not happen with typical relay version).
    #[inline]
    pub fn data_dyn(&self) -> Option<PaddingNegotiatedData> {
        let d = self.version.data(&self.cell);
        if d.is_empty() {
            return None;
        }

        let t = CellWithPadding::<PaddingNegotiatedCellData>::ref_from_bytes(d).unwrap();
        Some(t.data.to_data())
    }
}

impl<V: RelayVersion> PaddingNegotiated<V> {
    /// Gets cell data.
    ///
    /// # Panics
    ///
    /// Panics if cell format is invalid.
    /// (Should not happen with typical relay version).
    #[inline]
    pub fn data(&self) -> Option<PaddingNegotiatedData> {
        if self.version.len(&self.cell) == 0 {
            return None;
        }

        let t: &CellWithPadding<PaddingNegotiatedCellData> =
            transmute_ref!(self.version.data_padding(&self.cell));
        Some(t.data.to_data())
    }
}

impl<V> PaddingNegotiated<V> {
    /// Gets reference to relay version.
    #[inline]
    #[must_use]
    pub fn version(&self) -> &V {
        &self.version
    }

    /// Unwraps into inner cell.
    #[inline]
    #[must_use]
    pub fn into_inner(self) -> FixedCell {
        self.cell
    }
}

/// `PADDING_NEGOTIATE` cell content.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum PaddingNegotiateData {
    V0 {
        /// Command.
        command: V0Command,

        /// Machine ID.
        ///
        /// Correlates to [`PaddingNegotiated`] response.
        machine_ctr: u32,
    },
}

/// `PADDING_NEGOTIATED` cell content.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum PaddingNegotiatedData {
    V0 {
        /// Command.
        command: V0Command,

        /// Response value.
        response: V0Response,

        /// Machine ID.
        ///
        /// Correlates to [`PaddingNegotiate`] request.
        machine_ctr: u32,
    },
}

/// `PADDING_NEGOTIATE` and `PADDING_NEGOTIATED` command.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum V0Command {
    Start,
    Stop,
}

/// `PADDING_NEGOTIATED` response.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum V0Response {
    Ok,
    Err,
}

#[derive(FromBytes, IntoBytes, Immutable, KnownLayout, Unaligned)]
#[repr(C)]
struct PaddingNegotiateCellData {
    version: u8,
    command: u8,
    machine_ty: u8,
    unused: u8,
    machine_ctr: U32,
}

impl PaddingNegotiateCellData {
    #[inline]
    fn to_data(&self) -> PaddingNegotiateData {
        match self.version {
            0 => PaddingNegotiateData::V0 {
                command: match self.command {
                    1 => V0Command::Stop,
                    2 => V0Command::Start,
                    v => panic!("invalid PADDING_NEGOTIATE command {v}"),
                },
                machine_ctr: self.machine_ctr.get(),
            },
            v => panic!("invalid PADDING_NEGOTIATE version {v}"),
        }
    }

    #[expect(clippy::needless_pass_by_value)]
    #[inline]
    fn from_data(command: V0Command, machine_ctr: u32) -> Self {
        Self {
            version: 0,
            command: match command {
                V0Command::Stop => 1,
                V0Command::Start => 2,
            },
            machine_ty: 1,
            unused: 0,
            machine_ctr: machine_ctr.into(),
        }
    }
}

#[derive(FromBytes, IntoBytes, Immutable, KnownLayout, Unaligned)]
#[repr(C)]
struct PaddingNegotiatedCellData {
    version: u8,
    command: u8,
    response: u8,
    machine_ty: u8,
    machine_ctr: U32,
}

impl PaddingNegotiatedCellData {
    #[inline]
    fn to_data(&self) -> PaddingNegotiatedData {
        match self.version {
            0 => PaddingNegotiatedData::V0 {
                command: match self.command {
                    1 => V0Command::Stop,
                    2 => V0Command::Start,
                    v => panic!("invalid PADDING_NEGOTIATED command {v}"),
                },
                response: match self.response {
                    1 => V0Response::Ok,
                    2 => V0Response::Err,
                    v => panic!("invalid PADDING_NEGOTIATED response {v}"),
                },
                machine_ctr: self.machine_ctr.get(),
            },
            v => panic!("invalid PADDING_NEGOTIATED version {v}"),
        }
    }

    #[expect(clippy::needless_pass_by_value)]
    #[inline]
    fn from_data(command: V0Command, response: V0Response, machine_ctr: u32) -> Self {
        Self {
            version: 0,
            command: match command {
                V0Command::Stop => 1,
                V0Command::Start => 2,
            },
            response: match response {
                V0Response::Ok => 1,
                V0Response::Err => 2,
            },
            machine_ty: 1,
            machine_ctr: machine_ctr.into(),
        }
    }
}

#[derive(FromBytes, IntoBytes, Immutable, KnownLayout, Unaligned)]
#[repr(C)]
struct CellWithPadding<T> {
    data: T,
    rest: [u8],
}

fn check_padding_negotiate(s: &[u8]) -> bool {
    let Ok((v, _)) = PaddingNegotiateCellData::ref_from_prefix(s) else {
        return false;
    };
    match v.version {
        0 => matches!(v.command, 1 | 2) && v.machine_ty == 1,
        _ => false,
    }
}

fn check_padding_negotiated(s: &[u8]) -> bool {
    let Ok((v, _)) = PaddingNegotiatedCellData::ref_from_prefix(s) else {
        return false;
    };
    match v.version {
        0 => matches!(v.command, 1 | 2) && v.machine_ty == 1 && matches!(v.response, 1 | 2),
        _ => false,
    }
}
