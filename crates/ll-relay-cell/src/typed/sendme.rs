//! `SENDME` relay cell.

use std::num::NonZeroU16;

use onioncloud_ll_cell::fixed::FixedCell;
use zerocopy::byteorder::big_endian::U16;
use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout, Unaligned, transmute_ref};

use crate::AutoReturnCell;
use crate::error::{CellCastError, CellFormatError};
use crate::traits::{DynRelayVersion, RelayVersion, TryFromRelay};
use crate::v0::V0;
use crate::v1::V1;

/// `SENDME` relay ID.
pub const ID: u8 = 5;

/// `SENDME` relay cell.
pub struct Sendme<V = V0> {
    cell: FixedCell,
    version: V,
}

impl<V: DynRelayVersion> TryFromRelay<V> for Sendme<V> {
    type Error = CellCastError;

    fn try_from_relay_versioned(
        version: V,
        cell: &mut Option<FixedCell>,
    ) -> Result<Option<Self>, Self::Error> {
        let Some(cell) = AutoReturnCell::new(cell) else {
            return Ok(None);
        };
        let c = cell.cell();
        if version.command(c) != ID {
            return Ok(None);
        }
        let stream_id = NonZeroU16::new(version.stream_id(c));
        let data = version
            .data_checked(c)
            .ok_or_else(CellFormatError::default)?;
        if stream_id.is_some() || !check_data(data) {
            return Err(CellFormatError::default().into());
        }

        Ok(Some(Self {
            cell: cell.into_inner(),
            version,
        }))
    }
}

impl<V> From<Sendme<V>> for FixedCell {
    #[inline]
    fn from(v: Sendme<V>) -> FixedCell {
        v.into_inner()
    }
}

impl Sendme<V0> {
    /// Create new circuit [`Sendme`] with relay version 0.
    #[inline]
    #[must_use]
    pub fn new_v0(cell: FixedCell, data: SendmeData) -> Self {
        Self::new(cell, V0, data)
    }

    /// Create new stream [`Sendme`] with relay version 0.
    #[inline]
    #[must_use]
    pub fn new_stream_v0(cell: FixedCell, stream_id: NonZeroU16) -> Self {
        Self::new_stream(cell, V0, stream_id)
    }
}

impl Sendme<V1> {
    /// Create new circuit [`Sendme`] with relay version 1.
    #[inline]
    #[must_use]
    pub fn new_v1(cell: FixedCell, data: SendmeData) -> Self {
        Self::new(cell, V1, data)
    }

    /// Create new stream [`Sendme`] with relay version 1.
    #[inline]
    #[must_use]
    pub fn new_stream_v1(cell: FixedCell, stream_id: NonZeroU16) -> Self {
        Self::new_stream(cell, V1, stream_id)
    }
}

impl<V: DynRelayVersion> Sendme<V> {
    /// Create new circuit [`Sendme`].
    ///
    /// # Panics
    ///
    /// Panics if data does not fit cell.
    #[expect(clippy::needless_pass_by_value)]
    #[must_use]
    pub fn new(mut cell: FixedCell, version: V, data: SendmeData) -> Self {
        let t = SendmeCellData::mut_from_bytes(version.data_padding_mut(&mut cell)).unwrap();
        let l: u16 = match data {
            SendmeData::V0 => {
                t.version = 0;
                t.len.set(0);
                3
            }
            SendmeData::V1 { digest } => {
                t.version = 1;
                t.len.set(20);
                *<&mut [u8; 20]>::try_from(&mut t.data[..20]).unwrap() = digest;
                3 + 20
            }
        };
        version.set_len(&mut cell, l);
        version.set_command(&mut cell, ID);
        version.set_stream_id(&mut cell, 0);
        debug_assert!(check_data(version.data(&cell)), "invalid cell format");
        Self { cell, version }
    }

    /// Create new stream [`Sendme`].
    #[must_use]
    pub fn new_stream(mut cell: FixedCell, version: V, stream_id: NonZeroU16) -> Self {
        version.set_len(&mut cell, 0);
        version.set_command(&mut cell, ID);
        version.set_stream_id(&mut cell, stream_id.into());
        debug_assert!(version.data(&cell).is_empty(), "invalid cell format");
        Self { cell, version }
    }

    /// Gets stream ID.
    #[inline]
    #[must_use]
    pub fn stream_id(&self) -> Option<NonZeroU16> {
        NonZeroU16::new(self.version.stream_id(&self.cell))
    }

    /// Sets stream ID.
    #[inline]
    pub fn set_stream_id(&mut self, stream_id: Option<NonZeroU16>) {
        self.version
            .set_stream_id(&mut self.cell, stream_id.map_or_default(u16::from));
    }

    /// Gets cell data.
    ///
    /// # Panics
    ///
    /// Panics if cell format is invalid.
    /// (Should not happen with typical relay version).
    #[inline]
    pub fn data_dyn(&self) -> Option<SendmeData> {
        let d = self.version.data(&self.cell);
        if d.is_empty() {
            return None;
        }

        let t = SendmeCellData::ref_from_bytes(d).unwrap();
        Some(match t.version {
            0 => SendmeData::V0,
            1 => SendmeData::V1 {
                digest: t.data[..20].try_into().unwrap(),
            },
            v => panic!("invalid SENDME version {v}"),
        })
    }
}

impl<V: RelayVersion> Sendme<V> {
    /// Gets cell data.
    ///
    /// # Panics
    ///
    /// Panics if cell format is invalid.
    /// (Should not happen with typical relay version).
    #[inline]
    pub fn data(&self) -> Option<SendmeData> {
        if self.version.len(&self.cell) == 0 {
            return None;
        }

        let t: &SendmeCellData = transmute_ref!(self.version.data_padding(&self.cell));
        Some(match t.version {
            0 => SendmeData::V0,
            1 => SendmeData::V1 {
                digest: t.data[..20].try_into().unwrap(),
            },
            v => panic!("invalid SENDME version {v}"),
        })
    }
}

impl<V> Sendme<V> {
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

/// `SENDME` cell content.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum SendmeData {
    #[default]
    V0,
    V1 {
        digest: [u8; 20],
    },
}

#[derive(FromBytes, IntoBytes, Immutable, KnownLayout, Unaligned)]
#[repr(C)]
struct SendmeCellData {
    version: u8,
    len: U16,
    data: [u8],
}

fn check_data(s: &[u8]) -> bool {
    let Ok(v) = SendmeCellData::ref_from_bytes(s) else {
        return false;
    };
    let l = v.len.get() as usize;
    if v.data.len() < l {
        return false;
    }
    match v.version {
        0 => true,
        1 => l >= 20,
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::hint::black_box;

    #[test]
    fn test_sendme_v0() {
        let cell = black_box(Sendme::new_v0(Default::default(), SendmeData::V0));
        assert_eq!(cell.data(), Some(SendmeData::V0));
        assert_eq!(cell.stream_id(), None);
        let cell = black_box(Sendme::new_v0(
            Default::default(),
            SendmeData::V1 { digest: [1; 20] },
        ));
        assert_eq!(cell.data(), Some(SendmeData::V1 { digest: [1; 20] }));
        assert_eq!(cell.stream_id(), None);
        let cell = black_box(Sendme::new_stream_v0(
            Default::default(),
            NonZeroU16::new(10).unwrap(),
        ));
        assert_eq!(cell.data(), None);
        assert_eq!(cell.stream_id(), NonZeroU16::new(10));
    }

    #[test]
    fn test_sendme_v1() {
        let cell = black_box(Sendme::new_v1(Default::default(), SendmeData::V0));
        assert_eq!(cell.data(), Some(SendmeData::V0));
        assert_eq!(cell.stream_id(), None);
        let cell = black_box(Sendme::new_v1(
            Default::default(),
            SendmeData::V1 { digest: [1; 20] },
        ));
        assert_eq!(cell.data(), Some(SendmeData::V1 { digest: [1; 20] }));
        assert_eq!(cell.stream_id(), None);
        let cell = black_box(Sendme::new_stream_v1(
            Default::default(),
            NonZeroU16::new(10).unwrap(),
        ));
        assert_eq!(cell.data(), None);
        assert_eq!(cell.stream_id(), NonZeroU16::new(10));
    }
}
