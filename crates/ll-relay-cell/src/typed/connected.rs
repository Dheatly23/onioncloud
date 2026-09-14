//! `CONNECTED` relay cell.

use std::num::NonZeroU16;
use std::ops::{BitOr, BitOrAssign};
use std::str::{from_utf8, from_utf8_unchecked};

use onioncloud_ll_cell::fixed::FixedCell;
use zerocopy::byteorder::big_endian::U32;
use zerocopy::{transmute_mut, transmute_ref};

use crate::AutoReturnCell;
use crate::error::{CellCastError, CellFormatError, ZeroStreamID};
use crate::traits::{DynRelayVersion, TryFromRelay};
use crate::v0::V0;
use crate::v1::V1;

/// `CONNECTED` relay ID.
pub const ID: u8 = 4;

/// `CONNECTED` relay cell.
pub struct Connected<V = V0> {
    stream_id: NonZeroU16,
    len: u16,
    cell: FixedCell,
    version: V,
}

impl<V: DynRelayVersion> TryFromRelay<V> for Connected<V> {
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
        let stream_id = NonZeroU16::new(version.stream_id(c)).ok_or(ZeroStreamID)?;
        let len = version
            .data_checked(c)
            .and_then(check_data)
            .ok_or_else(CellFormatError::default)?;

        Ok(Some(Self {
            stream_id,
            len,
            cell: cell.into_inner(),
            version,
        }))
    }
}

impl<V> From<Connected<V>> for FixedCell {
    #[inline]
    fn from(v: Connected<V>) -> FixedCell {
        v.into_inner()
    }
}

impl Connected<V0> {
    /// Create new [`Connected`] with relay version 0.
    #[inline]
    #[must_use]
    pub fn new_v0(cell: FixedCell, stream_id: NonZeroU16, data: ConnectedData<'_>) -> Self {
        Self::new(cell, V0, stream_id, data)
    }
}

impl Connected<V1> {
    /// Create new [`Connected`] with relay version 1.
    #[inline]
    #[must_use]
    pub fn new_v1(cell: FixedCell, stream_id: NonZeroU16, data: ConnectedData<'_>) -> Self {
        Self::new(cell, V1, stream_id, data)
    }
}

impl<V: DynRelayVersion> Connected<V> {
    /// Create new [`Connected`].
    ///
    /// # Panics
    ///
    /// Panics if data does not fit cell.
    #[inline]
    #[must_use]
    pub fn new(
        cell: FixedCell,
        version: V,
        stream_id: NonZeroU16,
        data: ConnectedData<'_>,
    ) -> Self {
        Self::new_checked(cell, version, stream_id, data).expect("data does not fit cell")
    }

    /// Create new [`Connected`].
    ///
    /// Returns [`None`] if data does not fit cell.
    #[must_use]
    pub fn new_checked(
        mut cell: FixedCell,
        version: V,
        stream_id: NonZeroU16,
        data: ConnectedData<'_>,
    ) -> Option<Self> {
        let Some((a, [n, r @ ..])) = version
            .data_padding_mut(&mut cell)
            .split_at_mut_checked(data.addr.len())
        else {
            return None;
        };
        let b: &mut U32 = transmute_mut!(r.first_chunk_mut::<4>()?);
        let l = u16::try_from(a.len() + 5).ok()?;
        a.copy_from_slice(data.addr.as_bytes());
        *n = 0;
        b.set(data.flags.into());

        version.set_len(&mut cell, l);
        version.set_command(&mut cell, ID);
        version.set_stream_id(&mut cell, stream_id.into());
        debug_assert_eq!(
            check_data(version.data(&cell)).map(usize::from),
            Some(data.addr.len()),
            "invalid cell format"
        );
        Some(Self {
            stream_id,
            len: data.addr.len() as _,
            cell,
            version,
        })
    }

    /// Gets stream ID.
    #[inline]
    #[must_use]
    pub fn stream_id(&self) -> NonZeroU16 {
        self.stream_id
    }

    /// Sets stream ID.
    #[inline]
    pub fn set_stream_id(&mut self, stream_id: NonZeroU16) {
        self.stream_id = stream_id;
        self.version.set_stream_id(&mut self.cell, stream_id.into());
    }

    /// Gets cell data.
    ///
    /// # Panics
    ///
    /// Panics if cell format is invalid.
    /// (Should not happen with typical relay version).
    #[inline]
    pub fn data(&self) -> ConnectedData<'_> {
        let (addr, r) = self.version.data(&self.cell).split_at(self.len as _);
        let flags = Flags(if r.len() <= 1 {
            0
        } else {
            let t: &U32 = transmute_ref!(<&[u8; 4]>::try_from(&r[1..5]).unwrap());
            t.get()
        });

        ConnectedData {
            // SAFETY: Address has been checked to be UTF-8
            addr: unsafe { from_utf8_unchecked(addr) },
            flags,
        }
    }
}

impl<V> Connected<V> {
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

/// `CONNECTED` cell content.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct ConnectedData<'a> {
    /// Address and port in format of `ADDR:PORT`.
    pub addr: &'a str,
    /// Flags.
    pub flags: Flags,
}

/// Flags.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct Flags(u32);

impl From<Flags> for u32 {
    fn from(v: Flags) -> u32 {
        v.into_inner()
    }
}

impl BitOr for Flags {
    type Output = Self;

    fn bitor(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }
}

impl BitOrAssign for Flags {
    fn bitor_assign(&mut self, other: Self) {
        self.0 |= other.0;
    }
}

impl Flags {
    pub const IPV6_OK: Self = Self(1 << 0);
    pub const IPV4_NOT_OK: Self = Self(1 << 1);
    pub const IPV6_PREFER: Self = Self(1 << 2);

    /// Unwraps into inner value.
    #[inline]
    #[must_use]
    pub const fn into_inner(self) -> u32 {
        self.0
    }
}

fn check_data(s: &[u8]) -> Option<u16> {
    let l = u16::try_from(s.iter().position(|c| *c == 0)?).ok()?;

    let a = &s[..l as usize];
    if a.iter().any(|c| *c > 127) {
        return None;
    }
    let t = from_utf8(a);
    debug_assert!(t.is_ok(), "non-ascii string: {}", t.unwrap_err());
    // TODO: Check address format.

    let s = &s[l as usize + 1..];
    if matches!(s.len(), 1..4) {
        return None;
    }
    Some(l)
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::hint::black_box;

    #[test]
    fn test_connected_v0() {
        let cell = black_box(Connected::new_v0(
            Default::default(),
            NonZeroU16::new(10).unwrap(),
            ConnectedData {
                addr: "example.com:9973",
                flags: Flags(0),
            },
        ));
        assert_eq!(
            cell.data(),
            ConnectedData {
                addr: "example.com:9973",
                flags: Flags(0),
            }
        );
    }

    #[test]
    fn test_connected_v1() {
        let cell = black_box(Connected::new_v1(
            Default::default(),
            NonZeroU16::new(10).unwrap(),
            ConnectedData {
                addr: "example.com:9973",
                flags: Flags(0),
            },
        ));
        assert_eq!(
            cell.data(),
            ConnectedData {
                addr: "example.com:9973",
                flags: Flags(0),
            }
        );
    }

    #[test]
    #[should_panic(expected = "data does not fit cell")]
    fn test_connected_too_long() {
        let cell = Connected::new_v0(
            Default::default(),
            NonZeroU16::new(10).unwrap(),
            ConnectedData {
                addr: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.com:1",
                flags: Flags(1),
            },
        );
        println!("Cell: {}", FixedCell::from(cell));
    }
}
