//! `CONNECTED` relay cell.

use std::net::IpAddr;
use std::num::NonZeroU16;
use std::ops::{BitOr, BitOrAssign};
use std::ptr::from_ref;
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

        let mut l = u16::try_from(a.len()).ok()?.checked_add(1)?;
        if let Flags(f @ 1..) = data.flags {
            let b: &mut U32 = transmute_mut!(r.first_chunk_mut::<4>()?);
            l = l.checked_add(4)?;
            b.set(f);
        }
        a.copy_from_slice(data.addr.as_bytes());
        *n = 0;

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
    ///
    /// NOTE: Address format is not validated when creating cell. Manually check using [`validate_addr`].
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

/// Valid address and port.
#[derive(Debug, PartialEq, Eq)]
#[non_exhaustive]
pub struct ValidAddrPort<'a> {
    /// Address.
    pub addr: ValidAddr<'a>,
    /// Port.
    pub port: u16,
}

/// Valid address.
#[derive(Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum ValidAddr<'a> {
    /// Parsed IP address.
    Ip(IpAddr),
    /// DNS hostname.
    Host(&'a str),
}

/// Checks if address is a valid address.
///
/// ```
/// # use std::assert_matches;
/// # use onioncloud_ll_relay_cell::typed::connected::{validate_addr, ValidAddr};
///
/// // Valid address.
/// let addr = validate_addr("example.com:9001").unwrap();
/// assert_eq!(addr.addr, ValidAddr::Host("example.com"));
/// assert_eq!(addr.port, 9001);
///
/// // Invalid address.
/// assert_matches!(validate_addr("abc..com:123"), None);
/// ```
#[inline]
#[must_use]
pub fn validate_addr(addr: &str) -> Option<ValidAddrPort<'_>> {
    let s = addr.as_bytes();
    let a = if let Some(s) = s.last_chunk::<8>() {
        *s
    } else {
        let mut v = [0u8; 8];
        v[..s.len()].copy_from_slice(s);
        v
    };

    // Use USIMD
    let v = u64::from_le_bytes(a);
    let mut t = v ^ const { !bcast(b':') };
    t &= t >> 4;
    t &= t >> 2;
    t &= t >> 1;
    t &= 0x0101_0101_0101_0101;
    let j @ 1..8 = t.leading_zeros() as u8 / 8 else {
        return None;
    };
    let i = (7 - j) as usize + s.len().saturating_sub(8);

    if v & 0x8080_8080_8080_8080 != 0 {
        return None;
    }
    let sh = 8 - s.len().min(8) as u8;
    let s @ 3..8 = 8 - j + sh else { return None };
    let m = u64::MAX >> (s * 8);
    t = v.swap_bytes() >> (sh * 8);
    t = const { bcast(128 - b'0') } + t;
    if !t & m & 0x8080_8080_8080_8080 != 0 {
        return None;
    }
    t &= m & 0x7f7f_7f7f_7f7f_7f7f;
    if let Some(s) = 6u8.checked_sub(s)
        && t >> (s * 8) < 0x0100
    {
        return None;
    }
    let u = (t | 0x8080_8080_8080_8080) - const { bcast(10) };
    if u & 0x8080_8080_8080_8080 != 0 {
        return None;
    }
    t += (t * 10) >> 8;
    t &= 0x00ff_00ff_00ff;
    let mut port = t as u32 & 0xffff;
    port = port.checked_add(((t >> 16) as u32 & 0xffff) * 100)?;
    port = port.checked_add((t >> 32) as u32 * 10_000)?;
    let port = u16::try_from(port).ok()?;

    let a = &addr[..i];
    let addr = if let Ok(v) = a.parse::<IpAddr>() {
        ValidAddr::Ip(v)
    } else if a.is_empty() || a.ends_with(".") || a.starts_with(".") || !check_addr(a.as_bytes()) {
        return None;
    } else {
        ValidAddr::Host(a)
    };

    Some(ValidAddrPort { addr, port })
}

const fn bcast(v: u8) -> u64 {
    let mut c = v as u64;
    c |= c << 8;
    c |= c << 16;
    c |= c << 32;
    c
}

#[expect(clippy::inline_always)]
#[inline(always)]
fn check_addr(s: &[u8]) -> bool {
    let mut ends_dot = false;
    let mut has_dot = false;

    let mut i = 0;
    while let Some(p) = s.get(i)
        && !from_ref(p).cast::<u64>().is_aligned()
    {
        let v = *p;
        i += 1;

        let is_dot = v == b'.';
        if ends_dot && is_dot {
            return false;
        }
        has_dot = has_dot || is_dot;
        ends_dot = is_dot;

        if !matches!(v, b'.' | b'0'..=b'9' | b'a'..=b'z' | b'A'..=b'Z') {
            return false;
        }
    }

    while let Some(p) = s.get(i..i + 8) {
        let p = from_ref(p).cast::<u64>();
        debug_assert!(p.is_aligned(), "pointer {p:?} is not aligned");
        let v = unsafe { *p };
        i += 8;

        if v & 0x8080_8080_8080_8080 != 0 {
            return false;
        }

        let mut t = v ^ const { !bcast(b'.') };
        t &= t >> 4;
        t &= t >> 2;
        t &= t >> 1;
        t &= 0x0101_0101_0101_0101;
        let is_dot = t;

        has_dot = has_dot || is_dot != 0;
        if is_dot & ((is_dot << 8) | u64::from(ends_dot)) != 0 {
            return false;
        }
        ends_dot = (is_dot >> 56) as u8 != 0;

        t = const { bcast(128 - b'0') } + v;
        t &= const { bcast(128 + b'9') } - v;
        t >>= 7;
        t &= 0x0101_0101_0101_0101;
        let is_num = t;

        t = const { bcast(128 - b'a') } + v;
        t &= const { bcast(128 + b'z') } - v;
        t >>= 7;
        t &= 0x0101_0101_0101_0101;
        let is_lower = t;

        t = const { bcast(128 - b'A') } + v;
        t &= const { bcast(128 + b'Z') } - v;
        t >>= 7;
        t &= 0x0101_0101_0101_0101;
        let is_upper = t;

        let is_invalid = !(is_dot | is_num | is_lower | is_upper) & 0x0101_0101_0101_0101;
        if is_invalid != 0 {
            return false;
        }
    }

    while let Some(&v) = s.get(i) {
        i += 1;

        let is_dot = v == b'.';
        if ends_dot && is_dot {
            return false;
        }
        has_dot = has_dot || is_dot;
        ends_dot = is_dot;

        if !matches!(v, b'.' | b'0'..=b'9' | b'a'..=b'z' | b'A'..=b'Z') {
            return false;
        }
    }

    has_dot
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
