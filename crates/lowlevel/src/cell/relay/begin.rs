use std::fmt::{Debug, Formatter, Result as FmtResult};
use std::hash::{Hash, Hasher};
use std::num::{NonZeroU16, NonZeroU32};
use std::ops::BitOr;
use std::ptr::from_ref;
use std::slice::from_raw_parts;
use std::str::{from_utf8, from_utf8_unchecked};

use memchr::memchr;
use zerocopy::byteorder::big_endian::U32;
use zerocopy::{FromBytes, transmute_mut};

use super::{
    IntoRelay, Relay, RelayV001, RelayVersion, RelayWrapper, TryFromRelay, set_cmd_stream, v0, v1,
};
use crate::cache::{Cachable, Cached, CellCache};
use crate::cell::FixedCell;
use crate::errors;

/// Represents a RELAY_BEGIN cell.
#[derive(Clone)]
pub struct RelayBegin {
    /// Stream ID.
    pub stream: NonZeroU16,
    /// Cell payload.
    data: RelayWrapper,
    /// Relay version.
    version: Option<RelayVersion>,

    // Auxiliary data to speedup access.
    /// Size of address:port (not including trailing NUL).
    addr_port_s: usize,
    /// `true` if cell has nonzero flags field.
    has_flags: bool,
}

impl Debug for RelayBegin {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        f.debug_struct("RelayBegin")
            .field("stream", &self.stream)
            .field("data", &self.data)
            .finish()
    }
}

impl PartialEq for RelayBegin {
    fn eq(&self, rhs: &Self) -> bool {
        self.stream == rhs.stream && self.data == rhs.data
    }
}

impl Hash for RelayBegin {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.stream.hash(state);
        self.data.hash(state);
    }
}

impl AsRef<FixedCell> for RelayBegin {
    fn as_ref(&self) -> &FixedCell {
        self.data.as_ref()
    }
}

impl Cachable for RelayBegin {
    fn cache<C: CellCache + ?Sized>(self, cache: &C) {
        self.data.cache(cache);
    }
}

impl TryFromRelay for RelayBegin {
    fn try_from_relay(
        relay: &mut Option<Relay>,
        version: RelayVersion,
    ) -> Result<Option<Self>, errors::CellFormatError> {
        let r = match (&*relay, version) {
            (Some(r), RelayVersion::V0) if v0::RelayExt::command(r) == Self::ID => r,
            (Some(r), RelayVersion::V1) if v1::RelayExt::command(r) == Self::ID => r,
            _ => return Ok(None),
        };
        let version = Some(version);
        let Some((Some(stream), addr_port_s, has_flags)) =
            Self::check(AsRef::<FixedCell>::as_ref(r).into(), version)
        else {
            return Err(errors::CellFormatError);
        };

        Ok(Some(Self {
            stream,
            // SAFETY: Relay is Some
            data: FixedCell::from(unsafe { relay.take().unwrap_unchecked() }).into(),
            version,
            addr_port_s,
            has_flags,
        }))
    }
}

impl IntoRelay for RelayBegin {
    fn try_into_relay(
        mut self,
        circuit: NonZeroU32,
        version: RelayVersion,
    ) -> Result<Relay, errors::CellLengthOverflowError> {
        set_cmd_stream(
            self.version,
            version,
            Self::ID,
            self.stream.into(),
            &mut self.data,
        )?;
        Ok(self.data.into_relay(circuit))
    }

    fn try_into_relay_cached<C: CellCache>(
        mut this: Cached<Self, C>,
        circuit: NonZeroU32,
        version: RelayVersion,
    ) -> Result<Cached<Relay, C>, errors::CellLengthOverflowError> {
        set_cmd_stream(
            this.version,
            version,
            Self::ID,
            this.stream.into(),
            &mut this.data,
        )?;
        Ok(Cached::map(this, |v| v.data.into_relay(circuit)))
    }
}

impl RelayBegin {
    /// RELAY_BEGIN command ID.
    pub const ID: u8 = 1;

    /// Creates RELAY_BEGIN cell from [`FixedCell`].
    ///
    /// # Safety
    ///
    /// Cell must be a valid RELAY_BEGIN cell.
    pub unsafe fn from_cell(cell: FixedCell, version: RelayVersion) -> Self {
        let version = Some(version);
        let data = RelayWrapper::from(cell);
        let Some((stream, addr_port_s, has_flags)) = Self::check(&data, version) else {
            panic!("malformed cell format");
        };

        Self {
            stream: unsafe { stream.unwrap_unchecked() },
            data,
            version,
            addr_port_s,
            has_flags,
        }
    }

    /// Creates new RELAY_BEGIN cell.
    ///
    /// # Parameters
    ///
    /// - `cell` : Cached [`FixedCell`].
    /// - `stream` : Stream ID.
    /// - `addr_port` : Address and port in format `addr:port`. Address can be either:
    ///   - A domain address.
    ///   - IPv4 address.
    ///   - IPv6 address.
    /// - `flags` : RELAY_BEGIN flags
    ///
    /// # Return
    ///
    /// Returns RELAY_BEGIN cell or error if data overflows cell.
    ///
    /// # Panics
    ///
    /// Panics if `addr_port` contains null byte.
    ///
    /// # Example
    ///
    /// ```
    /// use std::num::NonZeroU16;
    ///
    /// use onioncloud_lowlevel::cell::relay::begin::{Flags, RelayBegin};
    ///
    /// let cell = RelayBegin::new(
    ///     Default::default(),
    ///     NonZeroU16::new(1).unwrap(),
    ///     "example.com:80",
    ///     Flags::new(),
    /// ).unwrap();
    ///
    /// assert_eq!(cell.addr_port(), "example.com:80");
    /// assert_eq!(cell.flags(), Flags::new());
    /// ```
    pub fn new(
        cell: FixedCell,
        stream: NonZeroU16,
        addr_port: &str,
        flags: Flags,
    ) -> Result<Self, errors::CellLengthOverflowError> {
        assert_eq!(
            chr_nul(addr_port.as_bytes()),
            None,
            "address/port contains NUL byte"
        );

        let mut data = RelayWrapper::from(cell);
        let RelayV001 { len, data: a } = RelayV001::from_mut(&mut data);
        let l = addr_port.len();
        if l >= a.len() {
            return Err(errors::CellLengthOverflowError);
        }
        a[..l].copy_from_slice(addr_port.as_bytes());
        a[l] = 0;

        let (has_flags, sz) = if flags != 0 {
            let Some(a) = a.get_mut(l + 1..l + 5) else {
                return Err(errors::CellLengthOverflowError);
            };
            let p: &mut U32 = transmute_mut!(<&mut [u8; 4]>::try_from(a).unwrap());
            p.set(flags.into());

            (true, l + 5)
        } else {
            (false, l + 1)
        };
        len.set(sz as _);

        if cfg!(debug_assertions) {
            debug_assert_eq!(Self::check(&data, None), Some((None, l, has_flags)));
        }

        Ok(Self {
            stream,
            data,
            version: None,
            addr_port_s: l,
            has_flags,
        })
    }

    /// Get address and port.
    ///
    /// The format is `addr:port`.
    pub fn addr_port(&self) -> &str {
        self.get_data().0
    }

    /// Get flags.
    pub fn flags(&self) -> Flags {
        Flags(self.get_data().1.map_or(0, |v| v.get()))
    }

    fn check(
        cell: &RelayWrapper,
        version: Option<RelayVersion>,
    ) -> Option<(Option<NonZeroU16>, usize, bool)> {
        let (stream, data) = match version {
            None => (None, RelayV001::from_ref(cell).data()),
            Some(RelayVersion::V0) => (
                Some(NonZeroU16::new(v0::RelayExt::stream(cell))?),
                v0::RelayExt::data(cell),
            ),
            Some(RelayVersion::V1) => (
                Some(NonZeroU16::new(v1::RelayExt::stream(cell))?),
                v1::RelayExt::data(cell),
            ),
        };

        let (s, [0, data @ ..]) = chr_nul(data).map(|i| data.split_at(i))? else {
            return None;
        };
        let has_flags = !data.is_empty();
        if has_flags {
            let _flags = U32::ref_from_bytes(data).ok()?;
            // TODO: Check flags.
        }

        let s = from_utf8(s).ok()?;
        // TODO: Check if string content is valid.

        Some((stream, s.len(), has_flags))
    }

    fn get_data(&self) -> (&str, Option<&U32>) {
        let a = match self.version {
            None => &RelayV001::from_ref(&self.data).data[..],
            Some(RelayVersion::V0) => &v0::RelayExt::data_padding(&self.data)[..],
            Some(RelayVersion::V1) => &v1::RelayExt::data_padding(&self.data)[..],
        };

        // SAFETY: Data validity has been checked and auxilirary data is valid.
        unsafe {
            let p = from_ref(a).cast::<u8>();
            (
                from_utf8_unchecked(from_raw_parts(p, self.addr_port_s)),
                if self.has_flags {
                    Some(&*p.add(self.addr_port_s + 1).cast())
                } else {
                    None
                },
            )
        }
    }
}

/// RELAY_BEGIN flags.
///
/// Opaque abstraction of flags. Can be converted to [`u32`] for inspection.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct Flags(u32);

impl From<Flags> for u32 {
    fn from(v: Flags) -> u32 {
        v.0
    }
}

impl PartialEq<u32> for Flags {
    fn eq(&self, rhs: &u32) -> bool {
        self.0 == *rhs
    }
}

impl BitOr for Flags {
    type Output = Self;

    fn bitor(self, rhs: Self) -> Self {
        Self(self.0 | rhs.0)
    }
}

impl Flags {
    /// Enables using IPv6.
    const IPV6_OK: u32 = 1 << 0;

    /// Disables connecting to IPv4.
    const IPV4_NOT_OK: u32 = 1 << 1;

    /// Prefers IPv6 address.
    const IPV6_PREFER: u32 = 1 << 2;

    /// Create empty flags.
    pub const fn new() -> Self {
        Self(0)
    }

    /// Enable IPv6 support.
    pub const fn with_ipv6(self) -> Self {
        Self(self.0 | Self::IPV6_OK)
    }

    /// Enable _only_ IPv6 (and disable IPv4).
    pub const fn without_ipv4(self) -> Self {
        // Set IPV6_OK because if not we can't connect at all.
        Self(self.0 | Self::IPV6_OK | Self::IPV4_NOT_OK)
    }

    /// Enable and prefer IPv6.
    pub const fn prefer_ipv6(self) -> Self {
        // Set IPV6_OK because if not it's useless.
        Self(self.0 | Self::IPV6_OK | Self::IPV6_PREFER)
    }

    /// Check if IPv6 is enabled.
    pub const fn is_ipv6_enabled(&self) -> bool {
        self.0 & Self::IPV6_OK != 0
    }

    /// Check if IPv4 is disabled.
    pub const fn is_ipv4_disabled(&self) -> bool {
        self.0 & Self::IPV4_NOT_OK != 0
    }

    /// Check if IPv6 is preferred.
    pub const fn is_ipv6_preferred(&self) -> bool {
        self.0 & Self::IPV6_PREFER != 0
    }
}

#[inline]
fn chr_nul(s: &[u8]) -> Option<usize> {
    memchr(0, s)
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::fmt::Write;
    use std::iter::repeat_n;

    use proptest::prelude::*;

    use crate::cell::FIXED_CELL_SIZE;
    use crate::cell::relay::v0::tests::assert_relay_eq;

    fn strat() -> impl Strategy<Value = (String, u32, NonZeroU16)> {
        (
            ("[a-zA-Z]{0,128}", any::<u16>()).prop_map(|(mut a, p)| {
                write!(a, ":{p}").unwrap();
                a
            }),
            any::<u32>(),
            any::<NonZeroU16>(),
        )
    }

    #[test]
    fn test_begin_no_nul() {
        let mut cell = Some(Relay::new(
            FixedCell::default(),
            NonZeroU32::new(1).unwrap(),
            RelayBegin::ID,
            1,
            b"example.com:80",
        ));
        RelayBegin::try_from_relay(&mut cell, RelayVersion::V0).unwrap_err();
        cell.unwrap();
    }

    #[test]
    fn test_begin_not_utf8() {
        let mut cell = Some(Relay::new(
            FixedCell::default(),
            NonZeroU32::new(1).unwrap(),
            RelayBegin::ID,
            1,
            b"example.\x80com:80\0\0\0\0\0",
        ));
        RelayBegin::try_from_relay(&mut cell, RelayVersion::V0).unwrap_err();
        cell.unwrap();
    }

    fn make_long_addr(n: usize) -> String {
        static SUFFIX: &str = ".com:80";
        let mut s = String::new();
        s.extend(repeat_n('a', n - SUFFIX.len()));
        s.push_str(SUFFIX);
        s
    }

    #[test]
    fn test_begin_overflow() {
        let ret = RelayBegin::new(
            FixedCell::default(),
            NonZeroU16::new(1).unwrap(),
            &make_long_addr(FIXED_CELL_SIZE - 2),
            Flags::new(),
        );
        assert!(ret.is_err(), "expect error, got {ret:?}");
    }

    #[test]
    fn test_begin_overflow2() {
        let ret = RelayBegin::new(
            FixedCell::default(),
            NonZeroU16::new(1).unwrap(),
            &make_long_addr(FIXED_CELL_SIZE - 6),
            Flags(1),
        );
        assert!(ret.is_err(), "expect error, got {ret:?}");
    }

    proptest! {
        #[test]
        fn test_begin_new(
            (addr_port, flags, stream) in strat(),
        ) {
            let cell = RelayBegin::new(FixedCell::default(), stream, &addr_port, Flags(flags)).unwrap();

            assert_eq!(cell.stream, stream);
            assert_eq!(cell.addr_port(), addr_port);
            assert_eq!(cell.flags(), flags);
        }

        #[test]
        fn test_begin_clone(
            (addr_port, flags, stream) in strat(),
        ) {
            let cell = RelayBegin::new(FixedCell::default(), stream, &addr_port, Flags(flags)).unwrap();
            drop(addr_port);
            let target = cell.clone();

            assert_eq!(cell.stream, target.stream);
            assert_eq!(cell.addr_port(), target.addr_port());
            assert_eq!(cell.flags(), target.flags());
        }

        #[test]
        fn test_begin_from_into_relay(
            (addr_port, flags, stream) in strat(),
        ) {
            let mut v = Vec::new();
            v.extend_from_slice(addr_port.as_bytes());
            v.push(0);
            if flags != 0 {
                v.extend_from_slice(&flags.to_be_bytes());
            }

            let cell = Relay::new(FixedCell::default(), NonZeroU32::new(1).unwrap(), RelayBegin::ID, stream.into(), &v);
            drop(v);
            let data = RelayWrapper::from(AsRef::<FixedCell>::as_ref(&cell).clone());
            let cell = RelayBegin::try_from_relay(&mut Some(cell), RelayVersion::V0).unwrap().unwrap();

            assert_eq!(cell.stream, stream);
            assert_eq!(cell.addr_port(), addr_port);
            assert_eq!(cell.flags(), flags);

            let cell = cell.try_into_relay(NonZeroU32::new(1).unwrap(), RelayVersion::V0).unwrap();

            assert_relay_eq(&cell, &data);
        }

        #[test]
        fn test_begin_truncated(n in 1usize..4) {
            static STR: &[u8] = b"example.com:80\0\0\0\0\x01";
            let mut cell = Some(Relay::new(
                FixedCell::default(),
                NonZeroU32::new(1).unwrap(),
                RelayBegin::ID,
                1,
                &STR[..STR.len() - n],
            ));
            RelayBegin::try_from_relay(&mut cell, RelayVersion::V0).unwrap_err();
            cell.unwrap();
        }
    }
}
