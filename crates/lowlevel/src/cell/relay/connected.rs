use std::mem::size_of;
use std::net::IpAddr;
use std::num::{NonZeroU16, NonZeroU32};
use std::ptr::from_mut;

use zerocopy::byteorder::big_endian::U32;
use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout, Unaligned, transmute_ref};

use super::{
    IntoRelay, Relay, RelayV001, RelayVersion, RelayWrapper, TryFromRelay, set_cmd_stream,
    take_if_nonzero_stream, v0, v1,
};
use crate::cache::{Cachable, Cached, CellCache};
use crate::cell::FixedCell;
use crate::errors;
use crate::util::c_max_usize;

#[derive(FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned)]
#[repr(C)]
struct ConnectedIpv4 {
    ip: [u8; 4],
    ttl: U32,
}

#[derive(FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned)]
#[repr(C)]
struct ConnectedIpv6 {
    all_z: [u8; 4],
    ip_ty: u8,
    ip: [u8; 16],
    ttl: U32,
}

/// Represents a RELAY_CONNECTED cell.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct RelayConnected {
    /// Stream ID.
    pub stream: NonZeroU16,
    /// Cell payload.
    data: RelayWrapper,
    /// Relay version.
    version: Option<RelayVersion>,
}

impl AsRef<FixedCell> for RelayConnected {
    fn as_ref(&self) -> &FixedCell {
        self.data.as_ref()
    }
}

impl Cachable for RelayConnected {
    fn cache<C: CellCache + ?Sized>(self, cache: &C) {
        self.data.cache(cache);
    }
}

impl TryFromRelay for RelayConnected {
    fn try_from_relay(
        relay: &mut Option<Relay>,
        version: RelayVersion,
    ) -> Result<Option<Self>, errors::CellFormatError> {
        take_if_nonzero_stream(relay, Self::ID, version, Self::check).map(|v| {
            v.map(|(stream, data)| Self {
                stream,
                data,
                version: Some(version),
            })
        })
    }
}

impl IntoRelay for RelayConnected {
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

impl RelayConnected {
    /// RELAY_CONNECTED command ID.
    pub const ID: u8 = 4;

    /// Creates RELAY_CONNECTED cell from [`FixedCell`].
    ///
    /// # Safety
    ///
    /// Cell must be a valid RELAY_CONNECTED cell.
    pub unsafe fn from_cell(cell: FixedCell, version: RelayVersion) -> Self {
        let data = RelayWrapper::from(cell);

        let (command, stream, a) = match version {
            RelayVersion::V0 => (
                v0::RelayExt::command(&data),
                v0::RelayExt::stream(&data),
                v0::RelayExt::data(&data),
            ),
            RelayVersion::V1 => (
                v1::RelayExt::command(&data),
                v1::RelayExt::stream(&data),
                v1::RelayExt::data(&data),
            ),
        };
        debug_assert_eq!(command, Self::ID);
        debug_assert!(Self::check(a));

        Self {
            stream: unsafe { NonZeroU16::new_unchecked(stream) },
            data,
            version: Some(version),
        }
    }

    /// Creates empty RELAY_CONNECTED cell.
    ///
    /// # Parameters
    ///
    /// - `cell` : Cached [`FixedCell`].
    /// - `stream` : Stream ID.
    ///
    /// # Example
    ///
    /// ```
    /// use std::num::NonZeroU16;
    ///
    /// use onioncloud_lowlevel::cell::relay::connected::RelayConnected;
    ///
    /// let cell = RelayConnected::new_empty(
    ///     Default::default(),
    ///     NonZeroU16::new(1).unwrap(),
    /// );
    /// ```
    pub fn new_empty(cell: FixedCell, stream: NonZeroU16) -> Self {
        let mut data = RelayWrapper::from(cell);

        RelayV001::from_mut(&mut data).len.set(0);

        Self {
            stream,
            data,
            version: None,
        }
    }

    /// Creates new RELAY_CONNECTED cell.
    ///
    /// # Parameters
    ///
    /// - `cell` : Cached [`FixedCell`].
    /// - `stream` : Stream ID.
    /// - `ip` : IP address.
    /// - `ttl` : Time to live.
    ///
    /// # Panics
    ///
    /// Panics if IP is unspecified (see [`std::net::IpAddr::is_unspecified`]).
    ///
    /// # Example
    ///
    /// ```
    /// use std::net::Ipv4Addr;
    /// use std::num::NonZeroU16;
    ///
    /// use onioncloud_lowlevel::cell::relay::connected::RelayConnected;
    ///
    /// let cell = RelayConnected::new(
    ///     Default::default(),
    ///     NonZeroU16::new(1).unwrap(),
    ///     Ipv4Addr::LOCALHOST.into(),
    ///     1,
    /// );
    /// ```
    pub fn new(cell: FixedCell, stream: NonZeroU16, ip: IpAddr, ttl: u32) -> Self {
        assert!(!ip.is_unspecified(), "IP is all zeros");

        let mut data = RelayWrapper::from(cell);

        let RelayV001 { len, data: a } = RelayV001::from_mut(&mut data);
        len.set(match ip {
            IpAddr::V4(v) => {
                let v = ConnectedIpv4 {
                    ip: v.octets(),
                    ttl: ttl.into(),
                };

                // SAFETY: Value fits in array.
                unsafe { *from_mut(a).cast::<_>() = v };

                size_of::<ConnectedIpv4>()
            }
            IpAddr::V6(v) => {
                let v = ConnectedIpv6 {
                    all_z: [0; 4],
                    ip_ty: 6,
                    ip: v.octets(),
                    ttl: ttl.into(),
                };

                // SAFETY: Value fits in array.
                unsafe { *from_mut(a).cast::<_>() = v };

                size_of::<ConnectedIpv6>()
            }
        } as _);

        debug_assert!(Self::check(&a[..len.get() as usize]));

        Self {
            stream,
            data,
            version: None,
        }
    }

    /// Get content of RELAY_CONNECTED.
    ///
    /// Returns an [`Option`] of IP address and TTL.
    pub fn data(&self) -> Option<(IpAddr, u32)> {
        const MAX_SIZE: usize = c_max_usize(size_of::<ConnectedIpv4>(), size_of::<ConnectedIpv6>());

        let (l, a) = match self.version {
            None => {
                let RelayV001 { len, data } = RelayV001::from_ref(&self.data);
                (len.get(), &data[..MAX_SIZE])
            }
            Some(RelayVersion::V0) => (
                v0::RelayExt::len(&self.data),
                &v0::RelayExt::data_padding(&self.data)[..MAX_SIZE],
            ),
            Some(RelayVersion::V1) => (
                v1::RelayExt::len(&self.data),
                &v1::RelayExt::data_padding(&self.data)[..MAX_SIZE],
            ),
        };
        if l == 0 {
            return None;
        }

        let a = <&[u8; MAX_SIZE]>::try_from(a).expect("array size must be MAX_LEN");

        #[derive(FromBytes, KnownLayout, Immutable, Unaligned)]
        #[repr(C)]
        struct ConnectedIpv4Pad {
            data: ConnectedIpv4,
            pad: [u8; const { MAX_SIZE - size_of::<ConnectedIpv4>() }],
        }

        #[derive(FromBytes, KnownLayout, Immutable, Unaligned)]
        #[repr(C)]
        struct ConnectedIpv6Pad {
            data: ConnectedIpv6,
            pad: [u8; const { MAX_SIZE - size_of::<ConnectedIpv6>() }],
        }

        Some(match transmute_ref!(a) {
            ConnectedIpv4Pad {
                data: ConnectedIpv4 {
                    ip: [0, 0, 0, 0], ..
                },
                ..
            } => {
                let &ConnectedIpv6Pad {
                    data: ConnectedIpv6 { ip, ttl, .. },
                    ..
                } = transmute_ref!(a);
                (ip.into(), ttl.into())
            }
            &ConnectedIpv4Pad {
                data: ConnectedIpv4 { ip, ttl },
                ..
            } => (ip.into(), ttl.into()),
        })
    }

    fn check(data: &[u8]) -> bool {
        if data.is_empty() {
            return true;
        }

        match ConnectedIpv4::ref_from_prefix(data) {
            Ok((
                ConnectedIpv4 {
                    ip: [0, 0, 0, 0], ..
                },
                _,
            )) => matches!(
                ConnectedIpv6::ref_from_prefix(data),
                Ok((ConnectedIpv6 { ip_ty: 6, .. }, []))
            ),
            Ok((_, [])) => true,
            _ => false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use proptest::prelude::*;

    use crate::cell::relay::v0::tests::assert_relay_eq;

    fn strat() -> impl Strategy<Value = (IpAddr, u32, NonZeroU16)> {
        (
            any::<IpAddr>().prop_filter("ip is zero", |v| !v.is_unspecified()),
            any::<u32>(),
            any::<NonZeroU16>(),
        )
    }

    #[test]
    fn test_connected_not_ip() {
        let mut cell = Some(Relay::new(
            FixedCell::default(),
            NonZeroU32::new(1).unwrap(),
            RelayConnected::ID,
            1,
            &[
                0, 0, 0, 0, 123, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0,
            ],
        ));
        RelayConnected::try_from_relay(&mut cell, RelayVersion::V0).unwrap_err();
        cell.unwrap();
    }

    #[test]
    #[should_panic]
    fn test_connected_ipv4_zero() {
        let cell = RelayConnected::new(
            FixedCell::default(),
            NonZeroU16::new(1).unwrap(),
            [0; 4].into(),
            0,
        );
        println!("{cell:?}");
    }

    #[test]
    #[should_panic]
    fn test_connected_ipv6_zero() {
        let cell = RelayConnected::new(
            FixedCell::default(),
            NonZeroU16::new(1).unwrap(),
            [0; 16].into(),
            0,
        );
        println!("{cell:?}");
    }

    proptest! {
        #[test]
        fn test_connected_new(
            (addr, ttl, stream) in strat(),
        ) {
            let cell = RelayConnected::new(FixedCell::default(), stream, addr, ttl);

            assert_eq!(cell.stream, stream);
            assert_eq!(cell.data(), Some((addr, ttl)));
        }

        #[test]
        fn test_connected_from_into_relay(
            (addr, ttl, stream) in strat(),
        ) {
            let mut v = Vec::new();
            match addr {
                IpAddr::V4(t) => v.extend_from_slice(&t.octets()),
                IpAddr::V6(t) => {
                    v.extend_from_slice(&[0, 0, 0, 0, 6]);
                    v.extend_from_slice(&t.octets());
                },
            }
            v.extend_from_slice(&ttl.to_be_bytes());

            let cell = Relay::new(FixedCell::default(), NonZeroU32::new(1).unwrap(), RelayConnected::ID, stream.into(), &v);
            drop(v);
            let data = RelayWrapper::from(AsRef::<FixedCell>::as_ref(&cell).clone());
            let cell = RelayConnected::try_from_relay(&mut Some(cell), RelayVersion::V0).unwrap().unwrap();

            assert_eq!(cell.stream, stream);
            assert_eq!(cell.data(), Some((addr, ttl)));

            let cell = cell.try_into_relay(NonZeroU32::new(1).unwrap(), RelayVersion::V0).unwrap();

            assert_relay_eq(&cell, &data);
        }

        #[test]
        fn test_connected_new_empty(stream: NonZeroU16) {
            let cell = RelayConnected::new_empty(FixedCell::default(), stream);

            assert_eq!(cell.stream, stream);
            assert_eq!(cell.data(), None);
        }

        #[test]
        fn test_connected_empty_from_into_relay(stream: NonZeroU16) {
            let cell = Relay::new(
                FixedCell::default(),
                NonZeroU32::new(1).unwrap(),
                RelayConnected::ID,
                stream.into(),
                &[],
            );
            let data = RelayWrapper::from(AsRef::<FixedCell>::as_ref(&cell).clone());
            let cell = RelayConnected::try_from_relay(&mut Some(cell), RelayVersion::V0)
                .unwrap()
                .unwrap();

            assert_eq!(cell.stream, stream);
            assert_eq!(cell.data(), None);

            let cell = cell.try_into_relay(NonZeroU32::new(1).unwrap(), RelayVersion::V0).unwrap();

            assert_relay_eq(&cell, &data);
        }

        #[test]
        fn test_connected_truncated(n in 1usize..8) {
            let mut cell = Some(Relay::new(
                FixedCell::default(),
                NonZeroU32::new(1).unwrap(),
                RelayConnected::ID,
                1,
                &[127, 0, 0, 1, 0, 0, 0, 0][..n],
            ));
            RelayConnected::try_from_relay(&mut cell, RelayVersion::V0).unwrap_err();
            cell.unwrap();
        }
    }
}
