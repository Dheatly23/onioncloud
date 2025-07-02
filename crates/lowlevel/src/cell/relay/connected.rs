use std::mem::size_of;
use std::net::IpAddr;
use std::num::{NonZeroU16, NonZeroU32};

use zerocopy::byteorder::big_endian::U32;
use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout, Unaligned, transmute_ref};

use super::{
    IntoRelay, RELAY_DATA_LENGTH, Relay, RelayLike, RelayWrapper, TryFromRelay, take_if,
    with_cmd_stream,
};
use crate::cache::Cachable;
use crate::cell::FixedCell;
use crate::errors;

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

#[derive(FromBytes, KnownLayout, Immutable, Unaligned)]
#[repr(C)]
struct ConnectedIpv4Pad {
    data: ConnectedIpv4,
    pad: [u8; const { RELAY_DATA_LENGTH - size_of::<ConnectedIpv4>() }],
}

#[derive(FromBytes, KnownLayout, Immutable, Unaligned)]
#[repr(C)]
struct ConnectedIpv6Pad {
    data: ConnectedIpv6,
    pad: [u8; const { RELAY_DATA_LENGTH - size_of::<ConnectedIpv6>() }],
}

/// Represents a RELAY_CONNECTED cell.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct RelayConnected {
    /// Stream ID.
    pub stream: NonZeroU16,
    /// Cell payload.
    data: RelayWrapper,
}

impl AsRef<FixedCell> for RelayConnected {
    fn as_ref(&self) -> &FixedCell {
        self.data.as_ref()
    }
}

impl Cachable for RelayConnected {
    fn maybe_into_fixed(self) -> Option<FixedCell> {
        Some(self.data.into())
    }
}

impl TryFromRelay for RelayConnected {
    fn try_from_relay(relay: &mut Option<Relay>) -> Result<Option<Self>, errors::CellFormatError> {
        let stream = match &*relay {
            Some(r) if r.command() == Self::ID => {
                NonZeroU16::new(r.stream()).ok_or(errors::CellFormatError)?
            }
            _ => return Ok(None),
        };

        take_if(relay, Self::check).map(|v| v.map(|data| Self { stream, data }))
    }
}

impl IntoRelay for RelayConnected {
    fn into_relay(self, circuit: NonZeroU32) -> Relay {
        with_cmd_stream(self.data, Self::ID, self.stream.into(), circuit)
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
    pub unsafe fn from_cell(cell: FixedCell) -> Self {
        let data = RelayWrapper::from(cell);
        debug_assert_eq!(data.command(), Self::ID);
        debug_assert!(Self::check(data.data()));

        Self {
            stream: NonZeroU16::new(data.stream()).expect("stream ID is zero"),
            data,
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

        data.set_data(&[]);

        debug_assert!(Self::check(data.data()));

        Self { stream, data }
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

        match ip {
            IpAddr::V4(v) => data.set_data(
                ConnectedIpv4 {
                    ip: v.octets(),
                    ttl: ttl.into(),
                }
                .as_bytes(),
            ),
            IpAddr::V6(v) => data.set_data(
                ConnectedIpv6 {
                    all_z: [0; 4],
                    ip_ty: 6,
                    ip: v.octets(),
                    ttl: ttl.into(),
                }
                .as_bytes(),
            ),
        };

        debug_assert!(Self::check(data.data()));

        Self { stream, data }
    }

    /// Get content of RELAY_CONNECTED.
    ///
    /// Returns an [`Option`] of IP address and TTL.
    pub fn data(&self) -> Option<(IpAddr, u32)> {
        if self.data.is_empty() {
            return None;
        }
        let data = self.data.data_padding();

        Some(match transmute_ref!(data) {
            ConnectedIpv4Pad {
                data: ConnectedIpv4 {
                    ip: [0, 0, 0, 0], ..
                },
                ..
            } => {
                let &ConnectedIpv6Pad {
                    data: ConnectedIpv6 { ip, ref ttl, .. },
                    ..
                } = transmute_ref!(data);
                (ip.into(), ttl.get())
            }
            &ConnectedIpv4Pad {
                data: ConnectedIpv4 { ip, ref ttl },
                ..
            } => (ip.into(), ttl.get()),
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

    use crate::cell::relay::tests::assert_relay_eq;

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
        RelayConnected::try_from_relay(&mut cell).unwrap_err();
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
        println!("{:?}", cell.data.data());
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
        println!("{:?}", cell.data.data());
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
            let cell = RelayConnected::try_from_relay(&mut Some(cell)).unwrap().unwrap();

            assert_eq!(cell.stream, stream);
            assert_eq!(cell.v(), Some((addr, ttl)));

            let cell = cell.into_relay(NonZeroU32::new(1).unwrap());

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
            let cell = RelayConnected::try_from_relay(&mut Some(cell))
                .unwrap()
                .unwrap();

            assert_eq!(cell.stream, stream);
            assert_eq!(cell.data(), None);

            let cell = cell.into_relay(NonZeroU32::new(1).unwrap());

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
            RelayConnected::try_from_relay(&mut cell).unwrap_err();
            cell.unwrap();
        }
    }
}
