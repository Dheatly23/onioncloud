use std::fmt::{Display, Formatter, Result as FmtResult};
use std::mem::size_of;
use std::net::IpAddr;
use std::num::{NonZeroU16, NonZeroU32};

use zerocopy::byteorder::big_endian::U32;
use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout, Unaligned, transmute_mut};

use super::{
    IntoRelay, Relay, RelayV001, RelayVersion, RelayWrapper, TryFromRelay, take_if_nonzero_stream,
    v0, v1, with_cmd_stream,
};
use crate::cache::Cachable;
use crate::cell::FixedCell;
use crate::errors;
use crate::util::c_max_usize;

#[derive(FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned)]
#[repr(C)]
struct ExitPolicyIpv4 {
    /// Must be 4.
    ty: u8,
    addr: [u8; 4],
    ttl: U32,
}

#[derive(FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned)]
#[repr(C)]
struct ExitPolicyIpv6 {
    /// Must be 4.
    ty: u8,
    addr: [u8; 16],
    ttl: U32,
}

/// Represents a RELAY_END cell.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct RelayEnd {
    /// Stream ID.
    pub stream: NonZeroU16,
    /// Cell payload.
    data: RelayWrapper,
    /// Relay version.
    version: Option<RelayVersion>,
}

impl AsRef<FixedCell> for RelayEnd {
    fn as_ref(&self) -> &FixedCell {
        self.data.as_ref()
    }
}

impl Cachable for RelayEnd {
    fn maybe_into_fixed(self) -> Option<FixedCell> {
        Some(self.data.into())
    }
}

impl TryFromRelay for RelayEnd {
    fn try_from_relay(
        relay: &mut Option<Relay>,
        version: RelayVersion,
    ) -> Result<Option<Self>, errors::CellFormatError> {
        take_if_nonzero_stream(relay, Self::ID, version, |_| true).map(|v| {
            v.map(|(stream, data)| Self {
                stream,
                data,
                version: Some(version),
            })
        })
    }
}

impl IntoRelay for RelayEnd {
    fn try_into_relay(
        self,
        circuit: NonZeroU32,
        version: RelayVersion,
    ) -> Result<Relay, errors::CellLengthOverflowError> {
        with_cmd_stream(
            self.data,
            self.version,
            version,
            Self::ID,
            self.stream.into(),
            circuit,
        )
    }
}

impl RelayEnd {
    /// RELAY_END command ID.
    pub const ID: u8 = 3;

    /// Creates RELAY_END cell from [`FixedCell`].
    ///
    /// # Safety
    ///
    /// Cell must be a valid RELAY_END cell.
    pub unsafe fn from_cell(cell: FixedCell, version: RelayVersion) -> Self {
        let data = RelayWrapper::from(cell);

        let (command, stream) = match version {
            RelayVersion::V0 => (v0::RelayExt::command(&data), v0::RelayExt::stream(&data)),
            RelayVersion::V1 => (v1::RelayExt::command(&data), v1::RelayExt::stream(&data)),
        };
        debug_assert_eq!(command, Self::ID);

        Self {
            stream: unsafe { NonZeroU16::new_unchecked(stream) },
            data,
            version: Some(version),
        }
    }

    /// Creates new RELAY_END cell.
    ///
    /// # Parameters
    ///
    /// - `cell` : Cached [`FixedCell`].
    /// - `stream` : Stream ID.
    /// - `reason` : End reason.
    ///
    /// # Example
    ///
    /// ```
    /// use std::num::NonZeroU16;
    ///
    /// use onioncloud_lowlevel::cell::relay::end::{EndReason, RelayEnd};
    ///
    /// let cell = RelayEnd::new(
    ///     Default::default(),
    ///     NonZeroU16::new(1).unwrap(),
    ///     EndReason::Misc,
    /// );
    /// ```
    pub fn new(cell: FixedCell, stream: NonZeroU16, reason: EndReason) -> Self {
        let mut data = RelayWrapper::from(cell);
        Self::set_reason_inner(&mut data, None, &reason);

        let ret = Self {
            stream,
            data,
            version: None,
        };
        debug_assert_eq!(ret.reason(), reason);
        ret
    }

    /// Get end reason.
    pub fn reason(&self) -> EndReason {
        fn parse_exit_policy(data: &[u8]) -> Option<ExitPolicy> {
            if let Ok((&ip, data)) = <[u8; 16]>::ref_from_prefix(data) {
                Some(ExitPolicy {
                    addr: ip.into(),
                    ttl: parse_ttl(data),
                })
            } else if let Ok((&ip, data)) = <[u8; 4]>::ref_from_prefix(data) {
                Some(ExitPolicy {
                    addr: ip.into(),
                    ttl: parse_ttl(data),
                })
            } else {
                None
            }
        }

        fn parse_ttl(data: &[u8]) -> u32 {
            match U32::ref_from_prefix(data) {
                Ok((ttl, _)) => ttl.get(),
                _ => u32::MAX,
            }
        }

        let a = match self.version {
            None => RelayV001::from_ref(&self.data).data(),
            Some(RelayVersion::V0) => v0::RelayExt::data(&self.data),
            Some(RelayVersion::V1) => v1::RelayExt::data(&self.data),
        };

        match a {
            [2, ..] => EndReason::ResolveFailed,
            [3, ..] => EndReason::ConnectRefused,
            [4, data @ ..] => EndReason::ExitPolicy(parse_exit_policy(data)),
            [5, ..] => EndReason::Destroy,
            [6, ..] => EndReason::Done,
            [7, ..] => EndReason::Timeout,
            [8, ..] => EndReason::NoRoute,
            [9, ..] => EndReason::Hibernating,
            [10, ..] => EndReason::Internal,
            [11, ..] => EndReason::ResourceLimit,
            [12, ..] => EndReason::ConnReset,
            [13, ..] => EndReason::TorProtocol,
            [14, ..] => EndReason::NotDirectory,
            _ => EndReason::Misc,
        }
    }

    /// Set end reason.
    pub fn set_reason(&mut self, reason: EndReason) {
        Self::set_reason_inner(&mut self.data, self.version, &reason);
    }

    fn set_reason_inner(
        data: &mut RelayWrapper,
        version: Option<RelayVersion>,
        reason: &EndReason,
    ) {
        const MAX_SIZE: usize = c_max_usize(
            size_of::<u8>(),
            c_max_usize(size_of::<ExitPolicyIpv4>(), size_of::<ExitPolicyIpv6>()),
        );

        let a = match version {
            None => &mut RelayV001::from_mut(data).data[..MAX_SIZE],
            Some(RelayVersion::V0) => &mut v0::RelayExt::data_padding_mut(data)[..MAX_SIZE],
            Some(RelayVersion::V1) => &mut v1::RelayExt::data_padding_mut(data)[..MAX_SIZE],
        };
        let a = <&mut [u8; MAX_SIZE]>::try_from(a).expect("array size must be MAX_LEN");

        #[derive(FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned)]
        #[repr(C)]
        struct ExitPolicyIpv4Pad {
            data: ExitPolicyIpv4,
            pad: [u8; const { MAX_SIZE - size_of::<ExitPolicyIpv4>() }],
        }

        #[derive(FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned)]
        #[repr(C)]
        struct ExitPolicyIpv6Pad {
            data: ExitPolicyIpv6,
            pad: [u8; const { MAX_SIZE - size_of::<ExitPolicyIpv6>() }],
        }

        let mut len = 1;
        match *reason {
            EndReason::Misc => a[0] = 1,
            EndReason::ResolveFailed => a[0] = 2,
            EndReason::ConnectRefused => a[0] = 3,
            EndReason::ExitPolicy(None) => a[0] = 4,
            EndReason::ExitPolicy(Some(ExitPolicy {
                addr: IpAddr::V4(ref addr),
                ttl,
            })) => {
                let ExitPolicyIpv4Pad { data, .. } = transmute_mut!(a);
                *data = ExitPolicyIpv4 {
                    ty: 4,
                    addr: addr.octets(),
                    ttl: ttl.into(),
                };
                len = size_of::<ExitPolicyIpv4>() as u16;
            }
            EndReason::ExitPolicy(Some(ExitPolicy {
                addr: IpAddr::V6(ref addr),
                ttl,
            })) => {
                let ExitPolicyIpv6Pad { data, .. } = transmute_mut!(a);
                *data = ExitPolicyIpv6 {
                    ty: 4,
                    addr: addr.octets(),
                    ttl: ttl.into(),
                };
                len = size_of::<ExitPolicyIpv6>() as u16;
            }
            EndReason::Destroy => a[0] = 5,
            EndReason::Done => a[0] = 6,
            EndReason::Timeout => a[0] = 7,
            EndReason::NoRoute => a[0] = 8,
            EndReason::Hibernating => a[0] = 9,
            EndReason::Internal => a[0] = 10,
            EndReason::ResourceLimit => a[0] = 11,
            EndReason::ConnReset => a[0] = 12,
            EndReason::TorProtocol => a[0] = 13,
            EndReason::NotDirectory => a[0] = 14,
        }

        // SAFETY: Length matches data length.
        unsafe {
            match version {
                None => RelayV001::from_mut(data).len.set(len),
                Some(RelayVersion::V0) => v0::RelayExt::set_len(data, len),
                Some(RelayVersion::V1) => v1::RelayExt::set_len(data, len),
            };
        }
    }
}

/// Reason for closing stream.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum EndReason {
    /// Catch-all for unlisted reasons.
    #[default]
    Misc,

    /// Couldn't look up hostname.
    ResolveFailed,

    /// Remote host refused connection.
    ConnectRefused,

    /// Relay refuses to connect to host or port.
    ExitPolicy(Option<ExitPolicy>),

    /// Circuit is being destroyed.
    Destroy,

    /// Anonymized TCP connection was closed.
    Done,

    /// Connection timed out, or relay timed out while connecting.
    Timeout,

    /// Routing error while attempting to contact destination.
    NoRoute,

    /// Relay is temporarily hibernating.
    Hibernating,

    /// Internal error at the relay.
    Internal,

    /// Relay has no resources to fulfill request.
    ResourceLimit,

    /// Connection was unexpectedly reset.
    ConnReset,

    /// Sent when closing connection because of Tor protocol violations.
    TorProtocol,

    /// Client sent RELAY_BEGIN_DIR to a non-directory relay.
    NotDirectory,
}

impl Display for EndReason {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        let s = match self {
            Self::Misc => "unknown reason",
            Self::ResolveFailed => "hostname resolution failed",
            Self::ConnectRefused => "remote host connection refused",
            Self::ExitPolicy(None) => "relay exit policy",
            Self::Destroy => "circuit is destroying",
            Self::Done => "TCP connection is closed",
            Self::Timeout => "connection timeout",
            Self::NoRoute => "unknown connection routing error",
            Self::Hibernating => "relay is hibernating",
            Self::Internal => "internal error",
            Self::ResourceLimit => "relay resource limit reached",
            Self::ConnReset => "connection is reset",
            Self::TorProtocol => "protocol violation",
            Self::NotDirectory => "relay is not a directory node",

            Self::ExitPolicy(Some(ExitPolicy { addr, .. })) => {
                return write!(f, "relay exit policy (resolved address: {addr})");
            }
        };

        write!(f, "{s}")
    }
}

/// Additional data for [`EndReason::ExitPolicy`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExitPolicy {
    /// IP Address.
    pub addr: IpAddr,

    /// Time to live.
    pub ttl: u32,
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::iter::repeat_n;
    use std::net::{Ipv4Addr, Ipv6Addr};

    use proptest::prelude::*;

    use crate::cell::relay::v0::tests::assert_relay_eq;

    fn strat() -> impl Strategy<Value = (NonZeroU16, EndReason)> {
        (
            any::<NonZeroU16>(),
            prop_oneof![
                Just(()).prop_map(|_| EndReason::Misc),
                Just(()).prop_map(|_| EndReason::ResolveFailed),
                Just(()).prop_map(|_| EndReason::ConnectRefused),
                Just(()).prop_map(|_| EndReason::ExitPolicy(None)),
                Just(()).prop_map(|_| EndReason::Destroy),
                Just(()).prop_map(|_| EndReason::Done),
                Just(()).prop_map(|_| EndReason::Timeout),
                Just(()).prop_map(|_| EndReason::NoRoute),
                Just(()).prop_map(|_| EndReason::Hibernating),
                Just(()).prop_map(|_| EndReason::Internal),
                Just(()).prop_map(|_| EndReason::ResourceLimit),
                Just(()).prop_map(|_| EndReason::ConnReset),
                Just(()).prop_map(|_| EndReason::TorProtocol),
                Just(()).prop_map(|_| EndReason::NotDirectory),
                (any::<IpAddr>(), any::<u32>())
                    .prop_map(|(addr, ttl)| EndReason::ExitPolicy(Some(ExitPolicy { addr, ttl }))),
            ],
        )
    }

    #[test]
    fn test_end_empty() {
        let mut cell = Some(Relay::new(
            FixedCell::default(),
            NonZeroU32::new(1).unwrap(),
            RelayEnd::ID,
            1,
            &[],
        ));
        let cell = RelayEnd::try_from_relay(&mut cell, RelayVersion::V0)
            .unwrap()
            .unwrap();
        assert_eq!(cell.reason(), EndReason::Misc);
    }

    #[test]
    fn test_end_unknown() {
        let mut cell = Some(Relay::new(
            FixedCell::default(),
            NonZeroU32::new(1).unwrap(),
            RelayEnd::ID,
            1,
            &[255],
        ));
        let cell = RelayEnd::try_from_relay(&mut cell, RelayVersion::V0)
            .unwrap()
            .unwrap();
        assert_eq!(cell.reason(), EndReason::Misc);
    }

    proptest! {
        #[test]
        fn test_end_from_data(
            (stream, reason) in strat(),
        ) {
            let cell = RelayEnd::new(FixedCell::default(), stream, reason.clone());

            assert_eq!(cell.stream, stream);
            assert_eq!(cell.reason(), reason);
        }

        #[test]
        fn test_end_from_into_relay(
            (stream, reason) in strat(),
        ) {
            let mut v = Vec::new();
            match reason {
                EndReason::Misc => v.push(1),
                EndReason::ResolveFailed => v.push(2),
                EndReason::ConnectRefused => v.push(3),
                EndReason::ExitPolicy(None) => v.push(4),
                EndReason::ExitPolicy(Some(ExitPolicy {
                    addr: IpAddr::V4(ref a),
                    ttl,
                })) => v.extend_from_slice(ExitPolicyIpv4 {
                    ty: 4,
                    addr: a.octets(),
                    ttl: ttl.into(),
                }.as_bytes()),
                EndReason::ExitPolicy(Some(ExitPolicy {
                    addr: IpAddr::V6(ref a),
                    ttl,
                })) => v.extend_from_slice(ExitPolicyIpv6 {
                    ty: 4,
                    addr:a.octets(),
                    ttl:ttl.into(),
                }.as_bytes()),
                EndReason::Destroy => v.push(5),
                EndReason::Done => v.push(6),
                EndReason::Timeout => v.push(7),
                EndReason::NoRoute => v.push(8),
                EndReason::Hibernating => v.push(9),
                EndReason::Internal => v.push(10),
                EndReason::ResourceLimit => v.push(11),
                EndReason::ConnReset => v.push(12),
                EndReason::TorProtocol => v.push(13),
                EndReason::NotDirectory => v.push(14),
            }

            let cell = Relay::new(FixedCell::default(), NonZeroU32::new(1).unwrap(), RelayEnd::ID, stream.into(), &v);
            drop(v);
            let data = RelayWrapper::from(AsRef::<FixedCell>::as_ref(&cell).clone());
            let cell = RelayEnd::try_from_relay(&mut Some(cell), RelayVersion::V0).unwrap().unwrap();

            assert_eq!(cell.stream, stream);
            assert_eq!(cell.reason(), reason);

            let cell = cell.try_into_relay(NonZeroU32::new(1).unwrap(), RelayVersion::V0).unwrap();

            assert_relay_eq(&cell, &data);
        }

        #[test]
        fn test_end_truncated(n in 1..21usize) {
            let mut cell = Some(Relay::new(
                FixedCell::default(),
                NonZeroU32::new(1).unwrap(),
                RelayEnd::ID,
                1,
                &[4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0][..n],
            ));
            let cell = RelayEnd::try_from_relay(&mut cell, RelayVersion::V0).unwrap().unwrap();
            let reason = cell.reason();
            assert!(
                matches!(reason, EndReason::ExitPolicy(None | Some(ExitPolicy {
                    addr: IpAddr::V4(Ipv4Addr::UNSPECIFIED) | IpAddr::V6(Ipv6Addr::UNSPECIFIED),
                    ttl: 0 | u32::MAX,
                }))),
                "reason {reason:?} is not ExitPolicy",
            );
        }

        #[test]
        fn test_end_trailing_v6(n in 1..64usize) {
            let mut v = vec![4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
            v.extend(repeat_n(0, n));

            let mut cell = Some(Relay::new(
                FixedCell::default(),
                NonZeroU32::new(1).unwrap(),
                RelayEnd::ID,
                1,
                &v,
            ));
            drop(v);

            let cell = RelayEnd::try_from_relay(&mut cell, RelayVersion::V0).unwrap().unwrap();
            assert_eq!(
                cell.reason(),
                EndReason::ExitPolicy(Some(ExitPolicy {
                    addr: IpAddr::V6(Ipv6Addr::UNSPECIFIED),
                    ttl: 1,
                })),
            );
        }

        #[test]
        fn test_end_trailing_v4(n in 1..8usize) {
            let mut v = vec![4, 0, 0, 0, 0, 0, 0, 0, 1];
            v.extend(repeat_n(0, n));

            let mut cell = Some(Relay::new(
                FixedCell::default(),
                NonZeroU32::new(1).unwrap(),
                RelayEnd::ID,
                1,
                &v,
            ));
            drop(v);

            let cell = RelayEnd::try_from_relay(&mut cell, RelayVersion::V0).unwrap().unwrap();
            assert_eq!(
                cell.reason(),
                EndReason::ExitPolicy(Some(ExitPolicy {
                    addr: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
                    ttl: 1,
                })),
            );
        }
    }
}
