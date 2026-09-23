//! `END` relay cell.

use std::net::IpAddr;
use std::num::NonZeroU16;

use onioncloud_ll_cell::fixed::FixedCell;
use zerocopy::byteorder::big_endian::U32;
use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout, Unaligned, transmute_ref};

use crate::AutoReturnCell;
use crate::error::{CellCastError, CellFormatError, ZeroStreamID};
use crate::traits::{DynRelayVersion, TryFromRelay};
use crate::v0::V0;
use crate::v1::V1;

#[derive(FromBytes, IntoBytes, Immutable, KnownLayout, Unaligned)]
#[repr(C)]
struct EndReasonExitPolicyV4 {
    reason: u8,
    ip: [u8; 4],
    ttl: U32,
}

#[derive(FromBytes, IntoBytes, Immutable, KnownLayout, Unaligned)]
#[repr(C)]
struct EndReasonExitPolicyV6 {
    reason: u8,
    ip: [u8; 16],
    ttl: U32,
}

/// `END` relay cell.
pub struct End<V = V0> {
    stream_id: NonZeroU16,
    cell: FixedCell,
    version: V,
}

impl<V: DynRelayVersion> TryFromRelay<V> for End<V> {
    type Error = CellCastError;

    fn try_from_relay_versioned(
        version: V,
        cell: &mut Option<FixedCell>,
    ) -> Result<Option<Self>, Self::Error> {
        let Some(cell) = AutoReturnCell::new(cell) else {
            return Ok(None);
        };
        let c = cell.cell();
        if version.command(c) != Self::ID {
            return Ok(None);
        }
        let stream_id = NonZeroU16::new(version.stream_id(c)).ok_or(ZeroStreamID)?;
        version
            .data_checked(c)
            .ok_or_else(CellFormatError::default)?;
        Ok(Some(Self {
            stream_id,
            cell: cell.into_inner(),
            version,
        }))
    }
}

impl<V> From<End<V>> for FixedCell {
    #[inline]
    fn from(v: End<V>) -> FixedCell {
        v.into_inner()
    }
}

impl End<V0> {
    /// Create new [`End`] with relay version 0 and end reason.
    #[inline]
    #[must_use]
    pub fn with_reason_v0(cell: FixedCell, stream_id: NonZeroU16, reason: EndReason) -> Self {
        Self::with_reason(cell, V0, stream_id, reason)
    }

    /// Create new [`End`] with relay version 0.
    #[inline]
    #[must_use]
    pub fn without_reason_v0(cell: FixedCell, stream_id: NonZeroU16) -> Self {
        Self::without_reason(cell, V0, stream_id)
    }
}

impl End<V1> {
    /// Create new [`End`] with relay version 1 and end reason.
    #[inline]
    #[must_use]
    pub fn with_reason_v1(cell: FixedCell, stream_id: NonZeroU16, reason: EndReason) -> Self {
        Self::with_reason(cell, V1, stream_id, reason)
    }

    /// Create new [`End`] with relay version 1.
    #[inline]
    #[must_use]
    pub fn without_reason_v1(cell: FixedCell, stream_id: NonZeroU16) -> Self {
        Self::without_reason(cell, V1, stream_id)
    }
}

impl<V: DynRelayVersion> End<V> {
    /// Create new [`End`] with end reason.
    #[must_use]
    pub fn with_reason(
        mut cell: FixedCell,
        version: V,
        stream_id: NonZeroU16,
        reason: EndReason,
    ) -> Self {
        let data = version.data_padding_mut(&mut cell);
        match reason {
            EndReason::Exitpolicy(Some(ExitPolicyData {
                ip: IpAddr::V4(ip),
                ttl,
            })) => {
                let s = EndReasonExitPolicyV4 {
                    reason: 4,
                    ip: ip.octets(),
                    ttl: U32::new(ttl),
                };
                let s = s.as_bytes();
                data[..s.len()].copy_from_slice(s);
                version.set_len(&mut cell, s.len().try_into().unwrap());
            }
            EndReason::Exitpolicy(Some(ExitPolicyData {
                ip: IpAddr::V6(ip),
                ttl,
            })) => {
                let s = EndReasonExitPolicyV6 {
                    reason: 4,
                    ip: ip.octets(),
                    ttl: U32::new(ttl),
                };
                let s = s.as_bytes();
                data[..s.len()].copy_from_slice(s);
                version.set_len(&mut cell, s.len().try_into().unwrap());
            }
            r => {
                data[0] = r.as_u8();
                version.set_len(&mut cell, 1);
            }
        }

        version.set_command(&mut cell, Self::ID);
        version.set_stream_id(&mut cell, stream_id.into());
        Self {
            stream_id,
            cell,
            version,
        }
    }

    /// Create new [`End`] without end reason.
    #[must_use]
    pub fn without_reason(mut cell: FixedCell, version: V, stream_id: NonZeroU16) -> Self {
        version.set_len(&mut cell, 0);
        version.set_command(&mut cell, Self::ID);
        version.set_stream_id(&mut cell, stream_id.into());
        Self {
            stream_id,
            cell,
            version,
        }
    }

    /// Gets end reason.
    ///
    /// Returns [`None`] if no end reason given or unknown end reason.
    #[inline]
    #[must_use]
    pub fn reason(&self) -> Option<EndReason> {
        let [r, s @ ..] = self.version.data(&self.cell) else {
            return None;
        };
        let mut s = s;
        let mut reason = EndReason::try_from(*r).ok()?;
        if let EndReason::Exitpolicy(ref mut data) = reason {
            let ip = if let Some((a, r)) = s.split_first_chunk::<16>() {
                s = r;
                Some(IpAddr::from(*a))
            } else if let Some((a, r)) = s.split_first_chunk::<4>() {
                s = r;
                Some(IpAddr::from(*a))
            } else {
                None
            };
            if let Some(ip) = ip {
                let ttl = if let Some((a, _)) = s.split_first_chunk::<4>() {
                    let v: &U32 = transmute_ref!(a);
                    v.get()
                } else {
                    u32::MAX
                };
                *data = Some(ExitPolicyData { ip, ttl });
            }
        }
        Some(reason)
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
}

impl<V> End<V> {
    /// `END` relay ID.
    pub const ID: u8 = 3;

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

/// End reasons.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum EndReason {
    /// Catch-all for unlisted reasons.
    Misc,
    /// Couldn't look up hostname.
    Resolvefailed,
    /// Remote host refused connection.
    Connectrefused,
    /// Relay refuses to connect to host or port.
    Exitpolicy(Option<ExitPolicyData>),
    /// Circuit is being destroyed.
    Destroy,
    /// Anonymized TCP connection was closed.
    Done,
    /// Connection timed out, or relay timed out while connecting.
    Timeout,
    /// Routing error while attempting to contact destination.
    Noroute,
    /// Relay is temporarily hibernating.
    Hibernating,
    /// Internal error at the relay.
    Internal,
    /// Relay has no resources to fulfill request.
    Resourcelimit,
    /// Connection was unexpectedly reset.
    Connreset,
    /// Sent when closing connection because of Tor protocol violations.
    Torprotocol,
    /// Client sent `RELAY_BEGIN_DIR` to a non-directory relay.
    Notdirectory,
}

/// Cast end reason ID into [`EndReason`].
///
/// Passes through ID if it does not correspond to any known ID.
impl TryFrom<u8> for EndReason {
    type Error = u8;

    fn try_from(v: u8) -> Result<Self, u8> {
        match v {
            1 => Ok(Self::Misc),
            2 => Ok(Self::Resolvefailed),
            3 => Ok(Self::Connectrefused),
            4 => Ok(Self::Exitpolicy(None)),
            5 => Ok(Self::Destroy),
            6 => Ok(Self::Done),
            7 => Ok(Self::Timeout),
            8 => Ok(Self::Noroute),
            9 => Ok(Self::Hibernating),
            10 => Ok(Self::Internal),
            11 => Ok(Self::Resourcelimit),
            12 => Ok(Self::Connreset),
            13 => Ok(Self::Torprotocol),
            14 => Ok(Self::Notdirectory),
            v => Err(v),
        }
    }
}

impl EndReason {
    /// Gets end reason ID.
    #[inline]
    #[must_use]
    pub fn as_u8(&self) -> u8 {
        match self {
            Self::Misc => 1,
            Self::Resolvefailed => 2,
            Self::Connectrefused => 3,
            Self::Exitpolicy(_) => 4,
            Self::Destroy => 5,
            Self::Done => 6,
            Self::Timeout => 7,
            Self::Noroute => 8,
            Self::Hibernating => 9,
            Self::Internal => 10,
            Self::Resourcelimit => 11,
            Self::Connreset => 12,
            Self::Torprotocol => 13,
            Self::Notdirectory => 14,
        }
    }
}

/// Exit policy end data.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct ExitPolicyData {
    /// IP Address.
    pub ip: IpAddr,
    /// Time-to-live.
    pub ttl: u32,
}

impl Default for ExitPolicyData {
    fn default() -> Self {
        Self {
            ip: IpAddr::V4([0; 4].into()),
            ttl: 0,
        }
    }
}

impl ExitPolicyData {
    /// Sets IP address.
    #[must_use]
    pub fn with_ip(mut self, ip: IpAddr) -> Self {
        self.ip = ip;
        self
    }

    /// Sets TTL.
    #[must_use]
    pub fn with_ttl(mut self, ttl: u32) -> Self {
        self.ttl = ttl;
        self
    }
}
