use std::fmt::{Debug, Formatter, Result as FmtResult};
use std::num::{NonZeroU16, NonZeroU32};
use std::ptr::{from_ref, null};
use std::slice::from_raw_parts;
use std::str::{from_utf8, from_utf8_unchecked};

use memchr::memchr;
use zerocopy::byteorder::big_endian::U32;
use zerocopy::{FromBytes, transmute_mut};

use super::{IntoRelay, Relay, RelayLike, RelayWrapper, TryFromRelay, with_cmd_stream};
use crate::cell::FixedCell;
use crate::errors;

/// Represents a RELAY_BEGIN cell.
pub struct RelayBegin {
    pub stream: NonZeroU16,
    data: RelayWrapper,

    // Auxiliary pointers for speedup access.
    // Use usize because stacked borrows prevent us from using regular pointer.
    p_addr_port_s: usize,
    p_flags: usize,
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

impl Clone for RelayBegin {
    fn clone(&self) -> Self {
        let data = self.data.clone();

        // Get offset between two pointers
        // Don't use byte_offset() because pointers are in different allocations
        let p = from_ref(data.data_padding());
        let off = p
            .addr()
            .wrapping_sub(self.data.data_padding().as_ptr().addr());

        Self {
            stream: self.stream,
            data,
            p_addr_port_s: self.p_addr_port_s,
            p_flags: self.p_flags.wrapping_add(off),
        }
    }
}

impl AsRef<FixedCell> for RelayBegin {
    fn as_ref(&self) -> &FixedCell {
        self.data.as_ref()
    }
}

impl TryFromRelay for RelayBegin {
    fn try_from_relay(relay: &mut Option<Relay>) -> Result<Option<Self>, errors::CellFormatError> {
        let Some(r) = relay.take() else {
            return Ok(None);
        };
        let Some((stream, p_addr_port_s, p_flags)) =
            Self::check(AsRef::<FixedCell>::as_ref(&r).into())
        else {
            *relay = Some(r);
            return Err(errors::CellFormatError);
        };
        Ok(Some(Self {
            stream,
            data: FixedCell::from(r).into(),
            p_addr_port_s,
            p_flags,
        }))
    }
}

impl IntoRelay for RelayBegin {
    fn into_relay(self, circuit: NonZeroU32) -> Relay {
        with_cmd_stream(self.data, Self::ID, self.stream.into(), circuit)
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
    pub unsafe fn from_cell(cell: FixedCell) -> Self {
        let data = RelayWrapper::from(cell);
        let (stream, p_addr_port_s, p_flags) = Self::check(&data).expect("malformed cell format");

        Self {
            stream,
            data,
            p_addr_port_s,
            p_flags,
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
    /// # Panics
    ///
    /// Panics if `data` is longer than [`RELAY_DATA_LENGTH`].
    pub fn new(cell: FixedCell, stream: NonZeroU16, addr_port: &str, flags: u32) -> Self {
        assert_eq!(
            chr_nul(addr_port.as_bytes()),
            None,
            "address/port contains NUL byte"
        );

        let mut data = RelayWrapper::from(cell);
        let b = data.data_padding_mut();
        let l = addr_port.len();
        b[..l].copy_from_slice(addr_port.as_bytes());
        b[l] = 0;

        let (p_flags, sz) = if flags != 0 {
            let p: &mut U32 =
                transmute_mut!(<&mut [u8; 4]>::try_from(&mut b[l + 1..l + 5]).unwrap());
            p.set(flags);

            (from_ref(p), l + 5)
        } else {
            (null(), l + 1)
        };

        // SAFETY: Payload length is valid.
        unsafe {
            data.set_len(sz as u16);
        }

        if cfg!(debug_assertions) {
            data.set_stream(stream.into());
            data.set_command(Self::ID);
            debug_assert_eq!(Self::check(&data), Some((stream, l, p_flags.addr())));
        }

        Self {
            stream,
            p_addr_port_s: l,
            p_flags: p_flags.addr(),
            data,
        }
    }

    /// Get address and port.
    ///
    /// The format is `addr:port`.
    pub fn addr_port(&self) -> &str {
        self.get_data().0
    }

    /// Get flags.
    pub fn flags(&self) -> u32 {
        self.get_data().1.map(|v| v.get()).unwrap_or_default()
    }

    fn check(cell: &RelayWrapper) -> Option<(NonZeroU16, usize, usize)> {
        if cell.command() != Self::ID {
            return None;
        }
        let stream = NonZeroU16::new(cell.stream())?;

        let data = cell.data();
        let (s, [0, data @ ..]) = chr_nul(data).map(|i| data.split_at(i))? else {
            return None;
        };
        let flags = if data.is_empty() {
            None
        } else {
            let flags = U32::ref_from_bytes(data).ok()?;
            // TODO: Check flags.
            Some(flags)
        };

        let s = from_utf8(s).ok()?;
        // TODO: Check if string content is valid.

        Some((stream, s.len(), flags.map_or(0, |p| from_ref(p).addr())))
    }

    fn get_data(&self) -> (&str, Option<&U32>) {
        // SAFETY: Data validity has been checked.
        unsafe {
            let p = self.data.data_padding();
            (
                from_utf8_unchecked(p.get_unchecked(..self.p_addr_port_s)),
                if self.p_flags == 0 {
                    None
                } else {
                    Some(&*from_ref(p).with_addr(self.p_flags).cast())
                },
            )
        }
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

    use proptest::prelude::*;

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

    proptest! {
        //#![proptest_config(ProptestConfig::with_cases(10))]

        #[test]
        fn test_begin_new(
            (addr_port, flags, stream) in strat(),
        ) {
            let cell = RelayBegin::new(FixedCell::default(), stream, &addr_port, flags);

            assert_eq!(cell.stream, stream);
            assert_eq!(cell.addr_port(), addr_port);
            assert_eq!(cell.flags(), flags);
        }

        #[test]
        fn test_begin_clone(
            (addr_port, flags, stream) in strat(),
        ) {
            let cell = RelayBegin::new(FixedCell::default(), stream, &addr_port, flags);
            drop(addr_port);
            let target = cell.clone();

            assert_eq!(cell.stream, target.stream);
            assert_eq!(cell.addr_port(), target.addr_port());
            assert_eq!(cell.flags(), target.flags());
        }

        #[test]
        fn test_begin_from_relay(
            (addr_port, flags, stream) in strat(),
        ) {
            let mut v = Vec::new();
            v.extend_from_slice(addr_port.as_bytes());
            v.push(0);
            if flags != 0 {
                v.extend_from_slice(&flags.to_be_bytes());
            }

            let mut cell = Some(Relay::new(FixedCell::default(), NonZeroU32::new(1).unwrap(), RelayBegin::ID, stream.into(),&v));
            drop(v);
            let cell = RelayBegin::try_from_relay(&mut cell).unwrap().unwrap();

            assert_eq!(cell.stream, stream);
            assert_eq!(cell.addr_port(), addr_port);
            assert_eq!(cell.flags(), flags);
        }
    }
}
