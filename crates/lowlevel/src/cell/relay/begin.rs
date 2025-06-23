use std::fmt::{Debug, Formatter, Result as FmtResult};
use std::num::{NonZeroU16, NonZeroU32};
use std::ptr::{NonNull, null};
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
    p_addr_port: NonNull<str>,
    p_flags: *const U32,
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

// SAFETY: Pointers target are stable.
unsafe impl Send for RelayBegin {}
unsafe impl Sync for RelayBegin {}

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
        let Some((stream, p_addr_port, p_flags)) =
            Self::check(AsRef::<FixedCell>::as_ref(&r).into())
        else {
            *relay = Some(r);
            return Err(errors::CellFormatError);
        };
        Ok(Some(Self {
            stream,
            data: FixedCell::from(r).into(),
            p_addr_port,
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
        let (stream, p_addr_port, p_flags) = Self::check(&data).expect("malformed cell format");

        Self {
            stream,
            data,
            p_addr_port,
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

        let (p_addr_port, p_flags);

        let mut data = RelayWrapper::from(cell);
        let b = data.data_padding_mut();
        let l = addr_port.len();
        b[..l].copy_from_slice(addr_port.as_bytes());
        b[l] = 0;

        // SAFETY: Pointer points to data's content
        p_addr_port = unsafe { NonNull::from(from_utf8_unchecked(&b[..l])) };

        if flags != 0 {
            let p: &mut U32 =
                transmute_mut!(<&mut [u8; 4]>::try_from(&mut b[l + 1..l + 5]).unwrap());
            p.set(flags);
            p_flags = p as *const U32;

            // SAFETY: Payload length is valid.
            unsafe {
                data.set_len((l + 5) as u16);
            }
        } else {
            p_flags = null();

            // SAFETY: Payload length is valid.
            unsafe {
                data.set_len((l + 1) as u16);
            }
        }

        debug_assert_eq!(Self::check(&data), Some((stream, p_addr_port, p_flags)));

        Self {
            stream,
            data,
            p_addr_port,
            p_flags,
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

    fn check(cell: &RelayWrapper) -> Option<(NonZeroU16, NonNull<str>, *const U32)> {
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

        Some((stream, s.into(), flags.map_or_else(null, |v| v as _)))
    }

    fn get_data(&self) -> (&str, Option<&U32>) {
        // SAFETY: Data validity has been checked.
        unsafe {
            (
                self.p_addr_port.as_ref(),
                if self.p_flags.is_null() {
                    None
                } else {
                    Some(&*self.p_flags)
                },
            )
        }
    }
}

#[inline]
fn chr_nul(s: &[u8]) -> Option<usize> {
    memchr(0, s)
}
