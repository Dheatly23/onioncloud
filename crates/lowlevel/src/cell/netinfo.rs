use std::net::IpAddr;

use zerocopy::byteorder::big_endian::U32;
use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout, SplitAt, Unaligned};

use super::{
    Cell, CellHeader, CellLike, CellRef, FIXED_CELL_SIZE, FixedCell, TryFromCell, to_fixed_with,
};
use crate::errors;

/// NETINFO header part 1.
#[derive(FromBytes, KnownLayout, Immutable, Unaligned)]
#[repr(C)]
struct NetinfoHeader1 {
    /// Timestamp sent by peer.
    timestamp: U32,

    /// Peer address. Also contains [`NetinfoHeader2`].
    peer_addr: Addr,
}

/// NETINFO header part 2.
#[derive(FromBytes, KnownLayout, Immutable, Unaligned)]
#[repr(C)]
struct NetinfoHeader2 {
    /// Number of this addresses.
    n_addrs: u8,

    /// Rest of the data.
    data: [u8],
}

/// Address header.
#[derive(FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned)]
#[repr(C)]
struct AddrHeader {
    /// Address type.
    ///
    /// Possible values:
    /// - 4 : IP version 4. Length must be 4 bytes.
    /// - 6 : IP version 6. Length must be 16 bytes.
    ty: u8,

    /// Length of payload.
    length: u8,
}

/// Address type.
#[derive(FromBytes, SplitAt, KnownLayout, Immutable, Unaligned)]
#[repr(C)]
struct Addr {
    /// Address header.
    header: AddrHeader,

    /// Address payload.
    data: [u8],
}

impl Addr {
    fn split_data(&self) -> Option<(&Self, &[u8])> {
        Some(self.split_at(self.header.length.into())?.via_immutable())
    }

    /// Converts into [`IpAddr`].
    ///
    /// NOTE: Payload length must be equal to length, use [`split_data`] to ensure it.
    #[track_caller]
    fn to_addr(&self) -> Option<IpAddr> {
        debug_assert_eq!(self.header.length as usize, self.data.len());

        match (self.header.ty, self.header.length) {
            (4, 4) => Some(<[u8; 4]>::try_from(&self.data).unwrap().into()),
            (6, 16) => Some(<[u8; 16]>::try_from(&self.data).unwrap().into()),
            _ => None,
        }
    }
}

#[derive(FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned)]
#[repr(C)]
struct AddrV4 {
    header: AddrHeader,
    data: [u8; 4],
}

#[derive(FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned)]
#[repr(C)]
struct AddrV6 {
    header: AddrHeader,
    data: [u8; 16],
}

fn write_addr(data: &mut [u8], addr: IpAddr) -> Option<&mut [u8]> {
    Some(match addr {
        IpAddr::V4(v) => {
            let (o, rest) = AddrV4::mut_from_prefix(data).ok()?;
            *o = AddrV4 {
                header: AddrHeader { ty: 4, length: 4 },
                data: v.octets(),
            };
            rest
        }
        IpAddr::V6(v) => {
            let (o, rest) = AddrV6::mut_from_prefix(data).ok()?;
            *o = AddrV6 {
                header: AddrHeader { ty: 6, length: 16 },
                data: v.octets(),
            };
            rest
        }
    })
}

/// Represents a NETINFO cell.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Netinfo(FixedCell);

impl From<Netinfo> for Cell {
    fn from(v: Netinfo) -> Cell {
        Cell::from_fixed(CellHeader::new(0, Netinfo::ID), v.into_inner())
    }
}

impl From<Netinfo> for FixedCell {
    fn from(v: Netinfo) -> FixedCell {
        v.into_inner()
    }
}

impl TryFromCell for Netinfo {
    fn try_from_cell(cell: &mut Option<Cell>) -> Result<Option<Self>, errors::CellFormatError> {
        let Some(
            c @ Cell {
                command: Self::ID, ..
            },
        ) = cell.as_ref()
        else {
            return Ok(None);
        };
        if c.circuit != 0 {
            return Err(errors::CellFormatError);
        }
        to_fixed_with(cell, Self::check).map(|v| v.map(|v| unsafe { Self::from_cell(v) }))
    }
}

impl CellLike for Netinfo {
    fn circuit(&self) -> u32 {
        0
    }

    fn command(&self) -> u8 {
        Self::ID
    }

    fn cell(&self) -> CellRef<'_> {
        CellRef::Fixed(&self.0)
    }
}

impl Netinfo {
    /// NETINFO command ID.
    pub const ID: u8 = 8;

    /// Creates new NETINFO cell from existing [`FixedCell`].
    ///
    /// # Safety
    ///
    /// Data must be a 2-byte array of [`U16`].
    pub unsafe fn from_cell(data: FixedCell) -> Self {
        debug_assert!(Self::check(data.data()));
        Self(data)
    }

    /// Creates new NETINFO cell.
    ///
    /// # Parameters
    ///
    /// - `cell` : Cached [`FixedCell`].
    /// - `time` : Timestamp.
    /// - `peer_addr` : Peer IP address.
    /// - `this_addr` : This IP addresses. Excessive addresses will be discared.
    ///
    /// ```
    /// use onioncloud_lowlevel::cell::FixedCell;
    /// use onioncloud_lowlevel::cell::netinfo::Netinfo;
    ///
    /// let cell = Netinfo::new(FixedCell::default(), 0, [0; 4].into(), []);
    /// ```
    pub fn new(
        mut cell: FixedCell,
        time: u32,
        peer_addr: IpAddr,
        this_addr: impl IntoIterator<Item = IpAddr>,
    ) -> Self {
        fn write_header(
            data: &mut [u8; FIXED_CELL_SIZE],
            time: u32,
            peer_addr: IpAddr,
        ) -> (&mut u8, &mut [u8]) {
            // Cannot use NetinfoHeader1 because of IntoBytes limitation.
            let (t, data) = U32::mut_from_prefix(data).expect("data must fit header");
            t.set(time);
            write_addr(data, peer_addr)
                .expect("data must fit header")
                .split_first_mut()
                .expect("data must fit header")
        }

        let (np, mut data) = write_header(cell.data_mut(), time, peer_addr);
        let mut n = 0u8;
        for addr in this_addr {
            let Some(s) = write_addr(data, addr) else {
                break;
            };
            data = s;

            n = match n.checked_add(1) {
                Some(v) => v,
                // Should be unlikely, but better be safe
                None => break,
            };
        }

        *np = n;
        // SAFETY: Data is valid
        unsafe { Self::from_cell(cell) }
    }

    /// Gets timestamp.
    pub fn time(&self) -> u32 {
        NetinfoHeader1::ref_from_bytes(self.0.data())
            .expect("data must fit header")
            .timestamp
            .get()
    }

    /// Gets peer IP address.
    ///
    /// Returns [`None`] if address is invalid.
    pub fn peer_addr(&self) -> Option<IpAddr> {
        NetinfoHeader1::ref_from_bytes(self.0.data())
            .expect("data must fit header")
            .peer_addr
            .split_data()
            .expect("data must fit header")
            .0
            .to_addr()
    }

    /// Gets iterator to this IP addresses.
    ///
    /// Iterator skips over invalid address.
    /// ```
    /// use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
    ///
    /// use onioncloud_lowlevel::cell::FixedCell;
    /// use onioncloud_lowlevel::cell::netinfo::Netinfo;
    ///
    /// let cell = Netinfo::new(FixedCell::default(), 0, [0; 4].into(), [Ipv4Addr::LOCALHOST.into(), Ipv6Addr::LOCALHOST.into()]);
    /// for addr in cell.this_addrs() {
    ///     println!("{addr}");
    /// }
    /// ```
    pub fn this_addrs(&self) -> NetinfoThisAddrIterator<'_> {
        let &NetinfoHeader2 {
            n_addrs: n,
            ref data,
        } = NetinfoHeader2::ref_from_bytes(
            NetinfoHeader1::ref_from_bytes(self.0.data())
                .expect("data must fit header")
                .peer_addr
                .split_data()
                .expect("data must fit header")
                .1,
        )
        .expect("data must fit header");

        NetinfoThisAddrIterator { data, n, i: 0 }
    }

    /// Unwraps into inner [`FixedCell`].
    pub fn into_inner(self) -> FixedCell {
        self.0
    }

    fn check(data: &[u8; FIXED_CELL_SIZE]) -> bool {
        // Use expect() because maximum size of header is
        // 4 (timestamp) + 2 (peer address header) + 255 (peer address payload) + 1 (number of this addresses) = 262 < FIXED_CELL_SIZE
        debug_assert!(262 < FIXED_CELL_SIZE, "fixed cell size is too small");
        let header = NetinfoHeader2::ref_from_bytes(
            NetinfoHeader1::ref_from_bytes(data)
                .expect("data must fit header")
                .peer_addr
                .split_data()
                .expect("data must fit header")
                .1,
        )
        .expect("data must fit header");
        let mut data = &header.data;

        for _ in 0..header.n_addrs {
            let Some((_, s)) = Addr::ref_from_bytes(data).ok().and_then(|v| v.split_data()) else {
                return false;
            };
            data = s;
        }

        true
    }
}

/// Iterator for [`Netinfo`].
///
/// Iterates over this addresses. Skips over invalid address.
pub struct NetinfoThisAddrIterator<'a> {
    data: &'a [u8],
    n: u8,
    i: u8,
}

impl Iterator for NetinfoThisAddrIterator<'_> {
    type Item = IpAddr;

    fn next(&mut self) -> Option<Self::Item> {
        debug_assert!(self.i <= self.n);

        while self.i < self.n {
            self.i += 1;

            let (addr, rest) = Addr::ref_from_bytes(self.data)
                .expect("data must be valid")
                .split_data()
                .expect("data must be valid");
            self.data = rest;
            if let r @ Some(_) = addr.to_addr() {
                return r;
            }
        }

        None
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        (0, Some((self.n - self.i).into()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::iter::repeat;
    use std::net::Ipv4Addr;

    use proptest::collection::vec;
    use proptest::prelude::*;

    fn netinfo_strat() -> impl Strategy<Value = (u32, IpAddr, Vec<IpAddr>)> {
        (any::<u32>(), any::<IpAddr>(), vec(any::<IpAddr>(), 0..4))
    }

    #[test]
    fn test_netinfo_too_many() {
        let cell = Netinfo::new(
            FixedCell::default(),
            0,
            Ipv4Addr::UNSPECIFIED.into(),
            repeat(Ipv4Addr::UNSPECIFIED.into()),
        );

        // 1000 should be way too many
        assert!(cell.this_addrs().count() < 1000);
    }

    proptest! {
        #[test]
        fn test_netinfo_new((time, other, this) in netinfo_strat()) {
            let cell = Netinfo::new(
                FixedCell::default(),
                time,
                other,
                this.iter().copied(),
            );

            assert_eq!(cell.time(), time);
            assert_eq!(cell.peer_addr(), Some(other));
            assert_eq!(cell.this_addrs().collect::<Vec<_>>(), this);
        }
    }
}
