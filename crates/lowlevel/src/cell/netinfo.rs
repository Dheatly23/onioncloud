use std::mem::size_of;
use std::net::IpAddr;

use zerocopy::byteorder::big_endian::U32;
use zerocopy::{
    FromBytes, Immutable, IntoBytes, KnownLayout, SplitAt, Unaligned, transmute_mut, transmute_ref,
};

use super::{
    Cell, CellHeader, CellLike, CellRef, FIXED_CELL_SIZE, FixedCell, TryFromCell, to_fixed_with,
};
use crate::errors;

/// NETINFO header.
#[derive(FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned)]
#[repr(C)]
struct NetinfoHeader {
    /// Header part 1.
    header: NetinfoHeader1,

    /// Peer address content.
    peer_addr_data: NetinfoHeaderPeerAddr,
}

/// NETINFO header part 1.
#[derive(FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned)]
#[repr(C)]
struct NetinfoHeader1 {
    /// Timestamp sent by peer.
    timestamp: U32,

    /// Peer address type. Equivalent of [`Addr::ty`].
    peer_addr_ty: u8,
}

/// Size of header part 1 + peer addr length + header part 2.
const HSZ: usize = size_of::<NetinfoHeader1>() + 1 + size_of::<NetinfoHeader2<[u8; 0]>>();

macro_rules! netinfo_header_peeer_addr {
    ($($l:ident = $n:literal),* $(,)?) => {
        #[derive(FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned)]
        #[repr(u8)]
        // Variants must be declared, but not necessarily used.
        #[allow(dead_code)]
        enum NetinfoHeaderPeerAddr {
            // L0 is not in macro expansion because some funky macro interaction.
            L0([u8; 0], NetinfoHeader2<[u8; const { FIXED_CELL_SIZE - HSZ }]>) = 0,
            $($l([u8; $n], NetinfoHeader2<[u8; const { FIXED_CELL_SIZE - HSZ - $n }]>) = $n,)*
        }

        impl NetinfoHeaderPeerAddr {
            fn part2(&self) -> &NetinfoHeader2<[u8]> {
                match self {
                    Self::L0(_, v) => v,
                    $(Self::$l(_, v) => v,)*
                }
            }

            fn part2_mut(&mut self) -> &mut NetinfoHeader2<[u8]> {
                match self {
                    Self::L0(_, v) => v,
                    $(Self::$l(_, v) => v,)*
                }
            }
        }
    };
}

netinfo_header_peeer_addr! {
    L1 = 1, L2 = 2, L3 = 3, L4 = 4, L5 = 5, L6 = 6, L7 = 7, L8 = 8,
    L9 = 9, L10 = 10, L11 = 11, L12 = 12, L13 = 13, L14 = 14, L15 = 15, L16 = 16,
    L17 = 17, L18 = 18, L19 = 19, L20 = 20, L21 = 21, L22 = 22, L23 = 23, L24 = 24,
    L25 = 25, L26 = 26, L27 = 27, L28 = 28, L29 = 29, L30 = 30, L31 = 31, L32 = 32,
    L33 = 33, L34 = 34, L35 = 35, L36 = 36, L37 = 37, L38 = 38, L39 = 39, L40 = 40,
    L41 = 41, L42 = 42, L43 = 43, L44 = 44, L45 = 45, L46 = 46, L47 = 47, L48 = 48,
    L49 = 49, L50 = 50, L51 = 51, L52 = 52, L53 = 53, L54 = 54, L55 = 55, L56 = 56,
    L57 = 57, L58 = 58, L59 = 59, L60 = 60, L61 = 61, L62 = 62, L63 = 63, L64 = 64,
    L65 = 65, L66 = 66, L67 = 67, L68 = 68, L69 = 69, L70 = 70, L71 = 71, L72 = 72,
    L73 = 73, L74 = 74, L75 = 75, L76 = 76, L77 = 77, L78 = 78, L79 = 79, L80 = 80,
    L81 = 81, L82 = 82, L83 = 83, L84 = 84, L85 = 85, L86 = 86, L87 = 87, L88 = 88,
    L89 = 89, L90 = 90, L91 = 91, L92 = 92, L93 = 93, L94 = 94, L95 = 95, L96 = 96,
    L97 = 97, L98 = 98, L99 = 99, L100 = 100, L101 = 101, L102 = 102, L103 = 103, L104 = 104,
    L105 = 105, L106 = 106, L107 = 107, L108 = 108, L109 = 109, L110 = 110, L111 = 111, L112 = 112,
    L113 = 113, L114 = 114, L115 = 115, L116 = 116, L117 = 117, L118 = 118, L119 = 119, L120 = 120,
    L121 = 121, L122 = 122, L123 = 123, L124 = 124, L125 = 125, L126 = 126, L127 = 127, L128 = 128,
    L129 = 129, L130 = 130, L131 = 131, L132 = 132, L133 = 133, L134 = 134, L135 = 135, L136 = 136,
    L137 = 137, L138 = 138, L139 = 139, L140 = 140, L141 = 141, L142 = 142, L143 = 143, L144 = 144,
    L145 = 145, L146 = 146, L147 = 147, L148 = 148, L149 = 149, L150 = 150, L151 = 151, L152 = 152,
    L153 = 153, L154 = 154, L155 = 155, L156 = 156, L157 = 157, L158 = 158, L159 = 159, L160 = 160,
    L161 = 161, L162 = 162, L163 = 163, L164 = 164, L165 = 165, L166 = 166, L167 = 167, L168 = 168,
    L169 = 169, L170 = 170, L171 = 171, L172 = 172, L173 = 173, L174 = 174, L175 = 175, L176 = 176,
    L177 = 177, L178 = 178, L179 = 179, L180 = 180, L181 = 181, L182 = 182, L183 = 183, L184 = 184,
    L185 = 185, L186 = 186, L187 = 187, L188 = 188, L189 = 189, L190 = 190, L191 = 191, L192 = 192,
    L193 = 193, L194 = 194, L195 = 195, L196 = 196, L197 = 197, L198 = 198, L199 = 199, L200 = 200,
    L201 = 201, L202 = 202, L203 = 203, L204 = 204, L205 = 205, L206 = 206, L207 = 207, L208 = 208,
    L209 = 209, L210 = 210, L211 = 211, L212 = 212, L213 = 213, L214 = 214, L215 = 215, L216 = 216,
    L217 = 217, L218 = 218, L219 = 219, L220 = 220, L221 = 221, L222 = 222, L223 = 223, L224 = 224,
    L225 = 225, L226 = 226, L227 = 227, L228 = 228, L229 = 229, L230 = 230, L231 = 231, L232 = 232,
    L233 = 233, L234 = 234, L235 = 235, L236 = 236, L237 = 237, L238 = 238, L239 = 239, L240 = 240,
    L241 = 241, L242 = 242, L243 = 243, L244 = 244, L245 = 245, L246 = 246, L247 = 247, L248 = 248,
    L249 = 249, L250 = 250, L251 = 251, L252 = 252, L253 = 253, L254 = 254, L255 = 255,
}

/// NETINFO header part 2.
#[derive(FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned)]
#[repr(C)]
struct NetinfoHeader2<T: ?Sized = [u8]> {
    /// Number of this addresses.
    n_addrs: u8,

    /// Rest of the data.
    data: T,
}

/// Address type.
#[derive(FromBytes, IntoBytes, SplitAt, KnownLayout, Immutable, Unaligned)]
#[repr(C)]
struct Addr<T: ?Sized = [u8]> {
    /// Address type.
    ///
    /// Possible values:
    /// - 4 : IP version 4. Length must be 4 bytes.
    /// - 6 : IP version 6. Length must be 16 bytes.
    ty: u8,

    /// Length of payload.
    length: u8,

    /// Address payload.
    data: T,
}

impl Addr {
    fn split_data(&self) -> Option<(&Self, &[u8])> {
        Some(self.split_at(self.length.into())?.via_immutable())
    }
}

impl<T: ?Sized> Addr<T> {
    /// Converts into [`IpAddr`].
    ///
    /// NOTE: Payload length must be equal to length, use [`split_data`] to ensure it.
    #[track_caller]
    fn to_addr(&self) -> Option<IpAddr>
    where
        T: AsRef<[u8]>,
    {
        debug_assert_eq!(self.length as usize, self.data.as_ref().len());

        match (self.ty, self.length) {
            (4, 4) => Some(<[u8; 4]>::try_from(self.data.as_ref()).unwrap().into()),
            (6, 16) => Some(<[u8; 16]>::try_from(self.data.as_ref()).unwrap().into()),
            _ => None,
        }
    }
}

fn write_addr(data: &mut [u8], addr: IpAddr) -> Option<&mut [u8]> {
    Some(match addr {
        IpAddr::V4(v) => {
            let (o, rest) = Addr::<[u8; 4]>::mut_from_prefix(data).ok()?;
            *o = Addr {
                ty: 4,
                length: 4,
                data: v.octets(),
            };
            rest
        }
        IpAddr::V6(v) => {
            let (o, rest) = Addr::<[u8; 16]>::mut_from_prefix(data).ok()?;
            *o = Addr {
                ty: 6,
                length: 16,
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
    /// Data must be a valid NETINFO cell.
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
    /// # Example
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
        ) -> &mut NetinfoHeader2 {
            let header: &mut NetinfoHeader = transmute_mut!(data);
            header.header.timestamp.set(time);

            (header.header.peer_addr_ty, header.peer_addr_data) = match peer_addr {
                IpAddr::V4(v) => (
                    4,
                    NetinfoHeaderPeerAddr::L4(
                        v.octets(),
                        NetinfoHeader2 {
                            n_addrs: 0,
                            data: [0; const { FIXED_CELL_SIZE - HSZ - 4 }],
                        },
                    ),
                ),
                IpAddr::V6(v) => (
                    6,
                    NetinfoHeaderPeerAddr::L16(
                        v.octets(),
                        NetinfoHeader2 {
                            n_addrs: 0,
                            data: [0; const { FIXED_CELL_SIZE - HSZ - 16 }],
                        },
                    ),
                ),
            };
            header.peer_addr_data.part2_mut()
        }

        let header = write_header(cell.data_mut(), time, peer_addr);
        let mut data = &mut header.data;
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

        header.n_addrs = n;
        // SAFETY: Data is valid
        unsafe { Self::from_cell(cell) }
    }

    /// Gets timestamp.
    pub fn time(&self) -> u32 {
        let header: &NetinfoHeader = transmute_ref!(self.0.data());
        header.header.timestamp.get()
    }

    /// Gets peer IP address.
    ///
    /// Returns [`None`] if address is invalid.
    pub fn peer_addr(&self) -> Option<IpAddr> {
        let header: &NetinfoHeader = transmute_ref!(self.0.data());
        match *header {
            NetinfoHeader {
                header: NetinfoHeader1 {
                    peer_addr_ty: 4, ..
                },
                peer_addr_data: NetinfoHeaderPeerAddr::L4(a, _),
            } => Some(a.into()),
            NetinfoHeader {
                header: NetinfoHeader1 {
                    peer_addr_ty: 6, ..
                },
                peer_addr_data: NetinfoHeaderPeerAddr::L16(a, _),
                ..
            } => Some(a.into()),
            _ => None,
        }
    }

    /// Gets iterator to this IP addresses.
    ///
    /// Iterator skips over invalid address.
    ///
    /// # Example
    ///
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
        let NetinfoHeader {
            peer_addr_data: a, ..
        } = transmute_ref!(self.0.data());
        let &NetinfoHeader2 {
            n_addrs: n,
            ref data,
        } = a.part2();

        NetinfoThisAddrIterator { data, n, i: 0 }
    }

    /// Unwraps into inner [`FixedCell`].
    pub fn into_inner(self) -> FixedCell {
        self.0
    }

    fn check(data: &[u8; FIXED_CELL_SIZE]) -> bool {
        let NetinfoHeader {
            peer_addr_data: a, ..
        } = transmute_ref!(data);
        let header = a.part2();
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

            let mut v = Vec::new();
            v.extend_from_slice(&time.to_be_bytes());
            match other {
                IpAddr::V4(t) => v.extend([4, 4].into_iter().chain(t.octets())),
                IpAddr::V6(t) => v.extend([6, 16].into_iter().chain(t.octets())),
            }
            v.push(this.len() as u8);
            for a in &this {
                match a {
                    IpAddr::V4(t) => v.extend([4, 4].into_iter().chain(t.octets())),
                    IpAddr::V6(t) => v.extend([6, 16].into_iter().chain(t.octets())),
                }
            }

            assert_eq!(&cell.into_inner().data()[..v.len()], v);
        }

        #[test]
        fn test_netinfo_well_formed(
            peer_addr_ty: u8,
            peer_addr_len: u8,
            this_addrs in vec((any::<u8>(), any::<u8>()), 0..32),
        ) {
            let mut cell = FixedCell::default();

            let mut data = &mut cell.data_mut()[4..];
            data[0] = peer_addr_ty;
            data[1] = peer_addr_len;
            let n_addrs;
            (n_addrs, data) = data[peer_addr_len as usize + 2..].split_first_mut().unwrap();
            let mut valid_addrs = 0;
            for (ty, len) in this_addrs {
                let Some((a, b)) = data.split_at_mut_checked(len as usize + 2) else {
                    break;
                };
                a[0] = ty;
                a[1] = len;
                *n_addrs += 1;
                data = b;
                if matches!((ty, len), (4, 4) | (6, 16)) {
                    valid_addrs += 1;
                }
            }

            assert!(Netinfo::check(cell.data()));
            // SAFETY: check has been asserted
            let cell = unsafe { Netinfo::from_cell(cell) };
            assert_eq!(cell.peer_addr().is_some(), matches!((peer_addr_ty, peer_addr_len), (4, 4) | (6, 16)));
            assert_eq!(cell.this_addrs().count(), valid_addrs);
        }
    }
}
