//! `NETINFO` cell type.

use std::fmt::{Debug, Formatter, Result as FmtResult, from_fn};
use std::mem::size_of;
use std::net::IpAddr;
use std::ptr::from_ref;

use zerocopy::byteorder::big_endian::U32;
use zerocopy::{
    FromBytes, Immutable, IntoBytes, KnownLayout, SplitAt, Unaligned, transmute_mut, transmute_ref,
};

use crate::cell::{AutoReturnFixed, Cell, CellHeader, TryFromCell};
use crate::error::{CellCastError, CellFormatError, NonZeroCircID};
use crate::fixed::{FIXED_CELL_SIZE, FixedCell};

/// `NETINFO` cell header.
#[derive(FromBytes, IntoBytes, Immutable, KnownLayout, Unaligned)]
#[repr(C)]
struct NetinfoHeader {
    timestamp: U32,
    ty: u8,
}

/// `NETINFO` cell value.
#[derive(FromBytes, IntoBytes, Immutable, KnownLayout, Unaligned)]
#[repr(C)]
struct NetinfoData {
    header: NetinfoHeader,
    data: NetinfoPayload,
}

macro_rules! netinfopayload {
    ($($l:ident = $v:tt),+ $(,)?) => {
        #[allow(dead_code)]
        #[derive(FromBytes, IntoBytes, Immutable, KnownLayout, Unaligned)]
        #[repr(u8)]
        enum NetinfoPayload {
            $($l([u8; $v], [u8; const { FIXED_CELL_SIZE - size_of::<NetinfoHeader>() - 1 - $v }]) = $v,)+
        }

        impl NetinfoPayload {
            #[inline(always)]
            const fn data(&self) -> &[u8] {
                match self {
                    $(Self::$l(s, _) => s,)*
                }
            }

            #[inline(always)]
            const fn rest(&self) -> (&u8, &[u8]) {
                match self {
                    $(Self::$l(_, [b, s @ ..]) => (b, s),)*
                }
            }

            #[inline(always)]
            const fn rest_mut(&mut self) -> (&mut u8, &mut [u8]) {
                match self {
                    $(Self::$l(_, [b, s @ ..]) => (b, s),)*
                }
            }
        }
    };
}

netinfopayload! {
    L0 = 0, L1 = 1, L2 = 2, L3 = 3, L4 = 4, L5 = 5, L6 = 6, L7 = 7,
    L8 = 8, L9 = 9, L10 = 10, L11 = 11, L12 = 12, L13 = 13, L14 = 14, L15 = 15,
    L16 = 16, L17 = 17, L18 = 18, L19 = 19, L20 = 20, L21 = 21, L22 = 22, L23 = 23,
    L24 = 24, L25 = 25, L26 = 26, L27 = 27, L28 = 28, L29 = 29, L30 = 30, L31 = 31,
    L32 = 32, L33 = 33, L34 = 34, L35 = 35, L36 = 36, L37 = 37, L38 = 38, L39 = 39,
    L40 = 40, L41 = 41, L42 = 42, L43 = 43, L44 = 44, L45 = 45, L46 = 46, L47 = 47,
    L48 = 48, L49 = 49, L50 = 50, L51 = 51, L52 = 52, L53 = 53, L54 = 54, L55 = 55,
    L56 = 56, L57 = 57, L58 = 58, L59 = 59, L60 = 60, L61 = 61, L62 = 62, L63 = 63,
    L64 = 64, L65 = 65, L66 = 66, L67 = 67, L68 = 68, L69 = 69, L70 = 70, L71 = 71,
    L72 = 72, L73 = 73, L74 = 74, L75 = 75, L76 = 76, L77 = 77, L78 = 78, L79 = 79,
    L80 = 80, L81 = 81, L82 = 82, L83 = 83, L84 = 84, L85 = 85, L86 = 86, L87 = 87,
    L88 = 88, L89 = 89, L90 = 90, L91 = 91, L92 = 92, L93 = 93, L94 = 94, L95 = 95,
    L96 = 96, L97 = 97, L98 = 98, L99 = 99, L100 = 100, L101 = 101, L102 = 102, L103 = 103,
    L104 = 104, L105 = 105, L106 = 106, L107 = 107, L108 = 108, L109 = 109, L110 = 110, L111 = 111,
    L112 = 112, L113 = 113, L114 = 114, L115 = 115, L116 = 116, L117 = 117, L118 = 118, L119 = 119,
    L120 = 120, L121 = 121, L122 = 122, L123 = 123, L124 = 124, L125 = 125, L126 = 126, L127 = 127,
    L128 = 128, L129 = 129, L130 = 130, L131 = 131, L132 = 132, L133 = 133, L134 = 134, L135 = 135,
    L136 = 136, L137 = 137, L138 = 138, L139 = 139, L140 = 140, L141 = 141, L142 = 142, L143 = 143,
    L144 = 144, L145 = 145, L146 = 146, L147 = 147, L148 = 148, L149 = 149, L150 = 150, L151 = 151,
    L152 = 152, L153 = 153, L154 = 154, L155 = 155, L156 = 156, L157 = 157, L158 = 158, L159 = 159,
    L160 = 160, L161 = 161, L162 = 162, L163 = 163, L164 = 164, L165 = 165, L166 = 166, L167 = 167,
    L168 = 168, L169 = 169, L170 = 170, L171 = 171, L172 = 172, L173 = 173, L174 = 174, L175 = 175,
    L176 = 176, L177 = 177, L178 = 178, L179 = 179, L180 = 180, L181 = 181, L182 = 182, L183 = 183,
    L184 = 184, L185 = 185, L186 = 186, L187 = 187, L188 = 188, L189 = 189, L190 = 190, L191 = 191,
    L192 = 192, L193 = 193, L194 = 194, L195 = 195, L196 = 196, L197 = 197, L198 = 198, L199 = 199,
    L200 = 200, L201 = 201, L202 = 202, L203 = 203, L204 = 204, L205 = 205, L206 = 206, L207 = 207,
    L208 = 208, L209 = 209, L210 = 210, L211 = 211, L212 = 212, L213 = 213, L214 = 214, L215 = 215,
    L216 = 216, L217 = 217, L218 = 218, L219 = 219, L220 = 220, L221 = 221, L222 = 222, L223 = 223,
    L224 = 224, L225 = 225, L226 = 226, L227 = 227, L228 = 228, L229 = 229, L230 = 230, L231 = 231,
    L232 = 232, L233 = 233, L234 = 234, L235 = 235, L236 = 236, L237 = 237, L238 = 238, L239 = 239,
    L240 = 240, L241 = 241, L242 = 242, L243 = 243, L244 = 244, L245 = 245, L246 = 246, L247 = 247,
    L248 = 248, L249 = 249, L250 = 250, L251 = 251, L252 = 252, L253 = 253, L254 = 254, L255 = 255,
}

/// A single address header value.
#[derive(FromBytes, IntoBytes, Immutable, KnownLayout, Unaligned)]
#[repr(C)]
struct AddrHeader {
    ty: u8,
    len: u8,
}

/// A single address.
#[derive(FromBytes, IntoBytes, SplitAt, Immutable, KnownLayout, Unaligned)]
#[repr(C)]
struct AddrData {
    header: AddrHeader,
    data: [u8],
}

/// `NETINFO` cell.
///
/// See also: [spec](https://spec.torproject.org/tor-spec/negotiating-channels.html#NETINFO-cells).
pub struct Netinfo {
    cell: FixedCell,
}

impl Debug for Netinfo {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        let mut f = f.debug_struct("Netinfo");
        f.field("timestamp", &self.timestamp());
        if let MaybeAddr::Ip(ip) = self.other_addr() {
            f.field("other_addr", &ip);
        }
        f.field(
            "my_addrs",
            &from_fn(|f| {
                f.debug_list()
                    .entries(self.my_addrs().filter_map(|v| match v {
                        MaybeAddr::Ip(ip) => Some(ip),
                        _ => None,
                    }))
                    .finish()
            }),
        );
        f.finish()
    }
}

impl TryFromCell for Netinfo {
    type Error = CellCastError;

    fn try_from_cell(cell: &mut Option<Cell>) -> Result<Option<Self>, Self::Error> {
        if let Some(cell) = AutoReturnFixed::new(cell)?
            && cell.header().command == Self::ID
        {
            if cell.header().circuit != 0 {
                Err(NonZeroCircID.into())
            } else if Self::validate_cell(cell.data().data()) {
                Ok(Some(Self {
                    cell: cell.into_inner().1,
                }))
            } else {
                Err(CellFormatError.into())
            }
        } else {
            Ok(None)
        }
    }
}

impl From<Netinfo> for Cell {
    fn from(cell: Netinfo) -> Self {
        Self::from_fixed(
            CellHeader {
                command: Netinfo::ID,
                circuit: 0,
            },
            cell.into_inner(),
        )
    }
}

impl From<Netinfo> for FixedCell {
    #[inline]
    fn from(v: Netinfo) -> FixedCell {
        v.into_inner()
    }
}

impl AsRef<FixedCell> for Netinfo {
    #[inline]
    fn as_ref(&self) -> &FixedCell {
        self.inner()
    }
}

impl Netinfo {
    /// Cell ID of `NETINFO`.
    pub const ID: u8 = 8;

    /// Creates new [`Netinfo`].
    ///
    /// # Errors
    ///
    /// Returns error if data does not fit.
    pub fn new(
        mut cell: FixedCell,
        timestamp: u32,
        other_addr: IpAddr,
        my_addrs: impl IntoIterator<Item = IpAddr>,
    ) -> Result<Self, FixedCell> {
        fn set_header(
            t: &mut NetinfoData,
            timestamp: u32,
            other_addr: IpAddr,
        ) -> (&mut u8, &mut [u8]) {
            t.header.timestamp.set(timestamp);
            match other_addr {
                IpAddr::V4(a) => {
                    t.header.ty = 4;
                    t.data = NetinfoPayload::L4(a.octets(), [0; _]);
                }
                IpAddr::V6(a) => {
                    t.header.ty = 6;
                    t.data = NetinfoPayload::L16(a.octets(), [0; _]);
                }
            }

            t.data.rest_mut()
        }

        fn append_addr<'a, 'b>(n: &'a mut u8, s: &'b mut [u8], a: IpAddr) -> Option<&'b mut [u8]> {
            *n = (*n).checked_add(1)?;
            let mut t = AddrData::mut_from_bytes(s).ok()?;

            let r;
            match a {
                IpAddr::V4(a) => {
                    (t, r) = t.split_at_mut(4)?.via_into_bytes();
                    t.header.ty = 4;
                    t.header.len = 4;
                    t.data.copy_from_slice(&a.octets());
                }
                IpAddr::V6(a) => {
                    (t, r) = t.split_at_mut(16)?.via_into_bytes();
                    t.header.ty = 6;
                    t.header.len = 16;
                    t.data.copy_from_slice(&a.octets());
                }
            }

            Some(r)
        }

        let (n, mut s) = set_header(transmute_mut!(cell.data_mut()), timestamp, other_addr);
        for a in my_addrs {
            s = match append_addr(n, s, a) {
                Some(v) => v,
                None => return Err(cell),
            };
        }
        s.fill(0);

        debug_assert!(
            Self::validate_cell(cell.data()),
            "cell format should be valid"
        );
        Ok(Self { cell })
    }

    /// Creates new [`Netinfo`] from slice.
    ///
    /// # Errors
    ///
    /// Returns error if data does not fit.
    #[inline]
    pub fn from_slice(
        cell: FixedCell,
        timestamp: u32,
        other_addr: IpAddr,
        my_addrs: &[IpAddr],
    ) -> Result<Self, FixedCell> {
        Self::new(cell, timestamp, other_addr, my_addrs.iter().copied())
    }

    /// Gets reference to inner.
    #[inline]
    #[must_use]
    pub fn inner(&self) -> &FixedCell {
        &self.cell
    }

    /// Unwraps into inner.
    #[inline]
    #[must_use]
    pub fn into_inner(self) -> FixedCell {
        self.cell
    }

    fn get_ref(&self) -> &NetinfoData {
        transmute_ref!(self.cell.data())
    }

    fn get_mut(&mut self) -> &mut NetinfoData {
        transmute_mut!(self.cell.data_mut())
    }

    /// Gets timestamp.
    #[inline]
    #[must_use]
    pub fn timestamp(&self) -> u32 {
        self.get_ref().header.timestamp.get()
    }

    /// Sets timestamp.
    #[inline]
    #[must_use]
    pub fn set_timestamp(&mut self, value: u32) {
        self.get_mut().header.timestamp.set(value)
    }

    /// Gets other IP address.
    #[inline]
    #[must_use]
    pub fn other_addr(&self) -> MaybeAddr<'_> {
        match *self.get_ref() {
            NetinfoData {
                header: NetinfoHeader { ty: 4, .. },
                data: NetinfoPayload::L4(a, _),
            } => MaybeAddr::Ip(a.into()),
            NetinfoData {
                header: NetinfoHeader { ty: 6, .. },
                data: NetinfoPayload::L16(a, _),
            } => MaybeAddr::Ip(a.into()),
            NetinfoData {
                header: NetinfoHeader { ty, .. },
                ref data,
            } => MaybeAddr::Unknown {
                ty,
                payload: data.data(),
            },
        }
    }

    /// Iterates through my IP addresses.
    #[inline]
    pub fn my_addrs<'a>(&'a self) -> MyAddrsIter<'a> {
        let (&n, s) = self.get_ref().data.rest();
        MyAddrsIter { s, n }
    }

    fn validate_cell(s: &[u8; FIXED_CELL_SIZE]) -> bool {
        let t: &NetinfoData = transmute_ref!(s);
        let (&n, mut s) = t.data.rest();

        for _ in 0..n {
            let Ok(t) = AddrData::ref_from_bytes(s) else {
                return false;
            };
            let Some(t) = t.split_at(t.header.len as usize) else {
                return false;
            };
            s = t.via_into_bytes().1;
        }

        true
    }
}

/// A single possible address.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum MaybeAddr<'a> {
    /// Valid IP address.
    Ip(IpAddr),
    /// Unknown IP address.
    ///
    /// Users _should_ discard it, as per spec.
    Unknown { ty: u8, payload: &'a [u8] },
}

impl From<IpAddr> for MaybeAddr<'_> {
    #[inline]
    fn from(v: IpAddr) -> Self {
        Self::Ip(v)
    }
}

impl PartialEq<IpAddr> for MaybeAddr<'_> {
    #[inline]
    fn eq(&self, o: &IpAddr) -> bool {
        match self {
            Self::Ip(v) => *v == *o,
            _ => false,
        }
    }
}

impl<'a> From<MaybeAddr<'a>> for Option<IpAddr> {
    #[inline]
    fn from(v: MaybeAddr<'a>) -> Self {
        match v {
            MaybeAddr::Ip(v) => Some(v),
            _ => None,
        }
    }
}

/// My IP addresses iterator for [`Netinfo`].
#[derive(Clone)]
#[must_use = "iterator does nothing if not used"]
pub struct MyAddrsIter<'a> {
    s: &'a [u8],
    n: u8,
}

impl<'a> Iterator for MyAddrsIter<'a> {
    type Item = MaybeAddr<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        self.n = self.n.checked_sub(1)?;

        // SAFETY: Cell content has been validated before.
        unsafe {
            let h = &*from_ref(self.s).cast::<AddrHeader>();
            let s = self.s.get_unchecked(size_of::<AddrHeader>()..);

            let ip: Option<IpAddr> = match h {
                AddrHeader { ty: 4, len: 4 } => Some((*from_ref(s).cast::<[u8; 4]>()).into()),
                AddrHeader { ty: 6, len: 16 } => Some((*from_ref(s).cast::<[u8; 16]>()).into()),
                _ => None,
            };

            self.s = s.get_unchecked(h.len as usize..);
            Some(match ip {
                Some(ip) => MaybeAddr::Ip(ip),
                None => MaybeAddr::Unknown {
                    ty: h.ty,
                    payload: s.get_unchecked(..h.len as usize),
                },
            })
        }
    }

    #[inline]
    fn size_hint(&self) -> (usize, Option<usize>) {
        let l = self.len();
        (l, Some(l))
    }
}

impl<'a> ExactSizeIterator for MyAddrsIter<'a> {
    #[inline]
    fn len(&self) -> usize {
        self.n as _
    }
}
