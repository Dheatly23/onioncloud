use std::mem::size_of_val;
use std::num::{NonZeroU16, NonZeroU32};
use std::ptr::from_ref;
use std::slice::from_raw_parts;

use zerocopy::byteorder::big_endian::U16;
use zerocopy::{
    FromBytes, Immutable, IntoBytes, KnownLayout, Unaligned, transmute_mut, transmute_ref,
};

use super::{
    IntoRelay, RELAY_DATA_LENGTH, Relay, RelayLike, RelayWrapper, TryFromRelay, take_if,
    with_cmd_stream,
};
use crate::cache::Cachable;
use crate::cell::FixedCell;
use crate::errors;

#[derive(FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned)]
#[repr(C)]
struct LinkspecHeader {
    ty: u8,
    len: u8,
}

#[derive(FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned)]
#[repr(C)]
struct HandshakeHeader {
    ty: U16,
    len: U16,
}

#[derive(FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned)]
#[repr(C)]
struct ExtendCell {
    n_link: u8,
    rest: [u8; const { RELAY_DATA_LENGTH - 1 }],
}

/// Link specifier data type.
///
/// # Example
///
/// ```
/// use onioncloud_lowlevel::cell::relay::extend::Linkspec;
///
/// let spec: Linkspec<Vec<u8>> = Linkspec {
///     ty: 0,
///     data: vec![127, 0, 0, 1, 0, 80],
/// };
/// ```
#[derive(Debug, Clone, Copy, Eq, Hash)]
pub struct Linkspec<T> {
    /// Link specifier type.
    ///
    /// Used to identify what kind of link specifier it is.
    pub ty: u8,

    /// Link specifier content.
    ///
    /// It should be a byteslice-like value.
    /// The data is not validated by RELAY_EXTEND2, it is the responsibility of user
    /// to validate it's valid for the given link specifier type.
    pub data: T,
}

impl<T: AsRef<[u8]>> AsRef<[u8]> for Linkspec<T> {
    fn as_ref(&self) -> &[u8] {
        self.data.as_ref()
    }
}

impl<T, U> PartialEq<Linkspec<U>> for Linkspec<T>
where
    T: PartialEq<U>,
{
    fn eq(&self, rhs: &Linkspec<U>) -> bool {
        self.ty == rhs.ty && self.data == rhs.data
    }
}

impl<T> Linkspec<T> {
    /// Create new [`Linkspec`].
    ///
    /// # Example
    ///
    /// ```
    /// use onioncloud_lowlevel::cell::relay::extend::Linkspec;
    ///
    /// let spec = Linkspec::<Vec<u8>>::new(0, vec![0; 10]);
    /// ```
    pub const fn new(ty: u8, data: T) -> Self {
        Self { ty, data }
    }

    /// Converts from `&Linkspec<T>` to `Linkspec<&T>`.
    ///
    /// # Example
    ///
    /// ```
    /// use onioncloud_lowlevel::cell::relay::extend::Linkspec;
    ///
    /// let spec = Linkspec::<Vec<u8>>::new(0, vec![0; 10]);
    /// let spec = spec.as_ref();
    /// ```
    pub const fn as_ref(&self) -> Linkspec<&T> {
        Linkspec {
            ty: self.ty,
            data: &self.data,
        }
    }
}

/// Handshake data type.
///
/// # Example
///
/// ```
/// use onioncloud_lowlevel::cell::relay::extend::Handshake;
///
/// let handshake: Handshake<Vec<u8>> = Handshake {
///     ty: 0,
///     data: vec![127, 0, 0, 1, 0, 80],
/// };
/// ```
#[derive(Debug, Clone, Copy, Eq, Hash)]
pub struct Handshake<T> {
    /// Handshake type.
    ///
    /// Used to identify what kind handshake it is.
    pub ty: u16,

    /// Handshake content.
    ///
    /// It should be a byteslice-like value.
    /// The data is not validated by RELAY_EXTEND2, it is the responsibility of user
    /// to validate it's valid for the given handshake type.
    pub data: T,
}

impl<T: AsRef<[u8]>> AsRef<[u8]> for Handshake<T> {
    fn as_ref(&self) -> &[u8] {
        self.data.as_ref()
    }
}

impl<T, U> PartialEq<Handshake<U>> for Handshake<T>
where
    T: PartialEq<U>,
{
    fn eq(&self, rhs: &Handshake<U>) -> bool {
        self.ty == rhs.ty && self.data == rhs.data
    }
}

impl<T> Handshake<T> {
    /// Create new [`Handshake`].
    ///
    /// # Example
    ///
    /// ```
    /// use onioncloud_lowlevel::cell::relay::extend::Handshake;
    ///
    /// let handshake = Handshake::<Vec<u8>>::new(0, vec![0; 10]);
    /// ```
    pub const fn new(ty: u16, data: T) -> Self {
        Self { ty, data }
    }

    /// Converts from `&Handshake<T>` to `Handshake<&T>`.
    ///
    /// # Example
    ///
    /// ```
    /// use onioncloud_lowlevel::cell::relay::extend::Handshake;
    ///
    /// let handshake = Handshake::<Vec<u8>>::new(0, vec![0; 10]);
    /// let handshake = handshake.as_ref();
    /// ```
    pub const fn as_ref(&self) -> Handshake<&T> {
        Handshake {
            ty: self.ty,
            data: &self.data,
        }
    }
}

/// Represents a RELAY_EXTEND2 cell.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct RelayExtend2 {
    /// Stream ID.
    pub stream: NonZeroU16,
    /// Cell payload.
    data: RelayWrapper,

    // Auxiliary data to speed up access.
    o_handshake: u16,
}

impl AsRef<FixedCell> for RelayExtend2 {
    fn as_ref(&self) -> &FixedCell {
        self.data.as_ref()
    }
}

impl Cachable for RelayExtend2 {
    fn maybe_into_fixed(self) -> Option<FixedCell> {
        Some(self.data.into())
    }
}

impl TryFromRelay for RelayExtend2 {
    fn try_from_relay(relay: &mut Option<Relay>) -> Result<Option<Self>, errors::CellFormatError> {
        let Some((stream, o_handshake)) = (match relay {
            Some(r) if r.command() == Self::ID => Self::check(AsRef::<FixedCell>::as_ref(r).into()),
            _ => return Ok(None),
        }) else {
            return Err(errors::CellFormatError);
        };

        Ok(Some(Self {
            stream,
            data: FixedCell::from(relay.take().unwrap()).into(),
            o_handshake,
        }))
    }
}

impl IntoRelay for RelayExtend2 {
    fn into_relay(self, circuit: NonZeroU32) -> Relay {
        with_cmd_stream(self.data, Self::ID, self.stream.into(), circuit)
    }
}

impl RelayExtend2 {
    /// RELAY_EXTEND2 command ID.
    pub const ID: u8 = 6;

    /// Creates RELAY_EXTEND2 cell from [`FixedCell`].
    ///
    /// # Safety
    ///
    /// Cell must be a valid RELAY_EXTEND2 cell.
    pub unsafe fn from_cell(cell: FixedCell) -> Self {
        let data = RelayWrapper::from(cell);
        let (stream, o_handshake) = Self::check(&data).expect("malformed cell format");

        Self {
            stream,
            data,
            o_handshake,
        }
    }

    /// Creates new RELAY_EXTEND2 cell.
    ///
    /// # Parameters
    ///
    /// - `cell` : Cached [`FixedCell`].
    /// - `stream` : Stream ID.
    /// - `linkspec` : Link specifier.
    /// - `handshake` : Handshake.
    ///
    /// # Panics
    ///
    /// Panics if:
    /// - Number of link specifiers > 255.
    /// - Link specifier payload length > 255.
    /// - Handshake payload length > 65535.
    /// - Data does not fit [`RELAY_DATA_LENGTH`].
    ///
    /// # Example
    ///
    /// ```
    /// use std::num::NonZeroU16;
    ///
    /// use onioncloud_lowlevel::cell::relay::extend::{Linkspec, Handshake, RelayExtend2};
    ///
    /// let linkspec: [Linkspec<&[u8]>; 2] = [
    ///     Linkspec {
    ///         ty: 0,
    ///         data: &[0],
    ///     },
    ///     Linkspec {
    ///         ty: 1,
    ///         data: &[1],
    ///     },
    /// ];
    /// let handshake: Handshake<&[u8]> = Handshake {
    ///     ty: 0,
    ///     data: &[0],
    /// };
    /// let cell = RelayExtend2::new(
    ///     Default::default(),
    ///     NonZeroU16::new(1).unwrap(),
    ///     linkspec,
    ///     handshake,
    /// );
    /// ```
    pub fn new(
        cell: FixedCell,
        stream: NonZeroU16,
        linkspec: impl IntoIterator<Item = Linkspec<impl AsRef<[u8]>>>,
        handshake: Handshake<impl AsRef<[u8]>>,
    ) -> Self {
        fn write_linkspec(
            data: &mut [u8; RELAY_DATA_LENGTH],
            linkspec: impl IntoIterator<Item = Linkspec<impl AsRef<[u8]>>>,
        ) -> (usize, &mut [u8]) {
            let data: &mut ExtendCell = transmute_mut!(data);
            let mut n = 0u8;
            let mut b = &mut data.rest[..];

            for l in linkspec {
                n = n.checked_add(1).expect("too many link specifiers");

                let v = l.data.as_ref();

                let (header, data);
                (header, b) = LinkspecHeader::mut_from_prefix(b).expect("data does not fit");
                header.ty = l.ty;
                header.len = v.len().try_into().expect("linkspec length > 255");
                (data, b) = b.split_at_mut_checked(v.len()).expect("data does not fit");
                data.copy_from_slice(v);
            }

            data.n_link = n;
            (RELAY_DATA_LENGTH - b.len(), b)
        }

        fn write_handshake(b: &mut [u8], ty: u16, data: &[u8]) -> usize {
            let (header, b) = HandshakeHeader::mut_from_prefix(b).expect("data does not fit");
            header.ty.set(ty);
            header
                .len
                .set(data.len().try_into().expect("handshake length > 65535"));
            b.get_mut(..data.len())
                .expect("data does not fit")
                .copy_from_slice(data);

            size_of_val(header) + data.len()
        }

        let mut data = RelayWrapper::from(cell);

        let (mut len, b) = write_linkspec(data.data_padding_mut(), linkspec);
        debug_assert!((1..RELAY_DATA_LENGTH).contains(&len));
        let o_handshake = (len - 1) as u16;
        len += write_handshake(b, handshake.ty, handshake.data.as_ref());

        // SAFETY: Payload length is valid.
        unsafe {
            data.set_len(len as _);
        }

        if cfg!(debug_assertions) {
            data.set_stream(stream.into());
            debug_assert_eq!(Self::check(&data), Some((stream, o_handshake)));
        }

        Self {
            stream,
            data,
            o_handshake,
        }
    }

    /// Get link specifiers.
    pub fn linkspec(&self) -> LinkspecIter<'_> {
        let (n, data, _, _) = self.get_data();
        LinkspecIter { n, data }
    }

    /// Get handshake.
    pub fn handshake(&self) -> Handshake<&'_ [u8]> {
        let (_, _, header, data) = self.get_data();
        Handshake::new(header.ty.get(), data)
    }

    fn check(cell: &RelayWrapper) -> Option<(NonZeroU16, u16)> {
        let stream = NonZeroU16::new(cell.stream())?;

        let [n, rest @ ..] = cell.data() else {
            return None;
        };
        let start = rest.len();
        let mut rest = rest;
        for _ in 0..*n {
            let header;
            (header, rest) = LinkspecHeader::ref_from_prefix(rest).ok()?;
            rest = rest.get(header.len as usize..)?;
        }

        let o_handshake = (start - rest.len()) as u16;
        let header;
        (header, rest) = HandshakeHeader::ref_from_prefix(rest).ok()?;
        if rest.len() != usize::from(header.len.get()) {
            return None;
        }

        Some((stream, o_handshake))
    }

    #[inline(always)]
    fn get_data(&self) -> (u8, &[u8], &HandshakeHeader, &[u8]) {
        let o_handshake = usize::from(self.o_handshake);
        let &ExtendCell { n_link, ref rest } = transmute_ref!(self.data.data_padding());
        debug_assert!(o_handshake <= rest.len());
        let p = from_ref(rest);

        let (link_data, header, hs_data);
        // SAFETY: Data validity has been checked and auxilirary data is valid.
        unsafe {
            link_data = from_raw_parts(p.cast::<u8>(), o_handshake);
            let p = p.cast::<HandshakeHeader>().byte_add(link_data.len());
            header = &*p;
            hs_data = from_raw_parts(p.add(1).cast::<u8>(), header.len.get().into());
        }

        (n_link, link_data, header, hs_data)
    }
}

pub struct LinkspecIter<'a> {
    n: u8,
    data: &'a [u8],
}

impl<'a> Iterator for LinkspecIter<'a> {
    type Item = Linkspec<&'a [u8]>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.n == 0 {
            debug_assert_eq!(self.data.len(), 0);
            return None;
        }
        self.n -= 1;

        let (header, rest) = LinkspecHeader::ref_from_prefix(self.data).unwrap();
        let l = usize::from(header.len);
        let data;
        (data, self.data) = rest.split_at(l);
        Some(Linkspec::new(header.ty, data))
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        let len = self.len();
        (len, Some(len))
    }
}

impl ExactSizeIterator for LinkspecIter<'_> {
    fn len(&self) -> usize {
        self.n.into()
    }
}

#[derive(FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned)]
#[repr(C)]
struct ExtendedData {
    len: U16,
    rest: [u8; const { RELAY_DATA_LENGTH - 2 }],
}

/// Represents a RELAY_EXTENDED2 cell.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct RelayExtended2 {
    /// Stream ID.
    pub stream: NonZeroU16,
    /// Cell payload.
    data: RelayWrapper,
}

impl AsRef<FixedCell> for RelayExtended2 {
    fn as_ref(&self) -> &FixedCell {
        self.data.as_ref()
    }
}

impl Cachable for RelayExtended2 {
    fn maybe_into_fixed(self) -> Option<FixedCell> {
        Some(self.data.into())
    }
}

impl TryFromRelay for RelayExtended2 {
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

impl IntoRelay for RelayExtended2 {
    fn into_relay(self, circuit: NonZeroU32) -> Relay {
        with_cmd_stream(self.data, Self::ID, self.stream.into(), circuit)
    }
}

impl RelayExtended2 {
    /// RELAY_EXTENDED2 command ID.
    pub const ID: u8 = 7;

    /// Creates RELAY_EXTENDED2 cell from [`FixedCell`].
    ///
    /// # Safety
    ///
    /// Cell must be a valid RELAY_EXTENDED2 cell.
    pub unsafe fn from_cell(cell: FixedCell) -> Self {
        let data = RelayWrapper::from(cell);
        debug_assert!(Self::check(data.data()));

        Self {
            stream: NonZeroU16::new(data.stream()).expect("stream ID is zero"),
            data,
        }
    }

    /// Creates new RELAY_EXTENDED2 cell.
    ///
    /// # Parameters
    ///
    /// - `cell` : Cached [`FixedCell`].
    /// - `stream` : Stream ID.
    /// - `data` : Handshake data.
    ///
    /// # Panics
    ///
    /// Panics if handshake data is longer than `RELAY_DATA_LENGTH - 2`.
    ///
    /// # Example
    ///
    /// ```
    /// use std::num::NonZeroU16;
    ///
    /// use onioncloud_lowlevel::cell::relay::extend::RelayExtended2;
    ///
    /// let cell = RelayExtended2::new(
    ///     Default::default(),
    ///     NonZeroU16::new(1).unwrap(),
    ///     &[1, 2, 3],
    /// );
    /// ```
    pub fn new(cell: FixedCell, stream: NonZeroU16, data: &[u8]) -> Self {
        let mut cell = RelayWrapper::from(cell);
        let p: &mut ExtendedData = transmute_mut!(cell.data_padding_mut());
        p.rest[..data.len()].copy_from_slice(data);
        p.len.set(data.len().try_into().unwrap());

        // SAFETY: Payload length is valid.
        unsafe {
            cell.set_len((data.len() + 2) as _);
        }

        debug_assert!(Self::check(cell.data()));

        Self { stream, data: cell }
    }

    /// Get handshake data.
    pub fn data(&self) -> &[u8] {
        let p: &ExtendedData = transmute_ref!(self.data.data_padding());
        &p.rest[..p.len.get() as usize]
    }

    fn check(data: &[u8]) -> bool {
        let Ok((len, data)) = U16::ref_from_prefix(data) else {
            return false;
        };
        data.len() == len.get().into()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use proptest::collection::vec;
    use proptest::prelude::*;

    use crate::cell::relay::tests::assert_relay_eq;

    fn strat() -> impl Strategy<Value = (NonZeroU16, Vec<Linkspec<Vec<u8>>>, Handshake<Vec<u8>>)> {
        (
            any::<NonZeroU16>(),
            vec(
                (any::<u8>(), vec(any::<u8>(), 0..32))
                    .prop_map(|(ty, data)| Linkspec::new(ty, data)),
                0..8,
            ),
            (any::<u16>(), vec(any::<u8>(), 0..128))
                .prop_map(|(ty, data)| Handshake::new(ty, data)),
        )
    }

    #[test]
    #[should_panic]
    fn test_extend2_linkspec_too_many() {
        let cell = RelayExtend2::new(
            FixedCell::default(),
            NonZeroU16::new(1).unwrap(),
            [Linkspec::new(0, []); 256].iter().copied(),
            Handshake::new(0, []),
        );
        println!("{:?}", cell.data.data());
    }

    #[test]
    #[should_panic(expected = "linkspec length > 255")]
    fn test_extend2_linkspec_too_long() {
        let cell = RelayExtend2::new(
            FixedCell::default(),
            NonZeroU16::new(1).unwrap(),
            [Linkspec::new(0, &[0; 256])],
            Handshake::new(0, []),
        );
        println!("{:?}", cell.data.data());
    }

    #[test]
    #[should_panic]
    fn test_extend2_handshake_not_fit() {
        let cell = RelayExtend2::new(
            FixedCell::default(),
            NonZeroU16::new(1).unwrap(),
            [Linkspec::new(0, [])],
            Handshake::new(0, &[0; const { RELAY_DATA_LENGTH - 6 }]),
        );
        println!("{:?}", cell.data.data());
    }

    #[test]
    #[should_panic(expected = "handshake length > 65535")]
    fn test_extend2_handshake_too_long() {
        let cell = RelayExtend2::new(
            FixedCell::default(),
            NonZeroU16::new(1).unwrap(),
            [Linkspec::new(0, [])],
            Handshake::new(0, &[0; 65536]),
        );
        println!("{:?}", cell.data.data());
    }

    #[test]
    #[should_panic]
    fn test_extended2_too_long() {
        let cell = RelayExtended2::new(
            FixedCell::default(),
            NonZeroU16::new(1).unwrap(),
            &[0; const { RELAY_DATA_LENGTH - 1 }],
        );
        println!("{:?}", cell.data.data());
    }

    proptest! {
        #[test]
        fn test_extend2_new(
            (stream, linkspec, handshake) in strat(),
        ) {
            let cell = RelayExtend2::new(FixedCell::default(), stream, linkspec.iter().map(|l| l.as_ref()), handshake.as_ref());

            assert_eq!(cell.stream, stream);
            assert_eq!(cell.linkspec().collect::<Vec<_>>(), linkspec);
            assert_eq!(cell.handshake(), handshake);
        }

        #[test]
        fn test_extend2_from_into_relay(
            (stream, linkspec, handshake) in strat(),
        ) {
            let mut v = Vec::new();
            v.push(linkspec.len() as u8);
            for l in &linkspec {
                v.extend_from_slice(LinkspecHeader {
                    ty: l.ty,
                    len: l.data.len() as _,
                }.as_bytes());
                v.extend_from_slice(&l.data);
            }
            v.extend_from_slice(HandshakeHeader {
                ty: handshake.ty.into(),
                len: (handshake.data.len() as u16).into(),
            }.as_bytes());
            v.extend_from_slice(&handshake.data);

            let cell = Relay::new(FixedCell::default(), NonZeroU32::new(1).unwrap(), RelayExtend2::ID, stream.into(), &v);
            drop(v);
            let data = RelayWrapper::from(AsRef::<FixedCell>::as_ref(&cell).clone());
            let cell = RelayExtend2::try_from_relay(&mut Some(cell)).unwrap().unwrap();

            assert_eq!(cell.stream, stream);
            assert_eq!(cell.linkspec().collect::<Vec<_>>(), linkspec);
            assert_eq!(cell.handshake(), handshake);

            let cell = cell.into_relay(NonZeroU32::new(1).unwrap());

            assert_relay_eq(&cell, &data);
        }

        #[test]
        fn test_extend2_truncated(n in 0..9usize) {
            static DATA: &[u8] = &[1, 1, 1, 0, 0, 1, 0, 1, 0];
            let mut cell = Some(Relay::new(FixedCell::default(), NonZeroU32::new(1).unwrap(), RelayExtend2::ID, 1, &DATA[..n]));
            RelayExtend2::try_from_relay(&mut cell).unwrap_err();
            cell.unwrap();
        }

        #[test]
        fn test_extended2_new(
            stream: NonZeroU16,
            data in vec(any::<u8>(), 0..300),
        ) {
            let cell = RelayExtended2::new(FixedCell::default(), stream, &data);

            assert_eq!(cell.stream, stream);
            assert_eq!(cell.data(), data);
        }

        #[test]
        fn test_extended2_from_into_relay(
            stream: NonZeroU16,
            data in vec(any::<u8>(), 0..300),
        ) {
            let mut v = Vec::new();
            v.extend_from_slice(&(data.len() as u16).to_be_bytes());
            v.extend_from_slice(&data);

            let cell = Relay::new(FixedCell::default(), NonZeroU32::new(1).unwrap(), RelayExtended2::ID, stream.into(), &v);
            drop(v);
            let data_ = RelayWrapper::from(AsRef::<FixedCell>::as_ref(&cell).clone());
            let cell = RelayExtended2::try_from_relay(&mut Some(cell)).unwrap().unwrap();

            assert_eq!(cell.stream, stream);
            assert_eq!(cell.data(), data);

            let cell = cell.into_relay(NonZeroU32::new(1).unwrap());

            assert_relay_eq(&cell, &data_);
        }

        #[test]
        fn test_extended2_truncated(
            (n, data) in vec(any::<u8>(), 0..300).prop_flat_map(|v| (0..v.len() + 2, Just(v))),
        ) {
            let mut v = Vec::new();
            v.extend_from_slice(&(data.len() as u16).to_be_bytes());
            v.extend_from_slice(&data);

            let mut cell = Some(Relay::new(FixedCell::default(), NonZeroU32::new(1).unwrap(), RelayExtended2::ID, 1, &v[..n]));
            drop(v);
            RelayExtended2::try_from_relay(&mut cell).unwrap_err();
            cell.unwrap();
        }
    }
}
