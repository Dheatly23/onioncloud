use std::mem::size_of_val;
use std::num::{NonZeroU16, NonZeroU32};
use std::ptr::from_ref;
use std::slice::from_raw_parts;

use zerocopy::byteorder::big_endian::U16;
use zerocopy::{
    FromBytes, Immutable, IntoBytes, KnownLayout, Unaligned, transmute_mut, transmute_ref,
};

use super::{
    IntoRelay, Relay, RelayV001, RelayVersion, RelayWrapper, TryFromRelay, take_if_nonzero_stream,
    v0, v1, with_cmd_stream,
};
use crate::cache::Cachable;
use crate::cell::{FIXED_CELL_SIZE, FixedCell};
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
    /// Relay version.
    version: Option<RelayVersion>,

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
    fn try_from_relay(
        relay: &mut Option<Relay>,
        version: RelayVersion,
    ) -> Result<Option<Self>, errors::CellFormatError> {
        let (stream, a) = match (&*relay, version) {
            (Some(r), RelayVersion::V0) if v0::RelayExt::command(r) == Self::ID => {
                (v0::RelayExt::stream(r), v0::RelayExt::data(r))
            }
            (Some(r), RelayVersion::V1) if v1::RelayExt::command(r) == Self::ID => {
                (v1::RelayExt::stream(r), v1::RelayExt::data(r))
            }
            _ => return Ok(None),
        };

        let (Some(stream), Some(o_handshake)) = (NonZeroU16::new(stream), Self::check(a)) else {
            return Err(errors::CellFormatError);
        };

        Ok(Some(Self {
            stream,
            // SAFETY: Relay is Some
            data: FixedCell::from(unsafe { relay.take().unwrap_unchecked() }).into(),
            version: Some(version),
            o_handshake,
        }))
    }
}

impl IntoRelay for RelayExtend2 {
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

impl RelayExtend2 {
    /// RELAY_EXTEND2 command ID.
    pub const ID: u8 = 6;

    /// Creates RELAY_EXTEND2 cell from [`FixedCell`].
    ///
    /// # Safety
    ///
    /// Cell must be a valid RELAY_EXTEND2 cell.
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

        Self {
            o_handshake: unsafe { Self::check(a).unwrap_unchecked() },
            stream: unsafe { NonZeroU16::new_unchecked(stream) },
            data,
            version: Some(version),
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
    /// # Return
    ///
    /// Returns RELAY_EXTEND2 cell or error if:
    /// - Number of link specifiers > 255.
    /// - Link specifier payload length > 255.
    /// - Handshake payload length > 65535.
    /// - Data overflows cell.
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
    /// ).unwrap();
    /// ```
    pub fn new(
        cell: FixedCell,
        stream: NonZeroU16,
        linkspec: impl IntoIterator<Item = Linkspec<impl AsRef<[u8]>>>,
        handshake: Handshake<impl AsRef<[u8]>>,
    ) -> Result<Self, errors::CellLengthOverflowError> {
        fn write_linkspec(
            data: &mut [u8; const { FIXED_CELL_SIZE - 2 }],
            linkspec: impl IntoIterator<Item = Linkspec<impl AsRef<[u8]>>>,
        ) -> Result<(usize, &mut [u8]), errors::CellLengthOverflowError> {
            let [n_link, b @ ..] = data;
            let mut n = 0u8;
            let mut b = &mut b[..];

            for l in linkspec {
                n = n.checked_add(1).ok_or(errors::CellLengthOverflowError)?;

                let v = l.data.as_ref();

                let (header, data);
                (header, b) = LinkspecHeader::mut_from_prefix(b)
                    .ok()
                    .ok_or(errors::CellLengthOverflowError)?;
                header.ty = l.ty;
                header.len = v
                    .len()
                    .try_into()
                    .map_err(|_| errors::CellLengthOverflowError)?;
                (data, b) = b
                    .split_at_mut_checked(v.len())
                    .ok_or(errors::CellLengthOverflowError)?;
                data.copy_from_slice(v);
            }

            *n_link = n;
            Ok((FIXED_CELL_SIZE - 2 - b.len(), b))
        }

        fn write_handshake(
            b: &mut [u8],
            ty: u16,
            data: &[u8],
        ) -> Result<usize, errors::CellLengthOverflowError> {
            let (header, b) = HandshakeHeader::mut_from_prefix(b)
                .ok()
                .ok_or(errors::CellLengthOverflowError)?;
            header.ty.set(ty);
            header.len.set(
                data.len()
                    .try_into()
                    .ok()
                    .ok_or(errors::CellLengthOverflowError)?,
            );
            b.get_mut(..data.len())
                .ok_or(errors::CellLengthOverflowError)?
                .copy_from_slice(data);

            Ok(size_of_val(header) + data.len())
        }

        let mut data = RelayWrapper::from(cell);

        let RelayV001 { len, data: a } = RelayV001::from_mut(&mut data);
        let (mut l, b) = write_linkspec(a, linkspec)?;
        let o_handshake = (l - 1) as u16;
        l += write_handshake(b, handshake.ty, handshake.data.as_ref())?;

        debug_assert!((1..=FIXED_CELL_SIZE - 2).contains(&l));
        len.set(l as _);

        debug_assert_eq!(Self::check(&a[..len.get() as usize]), Some(o_handshake));

        Ok(Self {
            stream,
            data,
            version: None,
            o_handshake,
        })
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

    fn check(data: &[u8]) -> Option<u16> {
        let [n, rest @ ..] = data else {
            return None;
        };
        let mut rest = rest;

        let start = rest.len();
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

        Some(o_handshake)
    }

    #[inline(always)]
    fn get_data(&self) -> (u8, &[u8], &HandshakeHeader, &[u8]) {
        let o_handshake = usize::from(self.o_handshake);
        let data = match self.version {
            None => &RelayV001::from_ref(&self.data).data[..],
            Some(RelayVersion::V0) => &v0::RelayExt::data_padding(&self.data)[..],
            Some(RelayVersion::V1) => &v1::RelayExt::data_padding(&self.data)[..],
        };
        let [n_link, rest @ ..] = data else {
            unreachable!()
        };
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

        (*n_link, link_data, header, hs_data)
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

/// Represents a RELAY_EXTENDED2 cell.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct RelayExtended2 {
    /// Stream ID.
    pub stream: NonZeroU16,
    /// Cell payload.
    data: RelayWrapper,
    /// Relay version.
    version: Option<RelayVersion>,
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

impl IntoRelay for RelayExtended2 {
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

impl RelayExtended2 {
    /// RELAY_EXTENDED2 command ID.
    pub const ID: u8 = 7;

    /// Creates RELAY_EXTENDED2 cell from [`FixedCell`].
    ///
    /// # Safety
    ///
    /// Cell must be a valid RELAY_EXTENDED2 cell.
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

    /// Creates new RELAY_EXTENDED2 cell.
    ///
    /// # Parameters
    ///
    /// - `cell` : Cached [`FixedCell`].
    /// - `stream` : Stream ID.
    /// - `data` : Handshake data.
    ///
    /// # Return
    ///
    /// Returns RELAY_EXTENDED2 cell or error if data overflows cell.
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
    /// ).unwrap();
    /// ```
    pub fn new(
        cell: FixedCell,
        stream: NonZeroU16,
        data: &[u8],
    ) -> Result<Self, errors::CellLengthOverflowError> {
        let mut cell = RelayWrapper::from(cell);
        let RelayV001 { len, data: a } = RelayV001::from_mut(&mut cell);

        #[derive(FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned)]
        #[repr(C)]
        struct Data {
            n: U16,
            rest: [u8; const { FIXED_CELL_SIZE - 4 }],
        }

        let Data { n, rest } = transmute_mut!(a);
        rest.get_mut(..data.len())
            .ok_or(errors::CellLengthOverflowError)?
            .copy_from_slice(data);
        n.set(data.len() as _);
        len.set((data.len() + 2) as _);

        debug_assert!(Self::check(&a[..len.get() as usize]));

        Ok(Self {
            stream,
            data: cell,
            version: None,
        })
    }

    /// Get handshake data.
    pub fn data(&self) -> &[u8] {
        match self.version {
            None => {
                #[derive(FromBytes, KnownLayout, Immutable, Unaligned)]
                #[repr(C)]
                struct Data {
                    n: U16,
                    rest: [u8; const { FIXED_CELL_SIZE - 4 }],
                }

                let Data { n, rest } = transmute_ref!(&RelayV001::from_ref(&self.data).data);

                &rest[..n.get() as usize]
            }
            Some(RelayVersion::V0) => {
                #[derive(FromBytes, KnownLayout, Immutable, Unaligned)]
                #[repr(C)]
                struct Data {
                    n: U16,
                    rest: [u8; const { v0::RELAY_DATA_LENGTH - 2 }],
                }

                let Data { n, rest } = transmute_ref!(v0::RelayExt::data_padding(&self.data));

                &rest[..n.get() as usize]
            }
            Some(RelayVersion::V1) => {
                #[derive(FromBytes, KnownLayout, Immutable, Unaligned)]
                #[repr(C)]
                struct Data {
                    n: U16,
                    rest: [u8; const { v1::RELAY_DATA_LENGTH - 2 }],
                }

                let Data { n, rest } = transmute_ref!(v1::RelayExt::data_padding(&self.data));

                &rest[..n.get() as usize]
            }
        }
    }

    fn check(data: &[u8]) -> bool {
        let Ok((len, data)) = U16::ref_from_prefix(data) else {
            return false;
        };
        data.len() >= len.get().into()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use proptest::collection::vec;
    use proptest::prelude::*;

    use crate::cell::relay::v0::tests::assert_relay_eq;

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
    fn test_extend2_linkspec_too_many() {
        let ret = RelayExtend2::new(
            FixedCell::default(),
            NonZeroU16::new(1).unwrap(),
            [Linkspec::new(0, []); 256].iter().copied(),
            Handshake::new(0, []),
        );
        assert!(ret.is_err(), "expect error, got {ret:?}");
    }

    #[test]
    fn test_extend2_linkspec_too_long() {
        let ret = RelayExtend2::new(
            FixedCell::default(),
            NonZeroU16::new(1).unwrap(),
            [Linkspec::new(0, &[0; 256])],
            Handshake::new(0, []),
        );
        assert!(ret.is_err(), "expect error, got {ret:?}");
    }

    #[test]
    fn test_extend2_handshake_not_fit() {
        let ret = RelayExtend2::new(
            FixedCell::default(),
            NonZeroU16::new(1).unwrap(),
            [Linkspec::new(0, [])],
            Handshake::new(0, &[0; const { FIXED_CELL_SIZE - 8 }]),
        );
        assert!(ret.is_err(), "expect error, got {ret:?}");
    }

    #[test]
    fn test_extend2_handshake_too_long() {
        let ret = RelayExtend2::new(
            FixedCell::default(),
            NonZeroU16::new(1).unwrap(),
            [Linkspec::new(0, [])],
            Handshake::new(0, &[0; 65536]),
        );
        assert!(ret.is_err(), "expect error, got {ret:?}");
    }

    #[test]
    fn test_extended2_too_long() {
        let ret = RelayExtended2::new(
            FixedCell::default(),
            NonZeroU16::new(1).unwrap(),
            &[0; const { FIXED_CELL_SIZE - 3 }],
        );
        assert!(ret.is_err(), "expect error, got {ret:?}");
    }

    proptest! {
        #[test]
        fn test_extend2_new(
            (stream, linkspec, handshake) in strat(),
        ) {
            let cell = RelayExtend2::new(FixedCell::default(), stream, linkspec.iter().map(|l| l.as_ref()), handshake.as_ref()).unwrap();

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
            let cell = RelayExtend2::try_from_relay(&mut Some(cell), RelayVersion::V0).unwrap().unwrap();

            assert_eq!(cell.stream, stream);
            assert_eq!(cell.linkspec().collect::<Vec<_>>(), linkspec);
            assert_eq!(cell.handshake(), handshake);

            let cell = cell.try_into_relay(NonZeroU32::new(1).unwrap(), RelayVersion::V0).unwrap();

            assert_relay_eq(&cell, &data);
        }

        #[test]
        fn test_extend2_truncated(n in 0..9usize) {
            static DATA: &[u8] = &[1, 1, 1, 0, 0, 1, 0, 1, 0];
            let mut cell = Some(Relay::new(FixedCell::default(), NonZeroU32::new(1).unwrap(), RelayExtend2::ID, 1, &DATA[..n]));
            RelayExtend2::try_from_relay(&mut cell, RelayVersion::V0).unwrap_err();
            cell.unwrap();
        }

        #[test]
        fn test_extended2_new(
            stream: NonZeroU16,
            data in vec(any::<u8>(), 0..300),
        ) {
            let cell = RelayExtended2::new(FixedCell::default(), stream, &data).unwrap();

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
            let cell = RelayExtended2::try_from_relay(&mut Some(cell), RelayVersion::V0).unwrap().unwrap();

            assert_eq!(cell.stream, stream);
            assert_eq!(cell.data(), data);

            let cell = cell.try_into_relay(NonZeroU32::new(1).unwrap(), RelayVersion::V0).unwrap();

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
            RelayExtended2::try_from_relay(&mut cell, RelayVersion::V0).unwrap_err();
            cell.unwrap();
        }
    }
}
