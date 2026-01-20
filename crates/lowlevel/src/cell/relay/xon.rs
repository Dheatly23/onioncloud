use std::mem::size_of;
use std::num::{NonZeroU16, NonZeroU32};

use zerocopy::byteorder::big_endian::U32;
use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout, Unaligned, transmute_ref};

use super::{
    IntoRelay, Relay, RelayV001, RelayVersion, RelayWrapper, TryFromRelay, set_cmd_stream,
    take_if_nonzero_stream, v0, v1,
};
use crate::cache::{Cachable, Cached, CellCache};
use crate::cell::FixedCell;
use crate::errors;

#[derive(FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned)]
#[repr(C)]
struct Xon {
    version: u8,
    kbps: U32,
}

#[derive(FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned)]
#[repr(C)]
struct Xoff {
    version: u8,
}

/// Represents a RELAY_XON cell.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct RelayXon {
    /// Stream ID.
    pub stream: NonZeroU16,
    /// Cell payload.
    data: RelayWrapper,
    /// Relay version.
    version: Option<RelayVersion>,
}

impl AsRef<FixedCell> for RelayXon {
    fn as_ref(&self) -> &FixedCell {
        self.data.as_ref()
    }
}

impl Cachable for RelayXon {
    fn cache<C: CellCache + ?Sized>(self, cache: &C) {
        self.data.cache(cache);
    }
}

impl TryFromRelay for RelayXon {
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

impl IntoRelay for RelayXon {
    fn try_into_relay(
        mut self,
        circuit: NonZeroU32,
        version: RelayVersion,
    ) -> Result<Relay, errors::CellLengthOverflowError> {
        set_cmd_stream(
            self.version,
            version,
            Self::ID,
            self.stream.into(),
            &mut self.data,
        )?;
        Ok(self.data.into_relay(circuit))
    }

    fn try_into_relay_cached<C: CellCache>(
        mut this: Cached<Self, C>,
        circuit: NonZeroU32,
        version: RelayVersion,
    ) -> Result<Cached<Relay, C>, errors::CellLengthOverflowError> {
        set_cmd_stream(
            this.version,
            version,
            Self::ID,
            this.stream.into(),
            &mut this.data,
        )?;
        Ok(Cached::map(this, |v| v.data.into_relay(circuit)))
    }
}

impl RelayXon {
    /// RELAY_XON command ID.
    pub const ID: u8 = 43;

    /// Creates RELAY_XON cell from [`FixedCell`].
    ///
    /// # Safety
    ///
    /// Cell must be a valid RELAY_XON cell.
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

    /// Creates new RELAY_XON cell.
    ///
    /// # Parameters
    ///
    /// - `cell` : Cached [`FixedCell`].
    /// - `stream` : Stream ID.
    /// - `kbps` : Estimated kbps of stream. 0 represents unlimited.
    ///
    /// # Example
    ///
    /// ```
    /// use std::num::NonZeroU16;
    ///
    /// use onioncloud_lowlevel::cell::relay::xon::RelayXon;
    ///
    /// let cell = RelayXon::new(
    ///     Default::default(),
    ///     NonZeroU16::new(1).unwrap(),
    ///     0,
    /// );
    /// ```
    pub fn new(cell: FixedCell, stream: NonZeroU16, kbps: u32) -> Self {
        let mut data = RelayWrapper::from(cell);

        let RelayV001 { len, data: a } = RelayV001::from_mut(&mut data);
        a[..size_of::<Xon>()].copy_from_slice(
            Xon {
                version: 0,
                kbps: kbps.into(),
            }
            .as_bytes(),
        );
        len.set(size_of::<Xon>() as _);

        debug_assert!(Self::check(&a[..len.get() as usize]));

        Self {
            stream,
            data,
            version: None,
        }
    }

    /// Get estimated kbps.
    pub fn kbps(&self) -> u32 {
        let a = match self.version {
            None => &RelayV001::from_ref(&self.data).data[..size_of::<Xon>()],
            Some(RelayVersion::V0) => &v0::RelayExt::data_padding(&self.data)[..size_of::<Xon>()],
            Some(RelayVersion::V1) => &v1::RelayExt::data_padding(&self.data)[..size_of::<Xon>()],
        };

        let a = <&[u8; size_of::<Xon>()]>::try_from(a).expect("array size must be MAX_LEN");
        let data: &Xon = transmute_ref!(a);
        data.kbps.get()
    }

    fn check(data: &[u8]) -> bool {
        let Ok((data, _)) = Xon::ref_from_prefix(data) else {
            return false;
        };
        data.version == 0
    }
}

/// Represents a RELAY_XOFF cell.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct RelayXoff {
    /// Stream ID.
    pub stream: NonZeroU16,
    /// Cell payload.
    data: RelayWrapper,
    /// Relay version.
    version: Option<RelayVersion>,
}

impl AsRef<FixedCell> for RelayXoff {
    fn as_ref(&self) -> &FixedCell {
        self.data.as_ref()
    }
}

impl Cachable for RelayXoff {
    fn cache<C: CellCache + ?Sized>(self, cache: &C) {
        self.data.cache(cache);
    }
}

impl TryFromRelay for RelayXoff {
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

impl IntoRelay for RelayXoff {
    fn try_into_relay(
        mut self,
        circuit: NonZeroU32,
        version: RelayVersion,
    ) -> Result<Relay, errors::CellLengthOverflowError> {
        set_cmd_stream(
            self.version,
            version,
            Self::ID,
            self.stream.into(),
            &mut self.data,
        )?;
        Ok(self.data.into_relay(circuit))
    }

    fn try_into_relay_cached<C: CellCache>(
        mut this: Cached<Self, C>,
        circuit: NonZeroU32,
        version: RelayVersion,
    ) -> Result<Cached<Relay, C>, errors::CellLengthOverflowError> {
        set_cmd_stream(
            this.version,
            version,
            Self::ID,
            this.stream.into(),
            &mut this.data,
        )?;
        Ok(Cached::map(this, |v| v.data.into_relay(circuit)))
    }
}

impl RelayXoff {
    /// RELAY_XOFF command ID.
    pub const ID: u8 = 44;

    /// Creates RELAY_XOFF cell from [`FixedCell`].
    ///
    /// # Safety
    ///
    /// Cell must be a valid RELAY_XOFF cell.
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

    /// Creates new RELAY_XOFF cell.
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
    /// use onioncloud_lowlevel::cell::relay::xon::RelayXoff;
    ///
    /// let cell = RelayXoff::new(
    ///     Default::default(),
    ///     NonZeroU16::new(1).unwrap(),
    /// );
    /// ```
    pub fn new(cell: FixedCell, stream: NonZeroU16) -> Self {
        let mut data = RelayWrapper::from(cell);

        let RelayV001 { len, data: a } = RelayV001::from_mut(&mut data);
        a[..size_of::<Xoff>()].copy_from_slice(Xoff { version: 0 }.as_bytes());
        len.set(size_of::<Xoff>() as _);

        debug_assert!(Self::check(&a[..len.get() as usize]));

        Self {
            stream,
            data,
            version: None,
        }
    }

    fn check(data: &[u8]) -> bool {
        let Ok((data, _)) = Xoff::ref_from_prefix(data) else {
            return false;
        };
        data.version == 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use proptest::prelude::*;

    use crate::cell::relay::v0::tests::assert_relay_eq;

    #[test]
    fn test_xon_trailing() {
        let cell = Relay::new(
            FixedCell::default(),
            NonZeroU32::new(1).unwrap(),
            RelayXon::ID,
            1,
            &[0, 0, 0, 0, 100, 1, 1],
        );
        let cell = RelayXon::try_from_relay(&mut Some(cell), RelayVersion::V0)
            .unwrap()
            .unwrap();

        assert_eq!(cell.kbps(), 100);
    }

    #[test]
    fn test_xoff_trailing() {
        let cell = Relay::new(
            FixedCell::default(),
            NonZeroU32::new(1).unwrap(),
            RelayXoff::ID,
            1,
            &[0, 1, 2, 3, 4],
        );
        RelayXoff::try_from_relay(&mut Some(cell), RelayVersion::V0)
            .unwrap()
            .unwrap();
    }

    proptest! {
        #[test]
        fn test_xon_from_data(
            stream: NonZeroU16,
            kbps: u32,
        ) {
            let cell = RelayXon::new(FixedCell::default(), stream, kbps);

            assert_eq!(cell.stream, stream);
            assert_eq!(cell.kbps(), kbps);
        }

        #[test]
        fn test_xon_from_into_relay(
            stream: NonZeroU16,
            kbps: u32,
        ) {
            let mut v = Vec::with_capacity(5);
            v.push(0);
            v.extend_from_slice(&kbps.to_be_bytes());

            let cell = Relay::new(FixedCell::default(), NonZeroU32::new(1).unwrap(), RelayXon::ID, stream.into(), &v);
            drop(v);
            let data_ = RelayWrapper::from(AsRef::<FixedCell>::as_ref(&cell).clone());
            let cell = RelayXon::try_from_relay(&mut Some(cell), RelayVersion::V0).unwrap().unwrap();

            assert_eq!(cell.stream, stream);
            assert_eq!(cell.kbps(), kbps);

            let cell = cell.try_into_relay(NonZeroU32::new(1).unwrap(), RelayVersion::V0).unwrap();

            assert_relay_eq(&cell, &data_);
        }

        #[test]
        fn test_xon_truncated(n in 0..5usize) {
            let mut cell = Some(Relay::new(
                FixedCell::default(),
                NonZeroU32::new(1).unwrap(),
                RelayXon::ID,
                1,
                &[0, 1, 2, 3, 4][..n],
            ));
            RelayXon::try_from_relay(&mut cell, RelayVersion::V0).unwrap_err();
            cell.unwrap();
        }

        #[test]
        fn test_xoff_from_data(
            stream: NonZeroU16,
        ) {
            let cell = RelayXoff::new(FixedCell::default(), stream);

            assert_eq!(cell.stream, stream);
        }

        #[test]
        fn test_xoff_from_into_relay(
            stream: NonZeroU16,
        ) {
            let cell = Relay::new(FixedCell::default(), NonZeroU32::new(1).unwrap(), RelayXoff::ID, stream.into(), &[0]);
            let data_ = RelayWrapper::from(AsRef::<FixedCell>::as_ref(&cell).clone());
            let cell = RelayXoff::try_from_relay(&mut Some(cell), RelayVersion::V0).unwrap().unwrap();

            assert_eq!(cell.stream, stream);

            let cell = cell.try_into_relay(NonZeroU32::new(1).unwrap(), RelayVersion::V0).unwrap();

            assert_relay_eq(&cell, &data_);
        }
    }
}
