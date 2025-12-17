use std::mem::size_of;
use std::num::{NonZeroU16, NonZeroU32};

use zerocopy::byteorder::big_endian::U16;
use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout, Unaligned, transmute_ref};

use super::{
    IntoRelay, Relay, RelayV001, RelayVersion, RelayWrapper, TryFromRelay, set_cmd_stream, take_if,
    v0, v1,
};
use crate::cache::{Cachable, Cached, CellCache};
use crate::cell::FixedCell;
use crate::errors;

#[derive(FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned)]
#[repr(C)]
struct SendmeHeader {
    ty: u8,
    len: U16,
}

#[derive(FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned)]
#[repr(C)]
struct AuthSendme {
    /// Must be authenticated SENDME header.
    header: SendmeHeader,
    /// Digest.
    digest: [u8; 20],
}

/// Represents a RELAY_SENDME cell.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct RelaySendme {
    /// Stream ID.
    pub stream: u16,
    /// Cell payload.
    data: RelayWrapper,
    /// Relay version.
    version: Option<RelayVersion>,
}

impl AsRef<FixedCell> for RelaySendme {
    fn as_ref(&self) -> &FixedCell {
        self.data.as_ref()
    }
}

impl Cachable for RelaySendme {
    fn cache<C: CellCache + ?Sized>(self, cache: &C) {
        self.data.cache(cache);
    }
}

impl TryFromRelay for RelaySendme {
    fn try_from_relay(
        relay: &mut Option<Relay>,
        version: RelayVersion,
    ) -> Result<Option<Self>, errors::CellFormatError> {
        take_if(relay, Self::ID, version, Self::check).map(|v| {
            v.map(|(stream, data)| Self {
                stream,
                data,
                version: Some(version),
            })
        })
    }
}

impl IntoRelay for RelaySendme {
    fn try_into_relay(
        mut self,
        circuit: NonZeroU32,
        version: RelayVersion,
    ) -> Result<Relay, errors::CellLengthOverflowError> {
        set_cmd_stream(self.version, version, Self::ID, self.stream, &mut self.data)?;
        Ok(self.data.into_relay(circuit))
    }

    fn try_into_relay_cached<C: CellCache>(
        mut this: Cached<Self, C>,
        circuit: NonZeroU32,
        version: RelayVersion,
    ) -> Result<Cached<Relay, C>, errors::CellLengthOverflowError> {
        set_cmd_stream(this.version, version, Self::ID, this.stream, &mut this.data)?;
        Ok(Cached::map(this, |v| v.data.into_relay(circuit)))
    }
}

impl RelaySendme {
    /// RELAY_SENDME command ID.
    pub const ID: u8 = 13;

    /// Creates RELAY_SENDME cell from [`FixedCell`].
    ///
    /// # Safety
    ///
    /// Cell must be a valid RELAY_SENDME cell.
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
            stream,
            data,
            version: Some(version),
        }
    }

    /// Creates new unauthenticated sendme cell.
    ///
    /// # Parameters
    ///
    /// - `cell` : Cached [`FixedCell`].
    ///
    /// # Example
    ///
    /// ```
    /// use onioncloud_lowlevel::cell::relay::sendme::RelaySendme;
    ///
    /// let cell = RelaySendme::new_unauth(
    ///     Default::default(),
    /// );
    /// ```
    pub fn new_unauth(cell: FixedCell) -> Self {
        let mut data = RelayWrapper::from(cell);

        let RelayV001 { len, data: a } = RelayV001::from_mut(&mut data);
        a[..size_of::<SendmeHeader>()].copy_from_slice(
            SendmeHeader {
                ty: 0,
                len: 0.into(),
            }
            .as_bytes(),
        );
        len.set(size_of::<SendmeHeader>() as _);

        debug_assert!(Self::check(&a[..len.get() as usize]));

        Self {
            stream: 0,
            data,
            version: None,
        }
    }

    /// Creates new authenticated sendme cell.
    ///
    /// # Parameters
    ///
    /// - `cell` : Cached [`FixedCell`].
    /// - `digest` : Digest.
    ///
    /// # Example
    ///
    /// ```
    /// use onioncloud_lowlevel::cell::relay::sendme::RelaySendme;
    ///
    /// let cell = RelaySendme::new_auth(
    ///     Default::default(),
    ///     [0; 20],
    /// );
    /// ```
    pub fn new_auth(cell: FixedCell, digest: [u8; 20]) -> Self {
        let mut data = RelayWrapper::from(cell);

        let RelayV001 { len, data: a } = RelayV001::from_mut(&mut data);
        a[..size_of::<AuthSendme>()].copy_from_slice(
            AuthSendme {
                header: SendmeHeader {
                    ty: 1,
                    len: 20.into(),
                },
                digest,
            }
            .as_bytes(),
        );
        len.set(size_of::<AuthSendme>() as _);

        debug_assert!(Self::check(&a[..len.get() as usize]));

        Self {
            stream: 0,
            data,
            version: None,
        }
    }

    /// Creates new stream-level sendme cell.
    ///
    /// Stream-level SENDME are always unauthenticated.
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
    /// use onioncloud_lowlevel::cell::relay::sendme::RelaySendme;
    ///
    /// let cell = RelaySendme::new_stream_unauth(
    ///     Default::default(),
    ///     NonZeroU16::new(1).unwrap(),
    /// );
    /// ```
    pub fn new_stream_unauth(cell: FixedCell, stream: NonZeroU16) -> Self {
        let mut data = RelayWrapper::from(cell);

        RelayV001::from_mut(&mut data).len.set(0);

        Self {
            stream: stream.into(),
            data,
            version: None,
        }
    }

    /// Creates new RELAY_SENDME from [`SendmeData`].
    ///
    /// # Parameters
    ///
    /// - `cell` : Cached [`FixedCell`].
    /// - `digest` : Digest.
    ///
    /// # Example
    ///
    /// ```
    /// use onioncloud_lowlevel::cell::relay::sendme::{RelaySendme, SendmeData};
    ///
    /// let cell = RelaySendme::from_data(
    ///     Default::default(),
    ///     SendmeData::Unauth,
    /// );
    /// ```
    pub fn from_data(cell: FixedCell, data: SendmeData) -> Self {
        match data {
            SendmeData::Unauth => Self::new_unauth(cell),
            SendmeData::Auth(digest) => Self::new_auth(cell, digest),
        }
    }

    /// Get SENDME data.
    pub fn data(&self) -> Option<SendmeData> {
        const MAX_SIZE: usize = size_of::<AuthSendme>();

        let (l, a) = match self.version {
            None => {
                let RelayV001 { len, data } = RelayV001::from_ref(&self.data);
                (len.get(), &data[..MAX_SIZE])
            }
            Some(RelayVersion::V0) => (
                v0::RelayExt::len(&self.data),
                &v0::RelayExt::data_padding(&self.data)[..MAX_SIZE],
            ),
            Some(RelayVersion::V1) => (
                v1::RelayExt::len(&self.data),
                &v1::RelayExt::data_padding(&self.data)[..MAX_SIZE],
            ),
        };
        if l == 0 {
            return None;
        }

        let a = <&[u8; MAX_SIZE]>::try_from(a).expect("array size must be MAX_LEN");

        Some(match transmute_ref!(a) {
            AuthSendme {
                header: SendmeHeader { ty: 0, .. },
                ..
            } => SendmeData::Unauth,
            AuthSendme { digest, .. } => SendmeData::Auth(*digest),
        })
    }

    fn check(data: &[u8]) -> bool {
        if data.is_empty() {
            return true;
        }

        let Ok((header, data)) = SendmeHeader::ref_from_prefix(data) else {
            return false;
        };
        let Some(data) = data.get(..header.len.get().into()) else {
            return false;
        };

        match header.ty {
            // Unauthenticated SENDME, ignore the rest of the message.
            0 => true,
            // Authenticated SENDME, must contain at least 20 bytes.
            1 => data.len() >= 20,
            _ => false,
        }
    }
}

/// Content of RELAY_SENDME.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum SendmeData {
    /// Unauthenticated SENDME.
    Unauth,

    /// Authenticated SENDME.
    ///
    /// Contains digest of all cells so far, excluding current cell.
    Auth([u8; 20]),
}

#[cfg(test)]
mod tests {
    use super::*;

    use proptest::prelude::*;

    use crate::cell::relay::v0::tests::assert_relay_eq;

    fn strat() -> impl Strategy<Value = SendmeData> {
        prop_oneof![
            Just(()).prop_map(|_| SendmeData::Unauth),
            [any::<u8>(); 20].prop_map(SendmeData::Auth),
        ]
    }

    #[test]
    fn test_sendme_unauth_trailing() {
        let cell = Relay::new(
            FixedCell::default(),
            NonZeroU32::new(1).unwrap(),
            RelaySendme::ID,
            0,
            &[0, 0, 1, 1],
        );
        let cell = RelaySendme::try_from_relay(&mut Some(cell), RelayVersion::V0)
            .unwrap()
            .unwrap();

        assert_eq!(cell.data(), Some(SendmeData::Unauth));
    }

    #[test]
    fn test_sendme_auth_trailing() {
        let cell = Relay::new(
            FixedCell::default(),
            NonZeroU32::new(1).unwrap(),
            RelaySendme::ID,
            0,
            &[
                1, 0, 21, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1,
            ],
        );
        let cell = RelaySendme::try_from_relay(&mut Some(cell), RelayVersion::V0)
            .unwrap()
            .unwrap();

        assert_eq!(cell.data(), Some(SendmeData::Auth([0; 20])));
    }

    proptest! {
        #[test]
        fn test_sendme_from_data(
            data in strat(),
        ) {
            let cell = RelaySendme::from_data(FixedCell::default(), data.clone());

            assert_eq!(cell.stream, 0);
            assert_eq!(cell.data(), Some(data));
        }

        #[test]
        fn test_sendme_from_into_relay(
            data in strat(),
        ) {
            let mut v = Vec::new();
            match &data {
                SendmeData::Unauth => v.extend_from_slice(&[0; 3]),
                SendmeData::Auth(digest) => {
                    v.extend_from_slice(&[1, 0, 20]);
                    v.extend_from_slice(digest);
                }
            }

            let cell = Relay::new(FixedCell::default(), NonZeroU32::new(1).unwrap(), RelaySendme::ID, 0, &v);
            drop(v);
            let data_ = RelayWrapper::from(AsRef::<FixedCell>::as_ref(&cell).clone());
            let cell = RelaySendme::try_from_relay(&mut Some(cell), RelayVersion::V0).unwrap().unwrap();

            assert_eq!(cell.stream, 0);
            assert_eq!(cell.data(), Some(data));

            let cell = cell.try_into_relay(NonZeroU32::new(1).unwrap(), RelayVersion::V0).unwrap();

            assert_relay_eq(&cell, &data_);
        }

        #[test]
        fn test_sendme_new_auth(data: [u8; 20]) {
            let cell = RelaySendme::new_auth(FixedCell::default(), data);

            assert_eq!(cell.stream, 0);
            assert_eq!(cell.data(), Some(SendmeData::Auth(data)));
        }

        #[test]
        fn test_sendme_truncated(n in 0..20usize) {
            let mut cell = Some(Relay::new(
                FixedCell::default(),
                NonZeroU32::new(1).unwrap(),
                RelaySendme::ID,
                0,
                &[1, 0, n as u8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0][..n + 3],
            ));
            RelaySendme::try_from_relay(&mut cell, RelayVersion::V0).unwrap_err();
            cell.unwrap();
        }
    }
}
