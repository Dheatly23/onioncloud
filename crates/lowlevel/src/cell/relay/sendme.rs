use std::mem::size_of;
use std::num::{NonZeroU16, NonZeroU32};

use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout, Unaligned, transmute_ref};

use super::{
    IntoRelay, RELAY_DATA_LENGTH, Relay, RelayLike, RelayWrapper, TryFromRelay, take_if,
    with_cmd_stream,
};
use crate::cache::Cachable;
use crate::cell::FixedCell;
use crate::errors;

#[derive(FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned)]
#[repr(C)]
struct AuthSendme {
    /// Must be 1.
    ty: u8,
    /// Digest.
    digest: [u8; 20],
}

#[derive(FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned)]
#[repr(C)]
struct AuthSendmePad {
    data: AuthSendme,
    pad: [u8; const { RELAY_DATA_LENGTH - size_of::<AuthSendme>() }],
}

/// Represents a RELAY_SENDME cell.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct RelaySendme {
    /// Stream ID.
    pub stream: NonZeroU16,
    /// Cell payload.
    data: RelayWrapper,
}

impl AsRef<FixedCell> for RelaySendme {
    fn as_ref(&self) -> &FixedCell {
        self.data.as_ref()
    }
}

impl Cachable for RelaySendme {
    fn maybe_into_fixed(self) -> Option<FixedCell> {
        Some(self.data.into())
    }
}

impl TryFromRelay for RelaySendme {
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

impl IntoRelay for RelaySendme {
    fn into_relay(self, circuit: NonZeroU32) -> Relay {
        with_cmd_stream(self.data, Self::ID, self.stream.into(), circuit)
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
    pub unsafe fn from_cell(cell: FixedCell) -> Self {
        let data = RelayWrapper::from(cell);
        debug_assert!(Self::check(data.data()));

        Self {
            stream: NonZeroU16::new(data.stream()).expect("stream ID is zero"),
            data,
        }
    }

    /// Creates new unauthenticated sendme cell.
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
    /// let cell = RelaySendme::new_unauth(
    ///     Default::default(),
    ///     NonZeroU16::new(1).unwrap(),
    /// );
    /// ```
    pub fn new_unauth(cell: FixedCell, stream: NonZeroU16) -> Self {
        let mut data = RelayWrapper::from(cell);
        data.set_data(&[0]);

        debug_assert!(Self::check(data.data()));

        Self { stream, data }
    }

    /// Creates new authenticated sendme cell.
    ///
    /// # Parameters
    ///
    /// - `cell` : Cached [`FixedCell`].
    /// - `stream` : Stream ID.
    /// - `digest` : Digest.
    ///
    /// # Example
    ///
    /// ```
    /// use std::num::NonZeroU16;
    ///
    /// use onioncloud_lowlevel::cell::relay::sendme::RelaySendme;
    ///
    /// let cell = RelaySendme::new_auth(
    ///     Default::default(),
    ///     NonZeroU16::new(1).unwrap(),
    ///     [0; 20],
    /// );
    /// ```
    pub fn new_auth(cell: FixedCell, stream: NonZeroU16, digest: [u8; 20]) -> Self {
        let mut data = RelayWrapper::from(cell);
        data.set_data(AuthSendme { ty: 1, digest }.as_bytes());

        debug_assert!(Self::check(data.data()));

        Self { stream, data }
    }

    /// Creates new RELAY_SENDME from [`SendmeData`].
    ///
    /// # Parameters
    ///
    /// - `cell` : Cached [`FixedCell`].
    /// - `stream` : Stream ID.
    /// - `digest` : Digest.
    ///
    /// # Example
    ///
    /// ```
    /// use std::num::NonZeroU16;
    ///
    /// use onioncloud_lowlevel::cell::relay::sendme::{RelaySendme, SendmeData};
    ///
    /// let cell = RelaySendme::from_data(
    ///     Default::default(),
    ///     NonZeroU16::new(1).unwrap(),
    ///     SendmeData::Unauth,
    /// );
    /// ```
    pub fn from_data(cell: FixedCell, stream: NonZeroU16, data: SendmeData) -> Self {
        match data {
            SendmeData::Unauth => Self::new_unauth(cell, stream),
            SendmeData::Auth(digest) => Self::new_auth(cell, stream, digest),
        }
    }

    /// Get SENDME data.
    pub fn data(&self) -> SendmeData {
        match self.data.data_padding() {
            [0, ..] => SendmeData::Unauth,
            data @ [1, ..] => {
                let p: &AuthSendmePad = transmute_ref!(data);
                SendmeData::Auth(p.data.digest)
            }
            _ => unreachable!("data must be valid"),
        }
    }

    fn check(data: &[u8]) -> bool {
        match data {
            // Unauthenticated SENDME, ignore the rest of the message.
            [0, ..] => true,
            // Authenticated SENDME, must contain at least 20 bytes.
            data @ [1, ..] => AuthSendme::ref_from_prefix(data).is_ok(),
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

    use crate::cell::relay::tests::assert_relay_eq;

    fn strat() -> impl Strategy<Value = (NonZeroU16, SendmeData)> {
        (
            any::<NonZeroU16>(),
            prop_oneof![
                Just(()).prop_map(|_| SendmeData::Unauth),
                [any::<u8>(); 20].prop_map(SendmeData::Auth),
            ],
        )
    }

    #[test]
    fn test_sendme_unauth_trailing() {
        let cell = Relay::new(
            FixedCell::default(),
            NonZeroU32::new(1).unwrap(),
            RelaySendme::ID,
            1,
            &[0; 2],
        );
        let cell = RelaySendme::try_from_relay(&mut Some(cell))
            .unwrap()
            .unwrap();

        assert_eq!(cell.data(), SendmeData::Unauth);
    }

    #[test]
    fn test_sendme_auth_trailing() {
        let cell = Relay::new(
            FixedCell::default(),
            NonZeroU32::new(1).unwrap(),
            RelaySendme::ID,
            1,
            &[
                1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1,
            ],
        );
        let cell = RelaySendme::try_from_relay(&mut Some(cell))
            .unwrap()
            .unwrap();

        assert_eq!(cell.data(), SendmeData::Auth([0; 20]));
    }

    proptest! {
        #[test]
        fn test_sendme_from_data(
            (stream, data) in strat(),
        ) {
            let cell = RelaySendme::from_data(FixedCell::default(), stream, data.clone());

            assert_eq!(cell.stream, stream);
            assert_eq!(cell.data(), data);
        }

        #[test]
        fn test_sendme_from_into_relay(
            (stream, data) in strat(),
        ) {
            let mut v = Vec::new();
            match &data {
                SendmeData::Unauth => v.push(0),
                SendmeData::Auth(digest) => {
                    v.push(1);
                    v.extend_from_slice(digest);
                }
            }

            let cell = Relay::new(FixedCell::default(), NonZeroU32::new(1).unwrap(), RelaySendme::ID, stream.into(), &v);
            drop(v);
            let data_ = RelayWrapper::from(AsRef::<FixedCell>::as_ref(&cell).clone());
            let cell = RelaySendme::try_from_relay(&mut Some(cell)).unwrap().unwrap();

            assert_eq!(cell.stream, stream);
            assert_eq!(cell.data(), data);

            let cell = cell.into_relay(NonZeroU32::new(1).unwrap());

            assert_relay_eq(&cell, &data_);
        }

        #[test]
        fn test_sendme_new_auth(stream: NonZeroU16, data: [u8; 20]) {
            let cell = RelaySendme::new_auth(FixedCell::default(), stream, data);

            assert_eq!(cell.stream, stream);
            assert_eq!(cell.data(), SendmeData::Auth(data));
        }

        #[test]
        fn test_sendme_truncated(n in 0..20usize) {
            let mut cell = Some(Relay::new(
                FixedCell::default(),
                NonZeroU32::new(1).unwrap(),
                RelaySendme::ID,
                1,
                &[1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0][..n],
            ));
            RelaySendme::try_from_relay(&mut cell).unwrap_err();
            cell.unwrap();
        }
    }
}
