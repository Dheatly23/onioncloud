use std::num::{NonZeroU16, NonZeroU32};

use super::{IntoRelay, Relay, RelayLike, RelayWrapper, TryFromRelay, with_cmd_stream};
use crate::cache::Cachable;
use crate::cell::FixedCell;
use crate::errors;
use crate::util::fill_data_multipart;

/// Represents a RELAY_DATA cell.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct RelayData {
    /// Stream ID.
    pub stream: NonZeroU16,
    /// Cell payload.
    data: RelayWrapper,
}

impl AsRef<FixedCell> for RelayData {
    fn as_ref(&self) -> &FixedCell {
        self.data.as_ref()
    }
}

impl Cachable for RelayData {
    fn maybe_into_fixed(self) -> Option<FixedCell> {
        Some(self.data.into())
    }
}

impl TryFromRelay for RelayData {
    fn try_from_relay(relay: &mut Option<Relay>) -> Result<Option<Self>, errors::CellFormatError> {
        let stream = match &*relay {
            Some(r) if r.command() == Self::ID => {
                NonZeroU16::new(r.stream()).ok_or(errors::CellFormatError)?
            }
            _ => return Ok(None),
        };

        Ok(Some(Self {
            stream,
            data: RelayWrapper::from(FixedCell::from(relay.take().unwrap())),
        }))
    }
}

impl IntoRelay for RelayData {
    fn into_relay(self, circuit: NonZeroU32) -> Relay {
        with_cmd_stream(self.data, Self::ID, self.stream.into(), circuit)
    }
}

impl RelayData {
    /// RELAY_DATA command ID.
    pub const ID: u8 = 2;

    /// Creates RELAY_DATA cell from [`FixedCell`].
    ///
    /// # Safety
    ///
    /// Cell must be a valid RELAY_DATA cell.
    pub unsafe fn from_cell(cell: FixedCell) -> Self {
        let data = RelayWrapper::from(cell);
        debug_assert_eq!(data.command(), Self::ID);

        Self {
            stream: NonZeroU16::new(data.stream()).expect("stream ID is zero"),
            data,
        }
    }

    /// Creates new RELAY_DATA cell.
    ///
    /// # Parameters
    ///
    /// - `cell` : Cached [`FixedCell`].
    /// - `stream` : Stream ID.
    /// - `data` : Cell data.
    ///
    /// # Panics
    ///
    /// Panics if data is longer than [`RELAY_DATA_LENGTH`](`super::RELAY_DATA_LENGTH`).
    ///
    /// # Example
    ///
    /// ```
    /// use std::num::NonZeroU16;
    ///
    /// use onioncloud_lowlevel::cell::relay::data::RelayData;
    ///
    /// let cell = RelayData::new(
    ///     Default::default(),
    ///     NonZeroU16::new(1).unwrap(),
    ///     b"123",
    /// );
    ///
    /// assert_eq!(cell.data(), b"123");
    /// ```
    pub fn new(cell: FixedCell, stream: NonZeroU16, data: &[u8]) -> Self {
        let mut cell = RelayWrapper::from(cell);
        cell.set_data(data);

        Self { stream, data: cell }
    }

    /// Creates new RELAY_DATA cell with multipart data.
    ///
    /// # Parameters
    ///
    /// - `cell` : Cached [`FixedCell`].
    /// - `stream` : Stream ID.
    /// - `data` : Cell data in multiple byte slices.
    ///
    /// # Panics
    ///
    /// Panics if data is longer than [`RELAY_DATA_LENGTH`](`super::RELAY_DATA_LENGTH`).
    ///
    /// # Example
    ///
    /// ```
    /// use std::num::NonZeroU16;
    ///
    /// use onioncloud_lowlevel::cell::relay::data::RelayData;
    ///
    /// let cell = RelayData::new_multipart(
    ///     Default::default(),
    ///     NonZeroU16::new(1).unwrap(),
    ///     [&b"123"[..], &b"456"[..]],
    /// );
    ///
    /// assert_eq!(cell.data(), b"123456");
    /// ```
    pub fn new_multipart<'a>(
        cell: FixedCell,
        stream: NonZeroU16,
        data: impl IntoIterator<Item = &'a [u8]>,
    ) -> Self {
        let mut cell = RelayWrapper::from(cell);

        let l = fill_data_multipart(data, cell.data_padding_mut());
        // SAFETY: Data is filled to length.
        unsafe {
            cell.set_len(l as _);
        }

        Self { stream, data: cell }
    }

    /// Get cell content.
    pub fn data(&self) -> &[u8] {
        self.data.data()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use proptest::collection::vec;
    use proptest::prelude::*;

    use crate::cell::relay::RELAY_DATA_LENGTH;
    use crate::cell::relay::tests::assert_relay_eq;

    #[test]
    #[should_panic]
    fn test_data_overflow() {
        let cell = RelayData::new(
            FixedCell::default(),
            NonZeroU16::new(1).unwrap(),
            &[0; const { RELAY_DATA_LENGTH + 1 }],
        );
        println!("{:?}", cell.data.data());
    }

    proptest! {
        #[test]
        fn test_data(
            stream: NonZeroU16,
            data in vec(any::<u8>(), 0..=RELAY_DATA_LENGTH),
        ) {
            let cell = RelayData::new(FixedCell::default(), stream, &data);

            assert_eq!(cell.stream, stream);
            assert_eq!(cell.data(), data);
        }

        #[test]
        fn test_data_from_into_relay(
            stream: NonZeroU16,
            data in vec(any::<u8>(), 0..=RELAY_DATA_LENGTH),
        ) {
            let cell = Relay::new(FixedCell::default(), NonZeroU32::new(1).unwrap(), RelayData::ID, stream.into(), &data);
            let data_ = RelayWrapper::from(AsRef::<FixedCell>::as_ref(&cell).clone());
            let cell = RelayData::try_from_relay(&mut Some(cell)).unwrap().unwrap();

            assert_eq!(cell.stream, stream);
            assert_eq!(cell.data(), data);

            let cell = cell.into_relay(NonZeroU32::new(1).unwrap());

            assert_relay_eq(&cell, &data_);
        }
    }
}
