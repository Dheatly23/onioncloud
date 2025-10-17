use std::num::{NonZeroU16, NonZeroU32};

use super::{
    IntoRelay, Relay, RelayV001, RelayVersion, RelayWrapper, TryFromRelay, take_if_nonzero_stream,
    v0, v1, with_cmd_stream,
};
use crate::cache::Cachable;
use crate::cell::FixedCell;
use crate::errors;

/// Represents a RELAY_DATA cell.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct RelayData {
    /// Stream ID.
    pub stream: NonZeroU16,
    /// Cell payload.
    data: RelayWrapper,
    /// Relay version.
    version: Option<RelayVersion>,
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
    fn try_from_relay(
        relay: &mut Option<Relay>,
        version: RelayVersion,
    ) -> Result<Option<Self>, errors::CellFormatError> {
        take_if_nonzero_stream(relay, Self::ID, version, |_| true).map(|v| {
            v.map(|(stream, data)| Self {
                stream,
                data,
                version: Some(version),
            })
        })
    }
}

impl IntoRelay for RelayData {
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

impl RelayData {
    /// RELAY_DATA command ID.
    pub const ID: u8 = 2;

    /// Creates RELAY_DATA cell from [`FixedCell`].
    ///
    /// # Safety
    ///
    /// Cell must be a valid RELAY_DATA cell.
    pub unsafe fn from_cell(cell: FixedCell, version: RelayVersion) -> Self {
        let data = RelayWrapper::from(cell);

        let (command, stream) = match version {
            RelayVersion::V0 => (v0::RelayExt::command(&data), v0::RelayExt::stream(&data)),
            RelayVersion::V1 => (v1::RelayExt::command(&data), v1::RelayExt::stream(&data)),
        };
        debug_assert_eq!(command, Self::ID);

        Self {
            stream: unsafe { NonZeroU16::new_unchecked(stream) },
            data,
            version: Some(version),
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
    /// # Return
    ///
    /// Returns RELAY_DATA cell or error if data overflows cell.
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
    /// ).unwrap();
    ///
    /// assert_eq!(cell.data(), b"123");
    /// ```
    pub fn new(
        cell: FixedCell,
        stream: NonZeroU16,
        data: &[u8],
    ) -> Result<Self, errors::CellLengthOverflowError> {
        let mut cell = RelayWrapper::from(cell);
        let RelayV001 { len, data: a } = RelayV001::from_mut(&mut cell);

        a.get_mut(..data.len())
            .ok_or(errors::CellLengthOverflowError)?
            .copy_from_slice(data);
        len.set(data.len() as _);

        Ok(Self {
            stream,
            data: cell,
            version: None,
        })
    }

    /// Creates new RELAY_DATA cell with multipart data.
    ///
    /// # Parameters
    ///
    /// - `cell` : Cached [`FixedCell`].
    /// - `stream` : Stream ID.
    /// - `data` : Cell data in multiple byte slices.
    ///
    /// # Return
    ///
    /// Returns RELAY_DATA cell or error if data overflows cell.
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
    /// ).unwrap();
    ///
    /// assert_eq!(cell.data(), b"123456");
    /// ```
    pub fn new_multipart<'a>(
        cell: FixedCell,
        stream: NonZeroU16,
        data: impl IntoIterator<Item = &'a [u8]>,
    ) -> Result<Self, errors::CellLengthOverflowError> {
        let mut cell = RelayWrapper::from(cell);
        let RelayV001 { len, data: a } = RelayV001::from_mut(&mut cell);

        let mut l = 0u16;
        let mut a = &mut a[..];
        for v in data {
            let Some((s, r)) = a.split_at_mut_checked(v.len()) else {
                return Err(errors::CellLengthOverflowError);
            };
            s.copy_from_slice(v);
            l += v.len() as u16;
            a = r;
        }
        len.set(l);

        Ok(Self {
            stream,
            data: cell,
            version: None,
        })
    }

    /// Get cell content.
    pub fn data(&self) -> &[u8] {
        match self.version {
            None => RelayV001::from_ref(&self.data).data(),
            Some(RelayVersion::V0) => v0::RelayExt::data(&self.data),
            Some(RelayVersion::V1) => v1::RelayExt::data(&self.data),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use proptest::collection::vec;
    use proptest::prelude::*;

    use crate::cell::FIXED_CELL_SIZE;
    use crate::cell::relay::v0::RELAY_DATA_LENGTH;
    use crate::cell::relay::v0::tests::assert_relay_eq;

    #[test]
    fn test_data_overflow() {
        let ret = RelayData::new(
            FixedCell::default(),
            NonZeroU16::new(1).unwrap(),
            &[0; const { FIXED_CELL_SIZE - 1 }],
        );
        assert!(ret.is_err(), "expect error, got {ret:?}");
    }

    proptest! {
        #[test]
        fn test_data(
            stream: NonZeroU16,
            data in vec(any::<u8>(), 0..=FIXED_CELL_SIZE - 2),
        ) {
            let cell = RelayData::new(FixedCell::default(), stream, &data).unwrap();

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
            let cell = RelayData::try_from_relay(&mut Some(cell), RelayVersion::V0).unwrap().unwrap();

            assert_eq!(cell.stream, stream);
            assert_eq!(cell.data(), data);

            let cell = cell.try_into_relay(NonZeroU32::new(1).unwrap(), RelayVersion::V0).unwrap();

            assert_relay_eq(&cell, &data_);
        }
    }
}
