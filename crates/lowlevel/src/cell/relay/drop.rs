use std::num::{NonZeroU16, NonZeroU32};

use rand::prelude::*;

use super::{
    IntoRelay, Relay, RelayV001, RelayVersion, RelayWrapper, TryFromRelay, take_if_nonzero_stream,
    v0, v1, with_cmd_stream,
};
use crate::cache::Cachable;
use crate::cell::FixedCell;
use crate::errors;

/// Represents a RELAY_DROP cell.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct RelayDrop {
    /// Stream ID.
    pub stream: NonZeroU16,
    /// Cell payload.
    data: RelayWrapper,
    /// Relay version.
    version: Option<RelayVersion>,
}

impl AsRef<FixedCell> for RelayDrop {
    fn as_ref(&self) -> &FixedCell {
        self.data.as_ref()
    }
}

impl Cachable for RelayDrop {
    fn maybe_into_fixed(self) -> Option<FixedCell> {
        Some(self.data.into())
    }
}

impl TryFromRelay for RelayDrop {
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

impl IntoRelay for RelayDrop {
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

impl RelayDrop {
    /// RELAY_DROP command ID.
    pub const ID: u8 = 2;

    /// Creates RELAY_DROP cell from [`FixedCell`].
    ///
    /// # Safety
    ///
    /// Cell must be a valid RELAY_DROP cell.
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

    /// Creates new RELAY_DROP cell.
    ///
    /// # Parameters
    ///
    /// - `cell` : Cached [`FixedCell`].
    /// - `stream` : Stream ID.
    /// - `len` : Padding length.
    ///
    /// # Return
    ///
    /// Returns RELAY_DROP cell or error if data overflows cell.
    ///
    /// # Example
    ///
    /// ```
    /// use std::num::NonZeroU16;
    ///
    /// use onioncloud_lowlevel::cell::relay::drop::RelayDrop;
    ///
    /// let cell = RelayDrop::new(
    ///     Default::default(),
    ///     NonZeroU16::new(1).unwrap(),
    ///     123,
    /// ).unwrap();
    ///
    /// assert_eq!(cell.len(), 123);
    /// ```
    pub fn new(
        cell: FixedCell,
        stream: NonZeroU16,
        len: usize,
    ) -> Result<Self, errors::CellLengthOverflowError> {
        let mut data = RelayWrapper::from(cell);
        let RelayV001 { len: l, data: a } = RelayV001::from_mut(&mut data);

        if len > a.len() {
            return Err(errors::CellLengthOverflowError);
        }
        ThreadRng::default().fill_bytes(a);
        l.set(len as _);

        Ok(Self {
            stream,
            data,
            version: None,
        })
    }

    /// Get cell length.
    pub fn len(&self) -> usize {
        match self.version {
            None => RelayV001::from_ref(&self.data).len.get(),
            Some(RelayVersion::V0) => v0::RelayExt::len(&self.data),
            Some(RelayVersion::V1) => v1::RelayExt::len(&self.data),
        }
        .into()
    }

    /// Returns `true` if cell is empty.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
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
    fn test_drop_overflow() {
        let ret = RelayDrop::new(
            FixedCell::default(),
            NonZeroU16::new(1).unwrap(),
            FIXED_CELL_SIZE - 1,
        );
        assert!(ret.is_err(), "expect error, got {ret:?}");
    }

    proptest! {
        #[test]
        fn test_drop(
            stream: NonZeroU16,
            len in 0..=FIXED_CELL_SIZE - 2,
        ) {
            let cell = RelayDrop::new(FixedCell::default(), stream, len).unwrap();

            assert_eq!(cell.stream, stream);
            assert_eq!(cell.len(), len);
        }

        #[test]
        fn test_drop_from_into_relay(
            stream: NonZeroU16,
            data in vec(any::<u8>(), 0..=RELAY_DATA_LENGTH),
        ) {
            let len = data.len();
            let cell = Relay::new(FixedCell::default(), NonZeroU32::new(1).unwrap(), RelayDrop::ID, stream.into(), &data);
            drop(data);
            let data = RelayWrapper::from(AsRef::<FixedCell>::as_ref(&cell).clone());
            let cell = RelayDrop::try_from_relay(&mut Some(cell), RelayVersion::V0).unwrap().unwrap();

            assert_eq!(cell.stream, stream);
            assert_eq!(cell.len(), len);

            let cell = cell.try_into_relay(NonZeroU32::new(1).unwrap(), RelayVersion::V0).unwrap();

            assert_relay_eq(&cell, &data);
        }
    }
}
