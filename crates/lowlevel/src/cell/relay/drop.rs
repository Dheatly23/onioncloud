use std::num::{NonZeroU16, NonZeroU32};

use rand::prelude::*;

use super::{
    IntoRelay, RELAY_DATA_LENGTH, Relay, RelayLike, RelayWrapper, TryFromRelay, with_cmd_stream,
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

impl IntoRelay for RelayDrop {
    fn into_relay(self, circuit: NonZeroU32) -> Relay {
        with_cmd_stream(self.data, Self::ID, self.stream.into(), circuit)
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
    pub unsafe fn from_cell(cell: FixedCell) -> Self {
        let data = RelayWrapper::from(cell);
        debug_assert_eq!(data.command(), Self::ID);

        Self {
            stream: NonZeroU16::new(data.stream()).expect("stream ID is zero"),
            data,
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
    /// # Panics
    ///
    /// Panics if data length is bigger than [`RELAY_DATA_LENGTH`].
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
    /// );
    ///
    /// assert_eq!(cell.len(), 123);
    /// ```
    pub fn new(cell: FixedCell, stream: NonZeroU16, len: usize) -> Self {
        assert!(len <= RELAY_DATA_LENGTH, "length is too long");

        let mut data = RelayWrapper::from(cell);

        // SAFETY: Length is checked.
        unsafe {
            data.set_len(len as u16);
        }

        ThreadRng::default().fill_bytes(data.data_mut());

        Self { stream, data }
    }

    /// Get cell length.
    pub fn len(&self) -> usize {
        self.data.len().into()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use proptest::collection::vec;
    use proptest::prelude::*;

    use crate::cell::relay::tests::assert_relay_eq;

    #[test]
    #[should_panic(expected = "length is too long")]
    fn test_drop_overflow() {
        let cell = RelayDrop::new(
            FixedCell::default(),
            NonZeroU16::new(1).unwrap(),
            RELAY_DATA_LENGTH + 1,
        );
        println!("{:?}", cell.data.data());
    }

    proptest! {
        #[test]
        fn test_drop(
            stream: NonZeroU16,
            len in 0..=RELAY_DATA_LENGTH,
        ) {
            let cell = RelayDrop::new(FixedCell::default(), stream, len);

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
            let cell = RelayDrop::try_from_relay(&mut Some(cell)).unwrap().unwrap();

            assert_eq!(cell.stream, stream);
            assert_eq!(cell.len(), len);

            let cell = cell.into_relay(NonZeroU32::new(1).unwrap());

            assert_relay_eq(&cell, &data);
        }
    }
}
