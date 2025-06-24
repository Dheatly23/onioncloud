use std::num::{NonZeroU16, NonZeroU32};

use super::{IntoRelay, Relay, RelayLike, RelayWrapper, TryFromRelay, with_cmd_stream};
use crate::cell::FixedCell;
use crate::errors;

/// Represents a RELAY_BEGIN_DIR cell.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct RelayBeginDir {
    /// Stream ID.
    pub stream: NonZeroU16,
    /// Cell payload.
    data: RelayWrapper,
}

impl AsRef<FixedCell> for RelayBeginDir {
    fn as_ref(&self) -> &FixedCell {
        self.data.as_ref()
    }
}

impl TryFromRelay for RelayBeginDir {
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

impl IntoRelay for RelayBeginDir {
    fn into_relay(mut self, circuit: NonZeroU32) -> Relay {
        self.data.set_data(&[]);
        with_cmd_stream(self.data, Self::ID, self.stream.into(), circuit)
    }
}

impl RelayBeginDir {
    /// RELAY_BEGIN_DIR command ID.
    pub const ID: u8 = 13;

    /// Creates RELAY_BEGIN_DIR cell from [`FixedCell`].
    ///
    /// # Safety
    ///
    /// Cell must be a valid RELAY_BEGIN_DIR cell.
    pub unsafe fn from_cell(cell: FixedCell) -> Self {
        let data = RelayWrapper::from(cell);
        debug_assert_eq!(data.command(), Self::ID);

        Self {
            stream: NonZeroU16::new(data.stream()).expect("stream ID is zero"),
            data,
        }
    }

    /// Creates new RELAY_BEGIN_DIR cell.
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
    /// use onioncloud_lowlevel::cell::relay::begin_dir::RelayBeginDir;
    ///
    /// let cell = RelayBeginDir::new(
    ///     Default::default(),
    ///     NonZeroU16::new(1).unwrap(),
    /// );
    /// ```
    pub fn new(cell: FixedCell, stream: NonZeroU16) -> Self {
        Self {
            stream,
            data: RelayWrapper::from(cell),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::cell::relay::tests::assert_relay_eq;

    #[test]
    fn test_begin_dir() {
        let stream = NonZeroU16::new(0x1234).unwrap();
        let circuit = NonZeroU32::new(227020 + 226554).unwrap();
        let cell = RelayBeginDir::new(FixedCell::default(), stream).into_relay(circuit);

        assert_relay_eq(
            &cell,
            &Relay::new(
                FixedCell::default(),
                circuit,
                RelayBeginDir::ID,
                stream.into(),
                &[],
            ),
        );
    }
}
