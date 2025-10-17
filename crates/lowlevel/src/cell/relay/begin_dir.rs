use std::num::{NonZeroU16, NonZeroU32};

use super::{
    IntoRelay, Relay, RelayVersion, RelayWrapper, TryFromRelay, get_stream_if_command_match, v0,
    v1, with_cmd_stream_v0, with_cmd_stream_v1,
};
use crate::cache::Cachable;
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

impl Cachable for RelayBeginDir {
    fn maybe_into_fixed(self) -> Option<FixedCell> {
        Some(self.data.into())
    }
}

impl TryFromRelay for RelayBeginDir {
    fn try_from_relay(
        relay: &mut Option<Relay>,
        version: RelayVersion,
    ) -> Result<Option<Self>, errors::CellFormatError> {
        let Some(stream) = get_stream_if_command_match(relay, version, Self::ID)? else {
            return Ok(None);
        };

        Ok(Some(Self {
            stream,
            // SAFETY: Relay is Some
            data: FixedCell::from(unsafe { relay.take().unwrap_unchecked() }).into(),
        }))
    }
}

impl IntoRelay for RelayBeginDir {
    fn try_into_relay(
        mut self,
        circuit: NonZeroU32,
        version: RelayVersion,
    ) -> Result<Relay, errors::CellLengthOverflowError> {
        Ok(match version {
            RelayVersion::V0 => {
                v0::RelayExt::set_data(&mut self.data, &[]);
                with_cmd_stream_v0(self.data, Self::ID, self.stream.into(), circuit)
            }
            RelayVersion::V1 => {
                v1::RelayExt::set_data(&mut self.data, &[]);
                with_cmd_stream_v1(self.data, Self::ID, self.stream.into(), circuit)
            }
        })
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

    use crate::cell::relay::v0::tests::assert_relay_eq;
    use crate::cell::relay::v1::tests::assert_relay_eq as assert_relay_eq_v1;

    #[test]
    fn test_begin_dir() {
        let stream = NonZeroU16::new(0x1234).unwrap();
        let circuit = NonZeroU32::new(227020 + 226554).unwrap();
        let cell = RelayBeginDir::new(FixedCell::default(), stream);

        assert_relay_eq(
            &cell
                .clone()
                .try_into_relay(circuit, RelayVersion::V0)
                .unwrap(),
            &Relay::new(
                FixedCell::default(),
                circuit,
                RelayBeginDir::ID,
                stream.into(),
                &[],
            ),
        );

        assert_relay_eq_v1(
            &cell.try_into_relay(circuit, RelayVersion::V1).unwrap(),
            &Relay::new_v1(
                FixedCell::default(),
                circuit,
                RelayBeginDir::ID,
                stream.into(),
                &[],
            ),
        );
    }
}
