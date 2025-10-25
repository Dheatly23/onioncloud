use std::num::{NonZeroU16, NonZeroU32};

use super::{
    IntoRelay, Relay, RelayVersion, RelayWrapper, TryFromRelay, set_cmd_stream_v0,
    set_cmd_stream_v1, take_if_nonzero_stream, v0, v1,
};
use crate::cache::{Cachable, Cached, CellCache};
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
    fn cache<C: CellCache + ?Sized>(self, cache: &C) {
        self.data.cache(cache);
    }
}

impl TryFromRelay for RelayBeginDir {
    fn try_from_relay(
        relay: &mut Option<Relay>,
        version: RelayVersion,
    ) -> Result<Option<Self>, errors::CellFormatError> {
        take_if_nonzero_stream(relay, Self::ID, version, |_| true)
            .map(|v| v.map(|(stream, data)| Self { stream, data }))
    }
}

impl IntoRelay for RelayBeginDir {
    fn try_into_relay(
        mut self,
        circuit: NonZeroU32,
        version: RelayVersion,
    ) -> Result<Relay, errors::CellLengthOverflowError> {
        match version {
            RelayVersion::V0 => {
                v0::RelayExt::set_data(&mut self.data, &[]);
                set_cmd_stream_v0(Self::ID, self.stream.into(), &mut self.data)
            }
            RelayVersion::V1 => {
                v1::RelayExt::set_data(&mut self.data, &[]);
                set_cmd_stream_v1(Self::ID, self.stream.into(), &mut self.data)
            }
        }
        Ok(self.data.into_relay(circuit))
    }

    fn try_into_relay_cached<C: CellCache>(
        mut this: Cached<Self, C>,
        circuit: NonZeroU32,
        version: RelayVersion,
    ) -> Result<Cached<Relay, C>, errors::CellLengthOverflowError> {
        match version {
            RelayVersion::V0 => {
                v0::RelayExt::set_data(&mut this.data, &[]);
                set_cmd_stream_v0(Self::ID, this.stream.into(), &mut this.data)
            }
            RelayVersion::V1 => {
                v1::RelayExt::set_data(&mut this.data, &[]);
                set_cmd_stream_v1(Self::ID, this.stream.into(), &mut this.data)
            }
        }
        Ok(Cached::map(this, |v| v.data.into_relay(circuit)))
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
