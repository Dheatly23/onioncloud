use std::mem::size_of;
use std::slice::{from_raw_parts, from_raw_parts_mut};

use zerocopy::FromBytes;
use zerocopy::byteorder::big_endian::U16;

use super::{Cell, CellHeader, CellLike, CellRef, TryFromCell, VariableCell, to_variable_with};
use crate::errors;

/// Represents a VERSIONS cell.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Versions(VariableCell);

impl AsRef<[U16]> for Versions {
    fn as_ref(&self) -> &[U16] {
        self.data()
    }
}

impl AsMut<[U16]> for Versions {
    fn as_mut(&mut self) -> &mut [U16] {
        self.data_mut()
    }
}

impl From<Versions> for Cell {
    fn from(v: Versions) -> Cell {
        Cell::from_variable(CellHeader::new(0, Versions::ID), v.into_inner())
    }
}

impl FromIterator<u16> for Versions {
    fn from_iter<T: IntoIterator<Item = u16>>(it: T) -> Self {
        let data = VariableCell::from(
            it.into_iter()
                .flat_map(|v| v.to_be_bytes())
                .collect::<Vec<_>>(),
        );
        // SAFETY: Data is valid
        unsafe { Self::new(data) }
    }
}

impl TryFromCell for Versions {
    fn try_from_cell(cell: &mut Option<Cell>) -> Result<Option<Self>, errors::CellFormatError> {
        let Some(
            c @ Cell {
                command: Self::ID, ..
            },
        ) = cell.as_ref()
        else {
            return Ok(None);
        };
        if c.circuit != 0 {
            return Err(errors::CellFormatError);
        }
        to_variable_with(cell, Self::check).map(|v| v.map(|v| unsafe { Self::new(v) }))
    }
}

impl CellLike for Versions {
    fn circuit(&self) -> u32 {
        0
    }

    fn command(&self) -> u8 {
        Self::ID
    }

    fn cell(&self) -> CellRef<'_> {
        CellRef::Variable(&self.0)
    }
}

impl Versions {
    /// VERSIONS command ID.
    pub const ID: u8 = 7;

    /// Creates new VERSIONS cell.
    ///
    /// # Safety
    ///
    /// Data must be a 2-byte array of [`U16`].
    pub unsafe fn new(data: VariableCell) -> Self {
        debug_assert!(<[U16]>::ref_from_bytes(data.data()).is_ok());
        Self(data)
    }

    /// Creates VERSIONS cell from a list of protocol versions to be negotiated.
    ///
    /// Note that version is not deduplicated nor checked for validity (e.g zero is not allowed).
    /// It is the responsibility of implementer to do all that.
    ///
    /// ```
    /// use onioncloud_lowlevel::cell::versions::Versions;
    ///
    /// let cell = Versions::from_list(&[1, 2, 3]);
    /// ```
    pub fn from_list(data: &[u16]) -> Self {
        Self::from_iter(data.iter().copied())
    }

    /// Gets reference into versions data.
    pub fn data(&self) -> &[U16] {
        let s = self.0.data();
        // SAFETY: Data has been checked
        // XXX: Use zerocopy instead?
        unsafe { from_raw_parts((s as *const [u8]).cast::<U16>(), s.len() / size_of::<U16>()) }
    }

    /// Gets mutable reference into versions data.
    pub fn data_mut(&mut self) -> &mut [U16] {
        let s = self.0.data_mut();
        // SAFETY: Data has been checked
        // XXX: Use zerocopy instead?
        unsafe { from_raw_parts_mut((s as *mut [u8]).cast::<U16>(), s.len() / size_of::<U16>()) }
    }

    /// Unwraps into inner [`VariableCell`].
    pub fn into_inner(self) -> VariableCell {
        self.0
    }

    fn check(data: &[u8]) -> bool {
        <[U16]>::ref_from_bytes(data).is_ok()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use proptest::prelude::*;

    proptest! {
        #[test]
        fn test_versions_from_list(versions: Vec<u16>) {
            let cell = Versions::from_list(&versions);
            assert_eq!(cell.data(), versions);
        }

        #[test]
        fn test_versions_from_iter(mut versions: Vec<u16>) {
            let cell = Versions::from_iter(versions.iter().map(|v| v.reverse_bits()));
            for v in &mut versions {
                *v = v.reverse_bits();
            }
            assert_eq!(cell.data(), versions);
        }

        #[test]
        fn test_versions_content(versions: Vec<u16>) {
            let data = Versions::from_list(&versions).into_inner();
            assert_eq!(data.data(), versions.into_iter().flat_map(|v| v.to_be_bytes()).collect::<Vec<_>>());
        }
    }
}
