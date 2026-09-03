//! `VERSIONS` cell types.

use std::num::NonZeroUsize;
use std::ptr::{from_mut, from_ref};
use std::slice::{from_raw_parts, from_raw_parts_mut};

use zerocopy::FromBytes;
use zerocopy::byteorder::big_endian::U16;

use crate::cell::{AutoReturnVariable, Cell, CellHeader, TryFromCell};
use crate::error::{CellCastError, CellFormatError, NonZeroCircID, VariableCellTooLong};
use crate::variable::VariableCell;

/// `VERSIONS` cell.
///
/// See also: [spec](https://spec.torproject.org/tor-spec/negotiating-channels.html#VERSIONS-cells).
///
/// # A Note on [`Versions`] Content.
///
/// In the spec, it's not defined in what order and if duplicates are allowed.
/// As such, [`TryFromCell`] impl does not enforce any of it, it only checks if the length is correct.
/// But, users **SHOULD** sort the versions in strictly ascending order and not zero.
///
/// Sorting can be done in post by:
///
/// ```
/// # use onioncloud_ll_cell::typed::Versions;
/// // Unsorted and contains duplicate
/// let mut cell = Versions::try_from_slice(&[1, 2, 3, 1, 4, 3]).unwrap();
///
/// // Sort
/// let data = cell.data_mut();
/// data.sort_unstable();
///
/// // Deduplicate
/// // let data = data.partition_dedup().0;
/// ```
#[derive(Debug)]
pub struct Versions {
    cell: VariableCell,
}

impl TryFromCell for Versions {
    type Error = CellCastError;

    fn try_from_cell(cell: &mut Option<Cell>) -> Result<Option<Self>, Self::Error> {
        if let Some(cell) = AutoReturnVariable::new(cell)?
            && cell.header().command == Self::ID
        {
            if cell.header().circuit != 0 {
                Err(NonZeroCircID.into())
            } else if <[U16] as FromBytes>::ref_from_bytes(cell.data().data()).is_ok() {
                Ok(Some(Self {
                    cell: cell.into_inner().1,
                }))
            } else {
                Err(CellFormatError.into())
            }
        } else {
            Ok(None)
        }
    }
}

impl From<Versions> for Cell {
    fn from(cell: Versions) -> Self {
        Self::from_variable(
            CellHeader {
                command: Versions::ID,
                circuit: 0,
            },
            cell.into_inner(),
        )
    }
}

impl From<Versions> for VariableCell {
    #[inline]
    fn from(v: Versions) -> VariableCell {
        v.into_inner()
    }
}

impl AsRef<VariableCell> for Versions {
    #[inline]
    fn as_ref(&self) -> &VariableCell {
        self.inner()
    }
}

impl AsMut<VariableCell> for Versions {
    #[inline]
    fn as_mut(&mut self) -> &mut VariableCell {
        self.inner_mut()
    }
}

impl AsRef<[U16]> for Versions {
    #[inline]
    fn as_ref(&self) -> &[U16] {
        self.data()
    }
}

impl AsMut<[U16]> for Versions {
    #[inline]
    fn as_mut(&mut self) -> &mut [U16] {
        self.data_mut()
    }
}

impl<'a> TryFrom<&'a [u16]> for Versions {
    type Error = VariableCellTooLong;

    #[inline]
    fn try_from(s: &'a [u16]) -> Result<Self, Self::Error> {
        Self::try_from_slice(s)
    }
}

impl Versions {
    /// Cell ID of `VERSIONS`.
    pub const ID: u8 = 7;

    /// Creates new [`Versions`] cell from slice of versions.
    ///
    /// # Errors
    ///
    /// Returns [`VariableCellTooLong`] if slice is too long.
    pub fn try_from_slice(data: &[u16]) -> Result<Self, VariableCellTooLong> {
        if data.len() > 32767 {
            return Err(VariableCellTooLong {
                len: NonZeroUsize::new(data.len().saturating_mul(2)).unwrap(),
            });
        }

        let mut v = vec![0u8; data.len() * 2].into_boxed_slice();
        assert_eq!(v.len(), data.len() * 2);
        for (i, &t) in data.iter().enumerate() {
            let j = i * 2;
            // SAFETY: Index is always within bound.
            let o = unsafe { &mut *from_mut(v.get_unchecked_mut(j..j + 2)).cast::<[u8; 2]>() };
            *o = t.to_be_bytes();
        }

        Ok(Self {
            cell: VariableCell::new(v),
        })
    }

    /// Creates new [`Versions`] cell from iterator of versions.
    ///
    /// # Errors
    ///
    /// Returns [`VariableCellTooLong`] if slice is too long.
    pub fn try_from_iter(it: impl IntoIterator<Item = u16>) -> Result<Self, VariableCellTooLong> {
        it.into_iter()
            .flat_map(u16::to_be_bytes)
            .collect::<Vec<u8>>()
            .try_into()
            .map(|cell| Self { cell })
    }

    /// Gets reference to inner.
    #[inline]
    #[must_use]
    pub fn inner(&self) -> &VariableCell {
        &self.cell
    }

    /// Gets mutable reference to inner.
    #[inline]
    #[must_use]
    pub fn inner_mut(&mut self) -> &mut VariableCell {
        &mut self.cell
    }

    /// Gets reference to versions.
    #[inline]
    #[must_use]
    pub fn data(&self) -> &[U16] {
        // SAFETY: Length is already checked to be even.
        unsafe {
            let s = self.cell.data();
            from_raw_parts(from_ref(s).cast::<U16>(), s.len() / 2)
        }
    }

    /// Gets mutable reference to versions.
    #[inline]
    #[must_use]
    pub fn data_mut(&mut self) -> &mut [U16] {
        // SAFETY: Length is already checked to be even.
        unsafe {
            let s = self.cell.data_mut();
            from_raw_parts_mut(from_mut(s).cast::<U16>(), s.len() / 2)
        }
    }

    /// Unwraps into inner.
    #[inline]
    #[must_use]
    pub fn into_inner(self) -> VariableCell {
        self.cell
    }
}
