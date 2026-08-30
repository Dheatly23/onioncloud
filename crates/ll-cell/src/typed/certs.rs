//! `CERTS` cell type.

use std::fmt::{Debug, Formatter, Result as FmtResult, from_fn};
use std::mem::size_of;
use std::num::NonZeroUsize;
use std::ops::Deref;
use std::ptr::from_ref;

use zerocopy::byteorder::big_endian::U16;
use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout, SplitAt, Unaligned};

use crate::cell::{AutoReturnVariable, Cell, CellHeader, TryFromCell};
use crate::error::{CellCastError, CellFormatError, NonZeroCircID, VariableCellTooLong};
use crate::variable::VariableCell;

/// `CERTS` header.
#[derive(FromBytes, SplitAt, Immutable, KnownLayout, Unaligned)]
#[repr(C)]
struct CertsHeader {
    n_certs: u8,
    data: [u8],
}

/// Certificate header.
#[derive(FromBytes, IntoBytes, Immutable, KnownLayout, Unaligned)]
#[repr(C)]
struct CertDataHeader {
    ty: u8,
    len: U16,
}

/// A single certificate.
#[derive(FromBytes, SplitAt, Immutable, KnownLayout, Unaligned)]
#[repr(C)]
struct CertData {
    header: CertDataHeader,
    data: [u8],
}

/// `CERTS` cell.
///
/// See also: [spec](https://spec.torproject.org/tor-spec/negotiating-channels.html#CERTS-cells).
pub struct Certs {
    cell: VariableCell,
}

impl Debug for Certs {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        f.debug_struct("Certs")
            .field("certs", &from_fn(|f| f.debug_list().entries(self).finish()))
            .finish()
    }
}

impl TryFromCell for Certs {
    type Error = CellCastError;

    fn try_from_cell(cell: &mut Option<Cell>) -> Result<Option<Self>, Self::Error> {
        if let Some(cell) = AutoReturnVariable::new(cell)?
            && cell.header().command == Self::ID
        {
            if cell.header().circuit != 0 {
                Err(NonZeroCircID.into())
            } else if Self::validate_cell(cell.data().data()) {
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

impl From<Certs> for Cell {
    fn from(cell: Certs) -> Self {
        Self::from_variable(
            CellHeader {
                command: Certs::ID,
                circuit: 0,
            },
            cell.into_inner(),
        )
    }
}

impl From<Certs> for VariableCell {
    #[inline]
    fn from(v: Certs) -> VariableCell {
        v.into_inner()
    }
}

impl AsRef<VariableCell> for Certs {
    #[inline]
    fn as_ref(&self) -> &VariableCell {
        self.inner()
    }
}

impl Certs {
    /// Cell ID of `CERTS`.
    pub const ID: u8 = 129;

    /// Creates new [`Certs`] cell from iterator of certificates.
    ///
    /// # Errors
    ///
    /// Returns [`VariableCellTooLong`] if cell is too long.
    pub fn try_from_iter<I, T>(it: I) -> Result<Self, VariableCellTooLong>
    where
        I: IntoIterator<Item = Cert<T>>,
        T: Deref<Target = [u8]>,
    {
        let mut v = vec![0u8];
        for c in it {
            v[0] = v[0].checked_add(1).ok_or_else(|| VariableCellTooLong {
                len: NonZeroUsize::new(65536).unwrap(),
            })?;

            let s = &*c.data;
            if let Some(l) = NonZeroUsize::new(
                v.len()
                    .saturating_add(size_of::<CertDataHeader>())
                    .saturating_add(s.len()),
            ) && l.get() > 65535
            {
                return Err(VariableCellTooLong { len: l });
            }
            debug_assert!(s.len() < 65536, "{} >= 65536", s.len());

            v.extend_from_slice(
                CertDataHeader {
                    ty: c.ty,
                    len: U16::new(s.len() as u16),
                }
                .as_bytes(),
            );
            v.extend_from_slice(s);
            debug_assert!(v.len() < 65536, "{} >= 65536", v.len());
        }

        debug_assert!(Self::validate_cell(&v), "cell format should be valid");
        v.try_into().map(|cell| Self { cell })
    }

    /// Gets reference to inner.
    #[inline]
    #[must_use]
    pub fn inner(&self) -> &VariableCell {
        &self.cell
    }

    /// Unwraps into inner.
    #[inline]
    #[must_use]
    pub fn into_inner(self) -> VariableCell {
        self.cell
    }

    /// Iterates through [`Cert`]s.
    #[inline]
    pub fn iter<'a>(&'a self) -> CertsIter<'a> {
        self.into_iter()
    }

    fn validate_cell(s: &[u8]) -> bool {
        let Ok(t) = CertsHeader::ref_from_bytes(s) else {
            return false;
        };
        let mut n = t.n_certs;
        let mut s = &t.data;

        while n > 0 {
            let Ok(t) = CertData::ref_from_bytes(s) else {
                return false;
            };
            let Some(t) = t.split_at(t.header.len.get() as usize) else {
                return false;
            };
            s = t.via_immutable().1;
            n -= 1;
        }

        true
    }
}

/// A single certificate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Cert<T> {
    /// Certificate type.
    pub ty: u8,
    /// Certificate data.
    pub data: T,
}

impl<T> Cert<T> {
    /// Casts [`data`](`Self::data`) from one type to another.
    #[inline]
    pub fn cast_data<U: From<T>>(self) -> Cert<U> {
        Cert {
            ty: self.ty,
            data: self.data.into(),
        }
    }
}

impl<'a> IntoIterator for &'a Certs {
    type Item = Cert<&'a [u8]>;
    type IntoIter = CertsIter<'a>;

    #[inline]
    fn into_iter(self) -> Self::IntoIter {
        let s = self.cell.data();
        // SAFETY: Cell content has been validated before.
        let (n, s) = unsafe { (*s.get_unchecked(0), s.get_unchecked(1..)) };

        Self::IntoIter { n, s }
    }
}

/// Iterator for [`Certs`].
#[derive(Clone)]
#[must_use = "iterator does nothing if not used"]
pub struct CertsIter<'a> {
    s: &'a [u8],
    n: u8,
}

impl<'a> Iterator for CertsIter<'a> {
    type Item = Cert<&'a [u8]>;

    fn next(&mut self) -> Option<Self::Item> {
        self.n = self.n.checked_sub(1)?;

        // SAFETY: Cell content has been validated before.
        unsafe {
            let (a, b) = self.s.split_at_unchecked(size_of::<CertDataHeader>());
            let CertDataHeader { ty, len } = *from_ref(a).cast();
            let (data, s) = b.split_at_unchecked(len.get() as usize);

            self.s = s;
            Some(Cert { ty, data })
        }
    }

    #[inline]
    fn size_hint(&self) -> (usize, Option<usize>) {
        let l = self.len();
        (l, Some(l))
    }
}

impl<'a> ExactSizeIterator for CertsIter<'a> {
    #[inline]
    fn len(&self) -> usize {
        self.n as _
    }
}
