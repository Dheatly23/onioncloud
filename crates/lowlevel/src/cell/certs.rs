use zerocopy::byteorder::big_endian::U16;
use zerocopy::{FromBytes, Immutable, KnownLayout, SplitAt, Unaligned};

use crate::cell::{
    Cell, CellHeader, CellLike, CellRef, TryFromCell, VariableCell, to_variable_with,
};
use crate::errors;

/// CERTS header.
#[derive(FromBytes, SplitAt, KnownLayout, Immutable, Unaligned)]
#[repr(C)]
struct CertsHeader {
    n_certs: u8,
    data: [u8],
}

/// DST of a single certificate.
#[derive(FromBytes, SplitAt, KnownLayout, Immutable, Unaligned)]
#[repr(C)]
struct CertRef {
    /// Certificate type.
    ///
    /// Used to identify what kind of certificate it is
    ty: u8,

    /// Length of payload.
    length: U16,

    /// Certificate content.
    ///
    /// This data is not validated, it is the responsibility of user
    /// to validate it's valid for the given certificate type.
    data: [u8],
}

/// Certificate data type.
///
/// # Example
///
/// ```
/// use onioncloud_lowlevel::cell::certs::Cert;
///
/// let cert: Cert<Vec<u8>> = Cert {
///     ty: 0,
///     data: vec![0; 10],
/// };
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Cert<T> {
    /// Certificate type.
    ///
    /// Used to identify what kind of certificate it is
    pub ty: u8,

    /// Certificate content.
    ///
    /// It should be a byteslice-like value.
    /// The data is not validated by CERTS, it is the responsibility of user
    /// to validate it's valid for the given certificate type.
    pub data: T,
}

impl<T: AsRef<[u8]>> AsRef<[u8]> for Cert<T> {
    fn as_ref(&self) -> &[u8] {
        self.data.as_ref()
    }
}

impl<T> Cert<T> {
    /// Create new [`Cert`].
    ///
    /// # Example
    ///
    /// ```
    /// use onioncloud_lowlevel::cell::certs::Cert;
    ///
    /// let cert = Cert::<Vec<u8>>::new(0, vec![0; 10]);
    /// ```
    pub fn new(ty: u8, data: T) -> Self {
        Self { ty, data }
    }

    /// Converts from `&Cert<T>` to `Cert<&T>`.
    ///
    /// # Example
    ///
    /// ```
    /// use onioncloud_lowlevel::cell::certs::Cert;
    ///
    /// let cert = Cert::<Vec<u8>>::new(0, vec![0; 10]);
    /// let cert = cert.as_ref();
    /// ```
    pub fn as_ref(&self) -> Cert<&T> {
        Cert {
            ty: self.ty,
            data: &self.data,
        }
    }
}

impl<'a> From<&'a CertRef> for Cert<&'a [u8]> {
    fn from(v: &'a CertRef) -> Self {
        debug_assert_eq!(v.length.get() as usize, v.data.len());

        Self {
            ty: v.ty,
            data: &v.data,
        }
    }
}

/// Represents a CERTS cell.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Certs(VariableCell);

impl From<Certs> for Cell {
    fn from(v: Certs) -> Cell {
        Cell::from_variable(CellHeader::new(0, Certs::ID), v.into_inner())
    }
}

/// Creates CERTS cell from iterator of [`Cert`].
///
/// # Panics
///
/// Panics if one of the following happened:
/// - Number of certificates exceeds 255.
/// - Length of _any_ certificate exceeds 65535.
impl<T: AsRef<[u8]>> FromIterator<Cert<T>> for Certs {
    fn from_iter<It: IntoIterator<Item = Cert<T>>>(it: It) -> Self {
        let mut buf = vec![0];
        let mut n = 0u8;

        for c in it {
            let ty = c.ty;
            let data = c.data.as_ref();

            n = n.checked_add(1).expect("too many certificates!");

            let Ok(l) = u16::try_from(data.len()) else {
                panic!(
                    "certificate {} is too long! (length: {})",
                    n - 1,
                    data.len()
                );
            };
            let [a, b] = l.to_be_bytes();

            buf.reserve(3 + data.len());
            buf.extend_from_slice(&[ty, a, b]);
            buf.extend_from_slice(data);
        }

        buf[0] = n;
        // SAFETY: Data is valid CERTS payload
        unsafe { Self::new(VariableCell::from(buf)) }
    }
}

impl TryFromCell for Certs {
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

impl CellLike for Certs {
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

impl Certs {
    /// CERTS command ID.
    pub const ID: u8 = 129;

    /// Creates new CERTS cell.
    ///
    /// # Safety
    ///
    /// Data must form a valid CERTS payload.
    pub unsafe fn new(data: VariableCell) -> Self {
        debug_assert!(Self::check(data.data()));
        Self(data)
    }

    /// Creates CERTS cell from certificates.
    ///
    /// # Panics
    ///
    /// Panics if one of the following happened:
    /// - Number of certificates exceeds 255.
    /// - Length of _any_ certificate exceeds 65535.
    pub fn from_list<T: AsRef<[u8]>>(list: &[Cert<T>]) -> Self {
        Self::from_iter(list.iter().map(Cert::as_ref))
    }

    /// Gets number of certificates.
    pub fn len(&self) -> usize {
        self.0.data()[0].into()
    }

    /// Checks if CERTS cell contains no certificate.
    pub fn is_empty(&self) -> bool {
        self.0.data()[0] == 0
    }

    /// Unwraps into inner [`VariableCell`].
    pub fn into_inner(self) -> VariableCell {
        self.0
    }

    fn check(data: &[u8]) -> bool {
        let Ok(header) = CertsHeader::ref_from_bytes(data) else {
            return false;
        };
        let mut data = &header.data;

        for _ in 0..header.n_certs {
            let Some(s) = CertRef::ref_from_bytes(data)
                .ok()
                .and_then(|c| c.split_at(c.length.get().into()))
            else {
                return false;
            };
            data = s.via_immutable().1;
        }

        true
    }
}

/// Iterator of [`Certs`].
pub struct CertsIterator<'a> {
    data: &'a [u8],
    n: u8,
    i: u8,
}

impl<'a> Iterator for CertsIterator<'a> {
    type Item = Cert<&'a [u8]>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.i >= self.n {
            return None;
        }

        let cert = CertRef::ref_from_bytes(self.data).expect("data must be valid");
        let (cert, rest) = cert
            .split_at(cert.length.get().into())
            .expect("data must be valid")
            .via_immutable();
        self.data = rest;
        self.i += 1;

        Some(cert.into())
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        let l = self.len();
        (l, Some(l))
    }
}

impl ExactSizeIterator for CertsIterator<'_> {
    fn len(&self) -> usize {
        self.n.saturating_sub(self.i).into()
    }
}

impl<'a> IntoIterator for &'a Certs {
    type IntoIter = CertsIterator<'a>;
    type Item = Cert<&'a [u8]>;

    fn into_iter(self) -> Self::IntoIter {
        let header = CertsHeader::ref_from_bytes(self.0.data()).expect("data must be valid");

        CertsIterator {
            data: &header.data,
            n: header.n_certs,
            i: 0,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::iter::{repeat, repeat_n};

    use proptest::collection::vec;
    use proptest::prelude::*;

    fn certs_strat() -> impl Strategy<Value = Vec<(u8, Vec<u8>)>> {
        vec((any::<u8>(), vec(any::<u8>(), 0..256)), 0..256)
    }

    #[test]
    #[should_panic]
    fn test_certs_too_long() {
        static DATA: &[u8] = &[0; 65536];

        Certs::from_iter([Cert::new(0, DATA)]);
    }

    #[test]
    #[should_panic]
    fn test_certs_too_many() {
        Certs::from_iter(repeat_n(Cert::new(0, []), 256));
    }

    #[test]
    #[should_panic]
    fn test_certs_infinity() {
        Certs::from_iter(repeat(Cert::new(0, [])));
    }

    proptest! {
        #[test]
        fn test_certs_from_list(certs in certs_strat()) {
            let cell = Certs::from_list(&certs.iter().map(|(t, v)| Cert::new(*t, &v[..])).collect::<Vec<_>>());
            assert_eq!(cell.into_iter().map(|v| (v.ty, Vec::from(v.data))).collect::<Vec<_>>(), certs);
        }

        #[test]
        fn test_certs_from_iter(certs in certs_strat()) {
            let cell = Certs::from_iter(certs.iter().map(|(t, v)| Cert::new(*t, &v[..])));
            assert_eq!(cell.into_iter().map(|v| (v.ty, Vec::from(v.data))).collect::<Vec<_>>(), certs);
        }

        #[test]
        fn test_certs_content(certs in certs_strat()) {
            let cell = Certs::from_iter(certs.iter().map(|(t, v)| Cert::new(*t, &v[..]))).into_inner();
            let mut data = cell.data();

            assert_eq!(data[0] as usize, certs.len());
            data = &data[1..];
            for (t, v) in certs {
                let (&[t_, a, b], r) = data.split_first_chunk::<3>().unwrap();
                assert_eq!(t, t_);

                let l: usize = u16::from_be_bytes([a, b]).into();
                assert_eq!(&r[..l], v);
                data = &r[l..];
            }

            assert_eq!(data, []);
        }
    }
}
