use crate::cell::{Cell, CellHeader, TryFromCell, VariableCell, to_variable_with};
use crate::errors;

/// Represents a CERTS cell.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Certs(VariableCell);

impl From<Certs> for Cell {
    fn from(v: Certs) -> Cell {
        Cell::from_variable(CellHeader::new(0, Certs::ID), v.into_inner())
    }
}

impl<T: AsRef<[u8]>> FromIterator<(u8, T)> for Certs {
    fn from_iter<It: IntoIterator<Item = (u8, T)>>(it: It) -> Self {
        let mut buf = vec![0];
        let mut n = 0u8;

        for (t, v) in it {
            n = match n.checked_add(1) {
                Some(v) => v,
                None => panic!("too many certificates!"),
            };

            let v = v.as_ref();
            let Ok(l) = u16::try_from(v.len()) else {
                panic!("certificate {} is too long! (length: {})", n - 1, v.len());
            };
            let [a, b] = l.to_be_bytes();

            buf.reserve(3 + v.len());
            buf.extend([t, a, b]);
            buf.extend_from_slice(v);
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
    pub fn from_list(list: &[Cert<'_>]) -> Self {
        Self::from_iter(list.iter().map(|&Cert { ty, data }| (ty, data)))
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
        let Some((&n, mut data)) = data.split_first() else {
            return false;
        };

        for _ in 0..n {
            let Some((&[_, a, b], v)) = data.split_first_chunk::<3>() else {
                return false;
            };
            let l = u16::from_be_bytes([a, b]);
            data = match v.get(l.into()..) {
                Some(v) => v,
                None => return false,
            };
        }

        true
    }
}

/// A reference to a certificate.
pub struct Cert<'a> {
    ty: u8,
    data: &'a [u8],
}

impl AsRef<[u8]> for Cert<'_> {
    fn as_ref(&self) -> &[u8] {
        self.data
    }
}

impl<'a> Cert<'a> {
    /// Creates new certificate.
    ///
    /// Most useful for [`Certs::from_list`].
    pub fn new(cert_type: u8, data: &'a [u8]) -> Self {
        Self {
            ty: cert_type,
            data,
        }
    }

    /// Gets certificate type.
    pub fn cert_type(&self) -> u8 {
        self.ty
    }

    /// Gets unparsed certificate bytes.
    pub fn data(&self) -> &[u8] {
        self.data
    }

    /// Unwraps inner bytes.
    pub fn into_inner(self) -> &'a [u8] {
        self.data
    }
}

/// Iterator in [`Certs`].
pub struct CertsIterator<'a> {
    certs: &'a Certs,
    n: u8,
    i: u8,
    off: usize,
}

impl<'a> Iterator for CertsIterator<'a> {
    type Item = Cert<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.i >= self.n {
            return None;
        }

        let data = self.certs.0.data();
        let [ty, a, b] =
            <[u8; 3]>::try_from(&data[self.off..self.off + 3]).expect("data must be valid");
        let l: usize = u16::from_be_bytes([a, b]).into();
        let data = &data[self.off + 3..self.off + 3 + l];

        self.off += 3 + l;
        self.i += 1;
        Some(Cert { ty, data })
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
    type Item = Cert<'a>;

    fn into_iter(self) -> Self::IntoIter {
        CertsIterator {
            n: self.0.data()[0],
            i: 0,
            off: 1,
            certs: self,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::iter::repeat;

    use proptest::collection::vec;
    use proptest::prelude::*;

    fn certs_strat() -> impl Strategy<Value = Vec<(u8, Vec<u8>)>> {
        vec((any::<u8>(), vec(any::<u8>(), 0..256)), 0..256)
    }

    #[test]
    #[should_panic]
    fn test_certs_too_long() {
        static DATA: &[u8] = &[0; 65536];

        Certs::from_iter([(0, DATA)]);
    }

    #[test]
    #[should_panic]
    fn test_certs_too_many() {
        Certs::from_iter(repeat((0, [])));
    }

    proptest! {
        #[test]
        fn test_certs_from_list(certs in certs_strat()) {
            let cell = Certs::from_list(&certs.iter().map(|(t, v)| Cert::new(*t, v)).collect::<Vec<_>>());
            assert_eq!(cell.into_iter().map(|v| (v.cert_type(), Vec::from(v.into_inner()))).collect::<Vec<_>>(), certs);
        }

        #[test]
        fn test_certs_from_iter(certs in certs_strat()) {
            let cell = Certs::from_iter(certs.iter().map(|(t, v)| (*t, v)));
            assert_eq!(cell.into_iter().map(|v| (v.cert_type(), Vec::from(v.into_inner()))).collect::<Vec<_>>(), certs);
        }

        #[test]
        fn test_certs_content(certs in certs_strat()) {
            let cell = Certs::from_iter(certs.iter().map(|(t, v)| (*t, v))).into_inner();
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
