use std::net::IpAddr;

use super::{Cell, CellHeader, FIXED_CELL_SIZE, FixedCell, TryFromCell, to_fixed_with};
use crate::errors;

/// Represents a NETINFO cell.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Netinfo(FixedCell);

impl From<Netinfo> for Cell {
    fn from(v: Netinfo) -> Cell {
        Cell::from_fixed(CellHeader::new(0, Netinfo::ID), v.into_inner())
    }
}

impl TryFromCell for Netinfo {
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
        to_fixed_with(cell, Self::check).map(|v| v.map(|v| unsafe { Self::from_cell(v) }))
    }
}

impl Netinfo {
    /// NETINFO command ID.
    pub const ID: u8 = 8;

    /// Creates new NETINFO cell from existing [`FixedCell`].
    ///
    /// # Safety
    ///
    /// Data must be a 2-byte array of [`U16`].
    pub unsafe fn from_cell(data: FixedCell) -> Self {
        debug_assert!(Self::check(data.data()));
        Self(data)
    }

    fn write_prefix(
        data: &mut [u8; FIXED_CELL_SIZE],
        time: u32,
        other_addr: IpAddr,
    ) -> (&mut u8, &mut [u8]) {
        *<&mut [u8; 4]>::try_from(&mut data[..4]).unwrap() = time.to_be_bytes();
        match other_addr {
            IpAddr::V4(v) => {
                data[4] = 4;
                data[5] = 4;
                let (a, b) = data[6..].split_first_chunk_mut::<4>().unwrap();
                *a = v.octets();
                b
            }
            IpAddr::V6(v) => {
                data[4] = 6;
                data[5] = 16;
                let (a, b) = data[6..].split_first_chunk_mut::<16>().unwrap();
                *a = v.octets();
                b
            }
        }
        .split_first_mut()
        .unwrap()
    }

    /// Creates new NETINFO cell.
    ///
    /// # Parameters
    ///
    /// - `cell` : Cached [`FixedCell`].
    /// - `time` : Timestamp.
    /// - `other_addr` : Peer IP address.
    /// - `this_addr` : This IP addresses. Excessive addresses will be discared.
    pub fn new(
        mut cell: FixedCell,
        time: u32,
        other_addr: IpAddr,
        this_addr: impl IntoIterator<Item = IpAddr>,
    ) -> Self {
        let (np, mut data) = Self::write_prefix(cell.data_mut(), time, other_addr);

        let mut n = 0u8;
        for a in this_addr {
            data = match a {
                IpAddr::V4(v) => {
                    let Some((a, r)) = data.split_first_chunk_mut::<{ 2 + 4 }>() else {
                        // Not enough space
                        break;
                    };
                    a[0] = 4;
                    a[1] = 4;
                    *<&mut [u8; 4]>::try_from(&mut a[2..]).unwrap() = v.octets();
                    r
                }
                IpAddr::V6(v) => {
                    let Some((a, r)) = data.split_first_chunk_mut::<{ 2 + 16 }>() else {
                        // Not enough space
                        break;
                    };
                    a[0] = 6;
                    a[1] = 16;
                    *<&mut [u8; 16]>::try_from(&mut a[2..]).unwrap() = v.octets();
                    r
                }
            };

            n = match n.checked_add(1) {
                Some(v) => v,
                // Should be unlikely, but better be safe
                None => break,
            };
        }

        *np = n;
        // SAFETY: Data is valid
        unsafe { Self::from_cell(cell) }
    }

    /// Gets timestamp.
    pub fn time(&self) -> u32 {
        u32::from_be_bytes(self.0.data()[..4].try_into().unwrap())
    }

    /// Gets peer IP address.
    ///
    /// Returns [`None`] if address is invalid.
    pub fn other_addr(&self) -> Option<IpAddr> {
        let b = self.0.data();
        match &b[4..6] {
            [4, 4] => Some(<[u8; 4]>::try_from(&b[6..6 + 4]).unwrap().into()),
            [6, 16] => Some(<[u8; 16]>::try_from(&b[6..6 + 16]).unwrap().into()),
            _ => None,
        }
    }

    /// Unwraps into inner [`FixedCell`].
    pub fn into_inner(self) -> FixedCell {
        self.0
    }

    fn check(data: &[u8; FIXED_CELL_SIZE]) -> bool {
        let l: usize = data[5].into();
        // l < 256 < FIXED_CELL_SIZE + 7
        let n = data[6 + l];

        let mut data = &data[7 + l..];
        for _ in 0..n {
            let Some((&[_, l], r)) = data.split_first_chunk::<2>() else {
                return false;
            };
            data = match r.get(l.into()..) {
                Some(v) => v,
                None => return false,
            };
        }

        true
    }
}

/// Iterator for [`Netinfo`].
///
/// Iterates over this addresses.
pub struct NetinfoIterator<'a> {
    cell: &'a Netinfo,
    n: u8,
    i: u8,
    off: usize,
}

impl Iterator for NetinfoIterator<'_> {
    type Item = IpAddr;

    fn next(&mut self) -> Option<Self::Item> {
        while self.i < self.n {
            let b = &self.cell.0.data()[self.off..];
            let [t, l] = <[u8; 2]>::try_from(&b[..2]).expect("slice must be valid array");
            let l_ = usize::from(l);
            let b = &b[2..2 + l_];
            self.off += 2 + l_;
            self.i += 1;

            return Some(match (t, l) {
                (4, 4) => <[u8; 4]>::try_from(b).expect("size must be 4").into(),
                (6, 16) => <[u8; 16]>::try_from(b).expect("size must be 16").into(),
                _ => continue,
            });
        }

        None
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        (0, Some((self.n - self.i).into()))
    }
}

/// Iterates over this addresses in the [`Netinfo`] cell.
impl<'a> IntoIterator for &'a Netinfo {
    type IntoIter = NetinfoIterator<'a>;
    type Item = IpAddr;

    fn into_iter(self) -> Self::IntoIter {
        let b = self.0.data();
        let l: usize = b[5].into();
        let n = b[6 + l];

        NetinfoIterator {
            n,
            i: 0,
            off: 7 + l,
            cell: self,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::iter::repeat_n;
    use std::net::Ipv4Addr;

    use proptest::collection::vec;
    use proptest::prelude::*;

    fn netinfo_strat() -> impl Strategy<Value = (u32, IpAddr, Vec<IpAddr>)> {
        (any::<u32>(), any::<IpAddr>(), vec(any::<IpAddr>(), 0..16))
    }

    #[test]
    fn test_netinfo_too_many() {
        let cell = Netinfo::new(
            FixedCell::default(),
            0,
            Ipv4Addr::UNSPECIFIED.into(),
            repeat_n(Ipv4Addr::UNSPECIFIED.into(), 1000),
        );

        assert!(cell.into_iter().count() < 1000);
    }

    proptest! {
        #[test]
        fn test_netinfo_new((time, other, this) in netinfo_strat()) {
            let cell = Netinfo::new(
                FixedCell::default(),
                time,
                other,
                this.iter().copied(),
            );

            assert_eq!(cell.time(), time);
            assert_eq!(cell.other_addr(), Some(other));
            assert_eq!(cell.into_iter().collect::<Vec<_>>(), this);
        }
    }
}
