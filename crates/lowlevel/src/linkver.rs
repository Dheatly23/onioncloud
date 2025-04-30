use std::sync::atomic::AtomicU32;
use std::sync::atomic::Ordering::*;

use rand::prelude::*;

use crate::cell::CellHeader;
use crate::cell::dispatch::{CellType, WithCellConfig};
use crate::cell::versions::Versions;
use crate::errors;

/// Data for link version negotiation.
#[derive(Debug)]
pub struct Linkver {
    low: u16,
    high: u16,
    version: AtomicU32,
}

const NEGOTIATED: u32 = 1 << 31;

impl Linkver {
    /// Create new [`Linkver`].
    ///
    /// Note that link version will be locked to version 1 until negotiated.
    ///
    /// # Parameters
    /// - `low` : Lowest supported link version.
    /// - `high` : Highest supported link version.
    pub fn new(low: u16, high: u16) -> Self {
        assert!(low <= high, "{low} > {high}");
        assert!(low > 0, "lowest version is too low");

        Self {
            low,
            high,
            version: AtomicU32::new(1),
        }
    }

    /// Get current link version.
    ///
    /// It might be lower than expected (see [`Linkver::new`]).
    pub fn version(&self) -> u16 {
        self.version.load(Acquire) as u16
    }

    /// Get the lowest supported link version.
    pub fn lowest(&self) -> u16 {
        self.low
    }

    /// Get the highest supported link version.
    pub fn highest(&self) -> u16 {
        self.high
    }

    /// Returns [`true`] if version has been negotiated.
    pub fn has_negotiated(&self) -> bool {
        self.version.load(Acquire) & NEGOTIATED != 0
    }

    /// Create a VERSIONS cell to be send to the other party.
    pub fn versions_cell(&self) -> Versions {
        let mut v = (self.low..=self.high).collect::<Vec<_>>();
        // Shuffle versions
        v.shuffle(&mut ThreadRng::default());
        Versions::from_iter(v)
    }

    /// Run version negotiation.
    ///
    /// If version has been negotiated before, it's ignored.
    /// Otherwise, the final version will be the highest supported version by both parties.
    /// If none of the advertised versions matched supported ones, it will return a [`errors::VersionsNegotiateError`] error.
    pub fn versions_negotiate(
        &self,
        other: Versions,
    ) -> Result<(), errors::VersionsNegotiateError> {
        let mut other = Some(other);
        let mut negotiated: Option<u16> = None;
        let mut version = self.version.load(Acquire);

        while version & NEGOTIATED == 0 {
            let Some(negotiated) = negotiated.or_else(|| {
                let mut other = other.take().expect("versions should have been negotiated");
                let data = other.data_mut();
                data.sort_unstable();
                negotiated = data.iter().rev().find_map(|v| {
                    let v = v.get();
                    if v <= self.high && v >= self.low {
                        Some(v)
                    } else {
                        None
                    }
                });
                negotiated
            }) else {
                return Err(errors::VersionsNegotiateError);
            };

            version = match self.version.compare_exchange_weak(
                version,
                u32::from(negotiated) | NEGOTIATED,
                AcqRel,
                Acquire,
            ) {
                Ok(_) => break,
                Err(v) => v,
            };
        }

        Ok(())
    }
}

#[derive(Debug)]
#[non_exhaustive]
pub struct StandardLinkver {
    pub inner: Linkver,
}

impl AsRef<Linkver> for StandardLinkver {
    fn as_ref(&self) -> &Linkver {
        &self.inner
    }
}

impl Default for StandardLinkver {
    fn default() -> Self {
        Self::new()
    }
}

impl StandardLinkver {
    pub const LOWEST: u16 = 4;
    pub const HIGHEST: u16 = 5;

    pub fn new() -> Self {
        Self {
            inner: Linkver::new(Self::LOWEST, Self::HIGHEST),
        }
    }
}

impl WithCellConfig for StandardLinkver {
    fn is_circ_id_4bytes(&self) -> bool {
        self.inner.version() >= 4
    }

    fn cell_type(&self, header: &CellHeader) -> Result<CellType, errors::InvalidCellHeader> {
        match self.inner.version() {
            // Obsolete, only support VERISIONS cell
            1..Self::LOWEST => match header.command {
                Versions::ID => Ok(CellType::Variable),
                _ => Err(errors::InvalidCellHeader::with_header(header)),
            },
            // Feeling lazy, not matching every single cell command
            Self::LOWEST..=Self::HIGHEST => Ok(match header.command {
                Versions::ID | 128.. => CellType::Variable,
                _ => CellType::Fixed,
            }),
            _ => unreachable!("version unsupported"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use proptest::collection::vec;
    use proptest::prelude::*;

    #[test]
    fn test_version_negotiate_twice() {
        let link = Linkver::new(2, 3);
        link.versions_negotiate(Versions::from_iter([2])).unwrap();
        assert_eq!(link.version(), 2);
        link.versions_negotiate(Versions::from_iter([3])).unwrap();
        assert_eq!(link.version(), 2);
    }

    proptest! {
        #[test]
        fn test_version_negotiate(
            a in 1u16..=1024,
            b in 1u16..=1024,
            mut vers in vec(1u16..=1024, 1..=256),
        ) {
            let (low, high) = (a.min(b), a.max(b));
            let link = Linkver::new(low, high);
            assert_eq!(link.version(), 1);
            assert_eq!(link.lowest(), low);
            assert_eq!(link.highest(), high);
            for v in link.versions_cell().data().iter().map(|v| v.get()) {
                assert!(v <= high && v >= low, "invalid version {v}");
            }
            let r = link.versions_negotiate(Versions::from_list(&vers));

            vers.sort_unstable();
            if let Some(v) = vers.into_iter().rev().find(|&v| v <= high && v >= low) {
                r.unwrap();
                assert_eq!(link.version(), v);
            } else {
                r.unwrap_err();
                assert_eq!(link.version(), 1);
            }
        }
    }
}
