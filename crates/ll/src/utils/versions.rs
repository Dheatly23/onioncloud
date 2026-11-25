//! Protocol versions.

use std::borrow::Borrow;
use std::cmp::{Ordering, PartialEq, PartialOrd};
use std::hash::{Hash, Hasher};

#[cfg(feature = "cell")]
use onioncloud_ll_cell::typed::Versions;
use thiserror::Error;

/// Newtype for link protocol version.
///
/// See also: [spec](https://spec.torproject.org/tor-spec/negotiating-channels.html#VERSIONS-cells).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct LinkVersion(pub u16);

impl Borrow<u16> for LinkVersion {
    #[inline]
    fn borrow(&self) -> &u16 {
        &self.0
    }
}

impl Hash for LinkVersion {
    #[inline]
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.0.hash(state);
    }
}

impl PartialEq<u16> for LinkVersion {
    #[inline]
    fn eq(&self, other: &u16) -> bool {
        self.0 == *other
    }
}

impl PartialOrd<u16> for LinkVersion {
    #[inline]
    fn partial_cmp(&self, other: &u16) -> Option<Ordering> {
        self.0.partial_cmp(other)
    }
}

impl From<LinkVersion> for u16 {
    #[inline]
    fn from(v: LinkVersion) -> u16 {
        v.0
    }
}

impl LinkVersion {
    /// Minimum supported link protocol version.
    pub const MIN: Self = Self(3);
    /// Maximum supported link protocol version.
    pub const MAX: Self = Self(5);

    /// Returns `true` if circuit ID should be 4 bytes.
    #[inline]
    #[must_use]
    pub fn is_circ_id_4bytes(&self) -> bool {
        self.0 >= 4
    }
}

#[cfg(feature = "cell")]
impl LinkVersion {
    /// Create VERSIONS cell from link version range.
    #[must_use]
    #[expect(clippy::missing_panics_doc)]
    pub fn make_versions(min: Self, max: Self) -> Versions {
        Versions::try_from_iter(min.0..=max.0)
            .unwrap_or_else(|_| Versions::try_from_slice(&[]).unwrap())
    }

    /// Do versions negotiation.
    ///
    /// # Arguments
    ///
    /// - `min`, `max` : Same as [`Self::make_versions`].
    /// - `versions` : VERSIONS cell response.
    ///
    /// # Errors
    ///
    /// Returns error if version negotiation failed.
    pub fn versions_negotiate(
        min: Self,
        max: Self,
        versions: &Versions,
    ) -> Result<Self, LinkVersionNegotiateError> {
        versions
            .data()
            .iter()
            .map(|v| Self(v.get()))
            .filter(|&v| v >= min && v <= max)
            .max()
            .ok_or(LinkVersionNegotiateError)
    }
}

/// Link protocol version negotiation error.
#[derive(Error, Debug)]
#[error("Error negotiating link protocol version")]
#[non_exhaustive]
pub struct LinkVersionNegotiateError;
