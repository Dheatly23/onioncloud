//! Cell reader/writer configurator.

use std::fmt::{Debug, Formatter, Result as FmtResult};
use std::sync::atomic::{AtomicU16, Ordering};

use onioncloud_ll_cell::cache::CellCache;
use onioncloud_ll_cell::cell::CellHeader;
use onioncloud_ll_cell::fixed::FixedCell;
use onioncloud_ll_cell::read::{CellType, ReadConfig};
use onioncloud_ll_cell::typed::Versions;
use onioncloud_ll_cell::write::WriteConfig;

use super::LinkVersion;

/// Cell reader/writer configurator.
///
/// Implements [`ReadConfig`] and [`WriteConfig`].
pub struct Config<C> {
    lv: AtomicU16,
    pub cache: C,
}

#[expect(clippy::missing_fields_in_debug)]
impl<C: Debug> Debug for Config<C> {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        f.debug_struct("Config")
            .field("link_version", &self.get_link_version())
            .field("cache", &self.cache)
            .finish()
    }
}

impl<C: CellCache> Config<C> {
    /// Creates new [`Config`].
    #[inline]
    pub const fn new(cache: C) -> Self {
        Self {
            lv: AtomicU16::new(0),
            cache,
        }
    }
}

impl<C> Config<C> {
    /// Sets link version.
    #[inline]
    pub fn set_link_version(&self, linkver: LinkVersion) {
        self.lv.store(linkver.0, Ordering::Relaxed);
    }

    /// Gets link version.
    #[inline]
    pub fn get_link_version(&self) -> LinkVersion {
        LinkVersion(self.lv.load(Ordering::Relaxed))
    }
}

impl<C: CellCache> ReadConfig for Config<C> {
    #[inline]
    fn is_circ_id_4bytes(&self) -> bool {
        self.get_link_version().is_circ_id_4bytes()
    }

    fn cell_type(&self, header: &CellHeader) -> Option<CellType> {
        Some(if header.command == Versions::ID || header.command > 127 {
            CellType::Variable
        } else {
            CellType::Fixed
        })
    }

    #[inline]
    fn get_fixed_cell(&self) -> FixedCell {
        self.cache.get_cached()
    }

    #[inline]
    fn cache_fixed_cell(&self, cell: FixedCell) {
        self.cache.cache_cell(cell);
    }
}

impl<C: CellCache> WriteConfig for Config<C> {
    #[inline]
    fn is_circ_id_4bytes(&self) -> bool {
        ReadConfig::is_circ_id_4bytes(self)
    }

    #[inline]
    fn cache_fixed_cell(&self, cell: FixedCell) {
        ReadConfig::cache_fixed_cell(self, cell)
    }
}
