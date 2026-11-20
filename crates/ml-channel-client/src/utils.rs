//! Utility types.

use onioncloud_ll::cell::typed::{AuthChallenge, Certs, Netinfo, Versions};
use std::fmt::{Debug, Display, Formatter, Result as FmtResult};
use std::time::Duration;

use humantime::format_duration;

pub(crate) struct CellID(pub(crate) u8);

impl From<u8> for CellID {
    fn from(v: u8) -> Self {
        Self(v)
    }
}

impl Debug for CellID {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        let id = match self.0 {
            Versions::ID => "VERSIONS",
            Certs::ID => "CERTS",
            AuthChallenge::ID => "AUTH_CHALLENGE",
            Netinfo::ID => "NETINFO",
            _ => return Display::fmt(&self.0, f),
        };
        Display::fmt(id, f)
    }
}

impl Display for CellID {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        Debug::fmt(self, f)
    }
}

#[derive(Debug)]
pub(crate) enum Timedelta {
    Neg(Duration),
    Pos(Duration),
}

impl Display for Timedelta {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        write!(
            f,
            "{} in the {}",
            format_duration(self.get_dur()),
            match self {
                Self::Neg(_) => "past",
                Self::Pos(_) => "future",
            }
        )
    }
}

impl Timedelta {
    pub(crate) fn get_dur(&self) -> Duration {
        let (Self::Neg(dur) | Self::Pos(dur)) = self;
        *dur
    }
}
