pub mod args;
pub mod auth_cert;
pub mod consensus;
pub mod descriptor;
pub mod microdesc;
pub(crate) mod misc;
pub mod netdoc;

use std::cmp::Ordering;
use std::fmt::{Debug, Display, Formatter, Result as FmtResult};

/// Exit port policy.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub struct ExitPortPolicy {
    /// `true` if accept.
    pub accept: bool,

    /// Ports list.
    ///
    /// Ports are sorted and ascending and non-overlapping, perfectly suited for [`ExitPort::in_ports`].
    pub ports: Vec<ExitPort>,
}

impl ExitPortPolicy {
    /// Create new [`ExitPortPolicy`].
    pub fn new(accept: bool, ports: Vec<ExitPort>) -> Self {
        Self { accept, ports }
    }

    /// Sort and validate port range.
    fn sort_validate(&mut self) -> bool {
        self.ports.sort_unstable_by(|a, b| {
            let (
                ExitPort::Port(a) | ExitPort::PortRange { from: a, .. },
                ExitPort::Port(b) | ExitPort::PortRange { from: b, .. },
            ) = (a, b);
            a.cmp(b)
        });

        for (i, v) in self.ports.iter().enumerate() {
            if let ExitPort::PortRange { from, to } = *v
                && from >= to
            {
                return false;
            } else if i > 0 {
                let (
                    ExitPort::Port(a) | ExitPort::PortRange { to: a, .. },
                    ExitPort::Port(b) | ExitPort::PortRange { from: b, .. },
                ) = (self.ports[i - 1], *v);
                if b.saturating_sub(a) <= 1 {
                    return false;
                }
            }
        }

        true
    }
}

/// A single exit port (range).
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub enum ExitPort {
    /// A single port.
    Port(u16),
    /// Port range.
    PortRange {
        /// From, inclusive.
        from: u16,
        /// To, inclusive.
        to: u16,
    },
}

impl Debug for ExitPort {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        match self {
            Self::Port(v) => write!(f, "{v}"),
            Self::PortRange { from, to } => write!(f, "{from}-{to}"),
        }
    }
}

impl Display for ExitPort {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        Debug::fmt(self, f)
    }
}

impl ExitPort {
    /// Checks if port is contained within.
    pub fn contains(&self, port: u16) -> bool {
        match self {
            Self::Port(v) => *v == port,
            Self::PortRange { from, to } => *from <= port && port <= *to,
        }
    }

    /// Checks if port is contained within exit ports.
    ///
    /// **NOTE:** Ports must be ascending, non-overlapping, and all port ranges are valid (`from` <= `to`). Otherwise the return value is meaningless.
    pub fn in_ports(ports: &[Self], port: u16) -> bool {
        let Ok(i) = ports.binary_search_by(|p| match p {
            Self::Port(v) => v.cmp(&port),
            Self::PortRange { from, to } => {
                if port < *from {
                    Ordering::Greater
                } else if port > *to {
                    Ordering::Less
                } else {
                    Ordering::Equal
                }
            }
        }) else {
            return false;
        };
        ports[i].contains(port)
    }
}

#[cfg(test)]
pub(crate) use tests::*;

#[cfg(test)]
mod tests {
    use super::*;

    use proptest::collection::vec;
    use proptest::prelude::*;

    pub(crate) fn map_exit_ports(a: impl IntoIterator<Item = u8>) -> Vec<ExitPort> {
        let mut v = Vec::new();
        let mut prev = None;
        for (ix, i) in a.into_iter().enumerate() {
            let ix = ix as u16 * 8;
            for j in 0..8u16 {
                let Some(ix) = ix.checked_add(j) else { break };
                let t = i & (1 << j) != 0;
                if t && prev.is_none() {
                    prev = Some(ix);
                } else if !t && let Some(prev) = prev.take() {
                    v.push(if ix - 1 == prev {
                        ExitPort::Port(prev)
                    } else {
                        ExitPort::PortRange {
                            from: prev,
                            to: ix - 1,
                        }
                    });
                }
            }
        }

        if let Some(prev) = prev {
            v.push(if 65535 == prev {
                ExitPort::Port(prev)
            } else {
                ExitPort::PortRange {
                    from: prev,
                    to: 65535,
                }
            });
        }

        v
    }

    pub(crate) fn strat_exit_ports() -> impl Strategy<Value = Vec<ExitPort>> {
        vec(any::<u8>(), 0..=65536 / 8).prop_filter_map("array is empty", |v| {
            let v = map_exit_ports(v);
            if v.is_empty() {
                return None;
            }
            Some(v)
        })
    }

    pub(crate) fn strat_exit_port() -> impl Strategy<Value = ExitPort> {
        any::<(u16, u16)>().prop_map(|(a, b)| {
            if a == b {
                ExitPort::Port(a)
            } else {
                let from = a.min(b);
                let to = a.max(b);
                ExitPort::PortRange { from, to }
            }
        })
    }

    pub(crate) fn strat_exit_policy() -> impl Strategy<Value = ExitPortPolicy> {
        (any::<bool>(), strat_exit_ports())
            .prop_map(|(accept, ports)| ExitPortPolicy { accept, ports })
    }

    proptest! {
        #[test]
        fn test_exit_ports_valid(v in strat_exit_ports()) {
            let mut v = ExitPortPolicy { accept: false, ports: v };
            assert!(v.sort_validate());
        }

        #[test]
        fn test_exit_port_contains(
            a: u16,
            b: u16,
            port: u16,
        ) {
            let (p, t) = if a == b {
                (ExitPort::Port(a), port == a)
            } else {
                let from = a.min(b);
                let to = a.max(b);
                (ExitPort::PortRange { from, to }, (from..=to).contains(&port))
            };
            assert_eq!(p.contains(port), t);
        }

        #[test]
        fn test_exit_port_in_ports(
            a in vec(any::<u8>(), 0..=65536 / 8),
            port: u16,
        ) {
            let t = match a.get((port >> 3) as usize) {
                Some(v) => *v >> (port & 7),
                None => a.last().copied().unwrap_or(0) >> 7,
            };
            let ok = t & 1 != 0;
            let p = map_exit_ports(a);
            assert_eq!(p.iter().any(|p| p.contains(port)), ok);
            assert_eq!(ExitPort::in_ports(&p, port), ok);
        }
    }
}
