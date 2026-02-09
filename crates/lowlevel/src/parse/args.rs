//! Various argument parsers.

use std::cmp::Ordering;
use std::fmt::{Debug, Display, Formatter, Result as FmtResult};
use std::iter::FusedIterator;

use memchr::{memchr, memchr_iter};

use super::netdoc::check::proto_keyword;
use super::netdoc::{Arguments, ArgumentsIter};
use crate::errors::{NetparamParseError, ProtoParseError, ProtoParseErrorInner};
use crate::util::parse::{MaybeRange, parse_maybe_range};

const MAX_VERSIONS_RANGE: usize = 256;

/// Subprotocol versions parser.
///
/// See also: [spec](https://spec.torproject.org/dir-spec/server-descriptor-format.html#item:proto).
#[derive(Debug, Clone)]
pub struct ProtoParser<'a>(Arguments<'a>);

/// Iterator of [`ProtoParser`].
#[derive(Debug, Clone)]
pub struct ProtoParserIter<'a>(Option<ArgumentsIter<'a>>);

/// A single protocol item.
///
/// Returned from iterating [`ProtoParserIter`].
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct Proto<'a> {
    /// Keyword.
    pub keyword: &'a str,
    /// Version ranges.
    ///
    /// Ranges are always ascending and non-overlapping.
    pub versions: Vec<VersionRange>,
}

/// Version range entry.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub enum VersionRange {
    /// A single version.
    Version(u32),
    /// Range of versions.
    Range {
        /// From, inclusive.
        from: u32,
        /// To, inclusive.
        to: u32,
    },
}

impl Debug for VersionRange {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        match self {
            Self::Version(v) => write!(f, "{v}"),
            Self::Range { from, to } => write!(f, "{from}-{to}"),
        }
    }
}

impl Display for VersionRange {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        Debug::fmt(self, f)
    }
}

impl VersionRange {
    /// Checks if version is contained within.
    pub fn contains(&self, version: u32) -> bool {
        match self {
            Self::Version(v) => *v == version,
            Self::Range { from, to } => *from <= version && version <= *to,
        }
    }

    /// Checks if version is contained within exit ports.
    ///
    /// **NOTE:** Versions must be ascending, non-overlapping, and all ranges are valid (`from` <= `to`). Otherwise the return value is meaningless.
    pub fn in_versions(versions: &[Self], version: u32) -> bool {
        let Ok(i) = versions.binary_search_by(|p| match p {
            Self::Version(v) => v.cmp(&version),
            Self::Range { from, to } => {
                if version < *from {
                    Ordering::Greater
                } else if version > *to {
                    Ordering::Less
                } else {
                    Ordering::Equal
                }
            }
        }) else {
            return false;
        };
        versions[i].contains(version)
    }
}

impl<'a> From<Arguments<'a>> for ProtoParser<'a> {
    fn from(a: Arguments<'a>) -> Self {
        Self::new(a)
    }
}

impl<'a> From<ProtoParser<'a>> for Arguments<'a> {
    fn from(a: ProtoParser<'a>) -> Self {
        a.0
    }
}

impl<'a> IntoIterator for ProtoParser<'a> {
    type Item = <ProtoParserIter<'a> as Iterator>::Item;
    type IntoIter = ProtoParserIter<'a>;

    fn into_iter(self) -> Self::IntoIter {
        self.iter()
    }
}

impl<'a> IntoIterator for &ProtoParser<'a> {
    type Item = <ProtoParserIter<'a> as Iterator>::Item;
    type IntoIter = ProtoParserIter<'a>;

    fn into_iter(self) -> Self::IntoIter {
        self.iter()
    }
}

impl<'a> ProtoParser<'a> {
    /// Creates new [`ProtoParser`].
    ///
    /// # Parameters
    ///
    /// - `args` : Arguments to be parsed.
    pub fn new(args: Arguments<'a>) -> Self {
        Self(args)
    }

    /// Gets raw string.
    #[inline(always)]
    pub const fn raw_string(&self) -> &'a str {
        self.0.raw_string()
    }

    /// Gets inner [`Arguments`].
    #[inline(always)]
    pub const fn into_inner(self) -> Arguments<'a> {
        self.0
    }

    /// Iterates over subprotocols.
    ///
    /// # Example
    ///
    /// ```
    /// use onioncloud_lowlevel::parse::args::{ProtoParser, VersionRange};
    /// use onioncloud_lowlevel::parse::netdoc::Arguments;
    ///
    /// let args = Arguments::try_from("Proto=1-2,4").unwrap();
    /// let mut parser = ProtoParser::from(args).into_iter();
    /// let proto = parser.next().unwrap().unwrap();
    /// assert_eq!(proto.keyword, "Proto");
    /// assert!(VersionRange::in_versions(&proto.versions, 1));
    /// assert!(VersionRange::in_versions(&proto.versions, 2));
    /// assert!(!VersionRange::in_versions(&proto.versions, 3));
    /// assert!(VersionRange::in_versions(&proto.versions, 4));
    /// ```
    pub fn iter(&self) -> ProtoParserIter<'a> {
        ProtoParserIter(Some(self.0.iter()))
    }
}

impl<'a> ProtoParserIter<'a> {
    fn parse(s: &str) -> Result<Proto<'_>, ProtoParseError> {
        let i = proto_keyword(s).map_err(|i| {
            ProtoParseError::with_pos(
                i,
                if i == s.len() {
                    ProtoParseErrorInner::NoEquals
                } else {
                    ProtoParseErrorInner::InvalidKeywordChar
                },
            )
        })?;
        // SAFETY: Index points to = character in string
        let (keyword, r) = unsafe { (s.get_unchecked(..i), s.get_unchecked(i + 1..)) };

        let mut l = 0;
        let mut versions = Vec::new();
        for j in memchr_iter(b',', r.as_bytes()).chain([r.len()]) {
            let o = i + l + 1;
            // SAFETY: Index points to , character in string
            let s = unsafe { r.get_unchecked(l..j) };
            let Some(v) = parse_maybe_range(s) else {
                return Err(ProtoParseError::with_pos(
                    o,
                    ProtoParseErrorInner::VersionRange,
                ));
            };
            l = j + 1;
            let v = match v {
                MaybeRange::Num(v) => VersionRange::Version(v),
                MaybeRange::Range { from, to } if from < to => VersionRange::Range { from, to },
                _ => {
                    return Err(ProtoParseError::with_pos(
                        o,
                        ProtoParseErrorInner::VersionRange,
                    ));
                }
            };
            if let (
                Some(VersionRange::Version(a) | VersionRange::Range { to: a, .. }),
                VersionRange::Version(b) | VersionRange::Range { from: b, .. },
            ) = (versions.last(), v)
                && b.saturating_sub(*a) <= 1
            {
                return Err(ProtoParseError::new(ProtoParseErrorInner::VersionOverlap));
            }
            if versions.len() >= MAX_VERSIONS_RANGE {
                return Err(ProtoParseError::new(ProtoParseErrorInner::TooManyVersions));
            }
            versions.push(v);
        }

        Ok(Proto { keyword, versions })
    }
}

impl<'a> Iterator for ProtoParserIter<'a> {
    type Item = Result<Proto<'a>, ProtoParseError>;

    fn next(&mut self) -> Option<Self::Item> {
        let r = Self::parse(self.0.as_mut()?.next()?);
        if r.is_err() {
            self.0 = None;
        }
        Some(r)
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        match &self.0 {
            None => (0, Some(0)),
            Some(it) => it.size_hint(),
        }
    }
}

impl DoubleEndedIterator for ProtoParserIter<'_> {
    fn next_back(&mut self) -> Option<Self::Item> {
        let r = Self::parse(self.0.as_mut()?.next_back()?);
        if r.is_err() {
            self.0 = None;
        }
        Some(r)
    }
}

impl FusedIterator for ProtoParserIter<'_> {}

/// Network/consensus parameter parser.
///
/// See also: [spec](https://spec.torproject.org/param-spec.html).
#[derive(Debug, Clone)]
pub struct NetparamParser<'a>(Arguments<'a>);

/// Iterator of [`NetparamParser`].
#[derive(Debug, Clone)]
pub struct NetparamParserIter<'a>(Option<ArgumentsIter<'a>>);

/// A single consensus parameter
///
/// The argument value is not parsed. It is the responsibility of user to parse it.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct Netparam<'a> {
    /// Parameter keyword.
    pub keyword: &'a str,
    /// Parameter argument.
    pub argument: &'a str,
}

impl<'a> From<Arguments<'a>> for NetparamParser<'a> {
    fn from(v: Arguments<'a>) -> Self {
        Self(v)
    }
}

impl<'a> From<NetparamParser<'a>> for Arguments<'a> {
    fn from(v: NetparamParser<'a>) -> Self {
        v.0
    }
}

impl<'a> IntoIterator for NetparamParser<'a> {
    type Item = <NetparamParserIter<'a> as Iterator>::Item;
    type IntoIter = NetparamParserIter<'a>;

    fn into_iter(self) -> Self::IntoIter {
        self.iter()
    }
}

impl<'a> IntoIterator for &NetparamParser<'a> {
    type Item = <NetparamParserIter<'a> as Iterator>::Item;
    type IntoIter = NetparamParserIter<'a>;

    fn into_iter(self) -> Self::IntoIter {
        self.iter()
    }
}

impl<'a> NetparamParser<'a> {
    /// Creates new [`NetparamParser`].
    pub fn new(args: Arguments<'a>) -> Self {
        Self(args)
    }

    /// Gets raw string.
    #[inline(always)]
    pub const fn raw_string(&self) -> &'a str {
        self.0.raw_string()
    }

    /// Gets inner [`Arguments`].
    #[inline(always)]
    pub const fn into_inner(self) -> Arguments<'a> {
        self.0
    }

    /// Iterates over consensus parameters.
    ///
    /// # Example
    ///
    /// ```
    /// use onioncloud_lowlevel::parse::args::{NetparamParser, VersionRange};
    /// use onioncloud_lowlevel::parse::netdoc::Arguments;
    ///
    /// let args = Arguments::try_from("Param=123").unwrap();
    /// let mut parser = NetparamParser::from(args).into_iter();
    /// let param = parser.next().unwrap().unwrap();
    /// assert_eq!(param.keyword, "Param");
    /// assert_eq!(param.argument, "123");
    /// ```
    pub fn iter(&self) -> NetparamParserIter<'a> {
        NetparamParserIter(Some(self.0.iter()))
    }
}

impl NetparamParserIter<'_> {
    fn parse(s: &str) -> Result<Netparam<'_>, NetparamParseError> {
        let i = memchr(b'=', s.as_bytes()).ok_or(NetparamParseError::NoEquals)?;

        if i == 0 {
            return Err(NetparamParseError::NoKeyword);
        }

        // SAFETY: Index points to = character in string
        unsafe {
            Ok(Netparam {
                keyword: s.get_unchecked(..i),
                argument: s.get_unchecked(i + 1..),
            })
        }
    }
}

impl<'a> Iterator for NetparamParserIter<'a> {
    type Item = Result<Netparam<'a>, NetparamParseError>;

    fn next(&mut self) -> Option<Self::Item> {
        let r = Self::parse(self.0.as_mut()?.next()?);
        if r.is_err() {
            self.0 = None;
        }
        Some(r)
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        match &self.0 {
            None => (0, Some(0)),
            Some(it) => it.size_hint(),
        }
    }
}

impl DoubleEndedIterator for NetparamParserIter<'_> {
    fn next_back(&mut self) -> Option<Self::Item> {
        let r = Self::parse(self.0.as_mut()?.next_back()?);
        if r.is_err() {
            self.0 = None;
        }
        Some(r)
    }
}

impl FusedIterator for NetparamParserIter<'_> {}

#[cfg(test)]
mod tests {
    use super::*;

    use std::fmt::Write as _;
    use std::mem::take;

    use bit_set::BitSet;
    use proptest::bits::bitset::between;
    use proptest::collection::vec;
    use proptest::prelude::*;

    fn proto_str(v: &Vec<(String, String, BitSet)>) -> String {
        let mut s = String::new();
        for (i, (sp, v, a)) in v.iter().enumerate() {
            if i != 0 {
                s += sp;
            }
            s += v;

            let mut first = true;
            let mut p = None;
            for (i, t) in a.get_ref().iter().enumerate() {
                if t && p.is_none() {
                    s += if take(&mut first) { "=" } else { "," };
                    write!(&mut s, "{i}").unwrap();
                    p = Some(i);
                } else if !t && let Some(p) = p.take() {
                    if p < i - 1 {
                        write!(&mut s, "-{}", i - 1).unwrap();
                    }
                }
            }

            if let Some(p) = p.take()
                && p < 255
            {
                s += "-255";
            }
        }

        s
    }

    proptest! {
        #[test]
        fn test_proto_parse(v in vec(("[ \t]+", "[a-zA-Z0-9][a-zA-Z0-9\\-]*", between(0, 256)), 0..=32)) {
            let s = proto_str(&v);

            let mut it = ProtoParser::new(Arguments::try_from(&*s).unwrap()).into_iter();
            for (i, (_, v, a)) in v.into_iter().enumerate() {
                let p = match it.next() {
                    None => panic!("iteration should produce at least {i} items"),
                    Some(Err(e)) => panic!("error at index {i}: {e:?}"),
                    Some(Ok(v)) => v,
                };

                assert_eq!(p.keyword, v, "mismatch at index {i}");
                for ix in 0..256 {
                    assert_eq!(VersionRange::in_versions(&p.versions, ix as u32), a.contains(ix), "error at item index {i} and index {ix}");
                }
            }

            if let Some(i) = it.next() {
                panic!("iteration should finish, got {i:?}");
            }
        }

        #[test]
        fn test_netparam_parse(v in vec(("[ \t]+", "[^ \t\0\n=]+", "[^ \t\0\n=]+"), 0..=32)) {
            let mut s = String::new();
            for (i, (sp, k, v)) in v.iter().enumerate() {
                if i != 0 {
                    s += sp;
                }
                s += k;
                s += "=";
                s += v;
            }

            let mut it = NetparamParser::new(Arguments::try_from(&*s).unwrap()).into_iter();
            for (i, (_, k, v)) in v.into_iter().enumerate() {
                let p = match it.next() {
                    None => panic!("iteration should produce at least {i} items"),
                    Some(Err(e)) => panic!("error at index {i}: {e:?}"),
                    Some(Ok(v)) => v,
                };

                assert_eq!(p.keyword, k, "mismatch at index {i}");
                assert_eq!(p.argument, v, "mismatch at index {i}");
            }

            if let Some(i) = it.next() {
                panic!("iteration should finish, got {i:?}");
            }
        }
    }
}
