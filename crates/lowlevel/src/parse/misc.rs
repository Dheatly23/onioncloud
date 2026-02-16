//! Helper functions for netdoc parsing.

use std::iter::FusedIterator;
use std::mem::take;

use base64ct::{Base64, Base64Unpadded, Decoder, Encoding, Error as B64Error};
use chrono::{DateTime, NaiveDateTime, Utc};
use memchr::{Memchr, memchr_iter};
use rsa::RsaPublicKey;
use rsa::pkcs1::DecodeRsaPublicKey;
use rsa::pkcs1::der::pem::BASE64_WRAP_WIDTH;

use super::netdoc::{ArgumentsIter, Item};
use super::{ExitPort, ExitPortPolicy};
use crate::errors::{CertFormatError, CertVerifyError};
use crate::util::parse::{parse_date, parse_maybe_range, parse_time};

pub(crate) enum Error {
    CertFormatError(CertFormatError),
    CertVerifyError(CertVerifyError),
}

impl From<CertFormatError> for Error {
    fn from(v: CertFormatError) -> Self {
        Self::CertFormatError(v)
    }
}

impl From<CertVerifyError> for Error {
    fn from(v: CertVerifyError) -> Self {
        Self::CertVerifyError(v)
    }
}

impl Error {
    #[allow(clippy::wrong_self_convention)]
    pub(crate) fn to_err<T: From<CertFormatError> + From<CertVerifyError>>(self) -> T {
        match self {
            Self::CertFormatError(v) => v.into(),
            Self::CertVerifyError(v) => v.into(),
        }
    }
}

fn map_b64_err(e: B64Error) -> Error {
    match e {
        B64Error::InvalidEncoding => CertFormatError.into(),
        B64Error::InvalidLength => CertVerifyError.into(),
    }
}

pub(crate) fn args_date_time(args: &mut ArgumentsIter<'_>) -> Option<DateTime<Utc>> {
    let date = args.next()?;
    let time = args.next()?;

    Some(NaiveDateTime::new(parse_date(date)?, parse_time(time)?).and_utc())
}

pub(crate) fn parse_b64<const N: usize>(s: &str) -> Result<[u8; N], CertFormatError> {
    let mut ret = [0u8; N];
    let t = Base64::decode(s, &mut ret).map_err(|_| CertFormatError)?;
    debug_assert_eq!(t.len(), ret.len());
    Ok(ret)
}

pub(crate) fn parse_b64u<const N: usize>(s: &str) -> Result<[u8; N], CertFormatError> {
    let mut ret = [0u8; N];
    let t = Base64Unpadded::decode(s, &mut ret).map_err(|_| CertFormatError)?;
    debug_assert_eq!(t.len(), ret.len());
    Ok(ret)
}

pub(crate) fn parse_cert<'a>(
    tmp: &'a mut [u8],
    s: &str,
) -> Result<(RsaPublicKey, &'a [u8]), Error> {
    let der = decode_b64(tmp, s)?;
    let Ok(key) = RsaPublicKey::from_pkcs1_der(der) else {
        return Err(CertVerifyError.into());
    };
    Ok((key, der))
}

pub(crate) fn decode_b64<'a>(tmp: &'a mut [u8], s: &str) -> Result<&'a [u8], Error> {
    let mut d =
        Decoder::<Base64>::new_wrapped(s.as_bytes(), BASE64_WRAP_WIDTH).map_err(map_b64_err)?;
    let tmp = tmp.get_mut(..d.remaining_len()).ok_or(CertVerifyError)?;
    d.decode(tmp).map_err(map_b64_err)
}

pub(crate) fn decode_cert<'a>(
    tmp: &'a mut [u8],
    item: &Item<'_>,
) -> Result<(RsaPublicKey, &'a [u8]), Error> {
    let Some(("RSA PUBLIC KEY", s)) = item.object() else {
        return Err(CertFormatError.into());
    };
    parse_cert(tmp, s)
}

pub(crate) fn args_exit_policy(
    args: &mut ArgumentsIter<'_>,
) -> Result<ExitPortPolicy, CertFormatError> {
    let accept = match args.next() {
        Some("accept") => true,
        Some("reject") => false,
        _ => return Err(CertFormatError),
    };
    let ports = args.next().ok_or(CertFormatError).and_then(|s| {
        // Limit number of exit port ranges to 256
        parse_exit_ports(256, s)
    })?;
    Ok(ExitPortPolicy { accept, ports })
}

pub(crate) fn parse_exit_port(s: &str) -> Result<ExitPort, CertFormatError> {
    parse_maybe_range(s)
        .map(ExitPort::from)
        .ok_or(CertFormatError)
}

pub(crate) fn parse_exit_ports(max_n: usize, s: &str) -> Result<Vec<ExitPort>, CertFormatError> {
    let mut last = 0;
    let mut r = Vec::new();
    for i in memchr_iter(b',', s.as_bytes()).chain([s.len()]) {
        // SAFETY: Index points to , character in string or is string length
        let s = unsafe { s.get_unchecked(last..i) };
        last = i + 1;
        let v = parse_exit_port(s)?;

        if let ExitPort::PortRange { from, to } = v
            && to <= from
        {
            return Err(CertFormatError);
        } else if let (
            Some(ExitPort::Port(p) | ExitPort::PortRange { to: p, .. }),
            ExitPort::Port(v) | ExitPort::PortRange { from: v, .. },
        ) = (r.last(), &v)
            && v.saturating_sub(*p) <= 1
        {
            return Err(CertFormatError);
        }

        if r.len() >= max_n {
            return Err(CertFormatError);
        }
        r.push(v);
    }

    Ok(r)
}

#[derive(Debug, Clone)]
pub(crate) struct CommaIter<'a> {
    s: &'a str,
    off: usize,
    it: Memchr<'a>,
}

impl CommaIter<'_> {
    pub(crate) fn terminate(&mut self) {
        self.s = "";
    }
}

impl<'a> From<&'a str> for CommaIter<'a> {
    fn from(s: &'a str) -> Self {
        Self {
            s,
            off: 0,
            it: Memchr::new(b',', s.as_bytes()),
        }
    }
}

impl<'a> Iterator for CommaIter<'a> {
    type Item = &'a str;

    fn next(&mut self) -> Option<Self::Item> {
        if self.s.is_empty() {
            return None;
        }

        let Some(mut i) = self.it.next() else {
            return Some(take(&mut self.s));
        };
        i -= self.off;
        self.off += i + 1;
        // SAFETY: Index points to , character in string
        let (a, b) = unsafe { (self.s.get_unchecked(..i), self.s.get_unchecked(i + 1..)) };
        self.s = b;
        Some(a)
    }
}

impl DoubleEndedIterator for CommaIter<'_> {
    fn next_back(&mut self) -> Option<Self::Item> {
        if self.s.is_empty() {
            return None;
        }

        let Some(mut i) = self.it.next_back() else {
            return Some(take(&mut self.s));
        };
        i -= self.off;
        // SAFETY: Index points to , character in string
        let (a, b) = unsafe { (self.s.get_unchecked(..i), self.s.get_unchecked(i + 1..)) };
        self.s = a;
        Some(b)
    }
}

impl FusedIterator for CommaIter<'_> {}

#[cfg(test)]
mod tests {
    use super::*;

    use std::fmt::Write as _;

    use crate::parse::strat_exit_ports;

    use proptest::prelude::*;

    proptest! {
        #[test]
        fn test_parse_exit_ports(v in strat_exit_ports()) {
            let mut s = String::new();
            for v in &v {
                if !s.is_empty() {
                    s.push(',');
                }
                write!(s, "{v}").unwrap();
            }

            let r = parse_exit_ports(usize::MAX, &s).unwrap();
            assert_eq!(r, v);
        }

        #[test]
        fn test_parse_exit_port_maybe_fail(s: String) {
            let v = if let Some((a, b)) = s.split_once('-') {
                if !a.starts_with("+") && !b.starts_with("+") && let (Ok(from), Ok(to)) = (a.parse::<u16>(), b.parse::<u16>()) {
                    Some(ExitPort::PortRange { from, to })
                } else {
                    None
                }
            } else if !s.starts_with("+") && let Ok(p) = s.parse::<u16>() {
                Some(ExitPort::Port(p))
            } else {
                None
            };

            let r = parse_exit_port(&s).ok();
            assert_eq!(r, v);
        }
    }
}
