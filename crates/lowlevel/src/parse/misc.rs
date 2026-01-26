//! Helper functions for netdoc parsing.

use base64ct::{Base64, Base64Unpadded, Decoder, Encoding, Error as B64Error};
use chrono::{DateTime, NaiveDateTime, Utc};

use rsa::RsaPublicKey;
use rsa::pkcs1::DecodeRsaPublicKey;
use rsa::pkcs1::der::pem::BASE64_WRAP_WIDTH;
use rsa::pkcs1v15::Signature;

use super::netdoc::{Arguments, Item};
use super::{ExitPort, ExitPortPolicy};
use crate::errors::{CertFormatError, CertVerifyError};
use crate::util::parse::{parse_date, parse_time};

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

pub(crate) fn args_date_time(args: &mut Arguments<'_>) -> Option<DateTime<Utc>> {
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

pub(crate) fn parse_cert<'a, T: From<RsaPublicKey>>(
    tmp: &'a mut [u8],
    s: &str,
) -> Result<(T, &'a [u8]), Error> {
    let der = decode_b64(tmp, s)?;
    let Ok(key) = RsaPublicKey::from_pkcs1_der(der) else {
        return Err(CertVerifyError.into());
    };
    Ok((key.into(), der))
}

pub(crate) fn decode_b64<'a>(tmp: &'a mut [u8], s: &str) -> Result<&'a [u8], Error> {
    let mut d =
        Decoder::<Base64>::new_wrapped(s.as_bytes(), BASE64_WRAP_WIDTH).map_err(map_b64_err)?;
    let tmp = tmp.get_mut(..d.remaining_len()).ok_or(CertVerifyError)?;
    d.decode(tmp).map_err(map_b64_err)
}

pub(crate) fn decode_cert<'a, T: From<RsaPublicKey>>(
    tmp: &'a mut [u8],
    item: &Item<'_>,
) -> Result<(T, &'a [u8]), Error> {
    let Some(("RSA PUBLIC KEY", s)) = item.object() else {
        return Err(CertFormatError.into());
    };
    let der = decode_b64(tmp, s)?;
    let Ok(key) = RsaPublicKey::from_pkcs1_der(der) else {
        return Err(CertVerifyError.into());
    };
    Ok((key.into(), der))
}

pub(crate) fn decode_sig(tmp: &mut [u8], s: &str) -> Result<Signature, Error> {
    decode_b64(tmp, s)?
        .try_into()
        .map_err(|_| CertVerifyError.into())
}

pub(crate) fn args_exit_policy(
    args: &mut Arguments<'_>,
) -> Result<ExitPortPolicy, CertFormatError> {
    let accept = match args.next() {
        Some("accept") => true,
        Some("reject") => false,
        _ => return Err(CertFormatError),
    };
    let ports = args
        .next()
        .ok_or(CertFormatError)
        .and_then(parse_exit_ports)?;
    let mut ret = ExitPortPolicy { accept, ports };
    if !ret.sort_validate() {
        return Err(CertFormatError.into());
    }
    Ok(ret)
}

pub(crate) fn parse_exit_port(s: &str) -> Result<ExitPort, CertFormatError> {
    let mut s = s.as_bytes();
    let mut a = 0u16;
    let mut i = 0;
    loop {
        a = match s.get(i) {
            None if i != 0 => return Ok(ExitPort::Port(a)),
            Some(b'-') => {
                (s, i) = (&s[i + 1..], 0);
                break;
            }
            Some(c @ b'0'..=b'9') if !(i != 0 && a == 0) => a
                .checked_mul(10)
                .and_then(|v| v.checked_add((c - b'0') as u16))
                .ok_or(CertFormatError)?,
            _ => return Err(CertFormatError),
        };
        i += 1;
    }

    let mut b = 0u16;
    loop {
        b = match s.get(i) {
            None if i != 0 => return Ok(ExitPort::PortRange { from: a, to: b }),
            Some(c @ b'0'..=b'9') if !(i != 0 && b == 0) => b
                .checked_mul(10)
                .and_then(|v| v.checked_add((c - b'0') as u16))
                .ok_or(CertFormatError)?,
            _ => return Err(CertFormatError),
        };
        i += 1;
    }
}

pub(crate) fn parse_exit_ports(s: &str) -> Result<Vec<ExitPort>, CertFormatError> {
    s.split(',')
        .map(parse_exit_port)
        .collect::<Result<Vec<_>, _>>()
}

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

            let r = parse_exit_ports(&s).unwrap();
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
