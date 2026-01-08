//! Directory authority certificate parser.
//!
//! Parses and validate directory authority certificates (at `/tor/keys/all`).

use std::net::SocketAddr;
use std::str::FromStr;
use std::time::SystemTime;

use base64ct::{Base64, Encoding};
use digest::Digest;
use rsa::RsaPublicKey;
use rsa::pkcs1::{DecodeRsaPublicKey, EncodeRsaPublicKey};
use rsa::pkcs1v15::{Signature, VerifyingKey};
use rsa::signature::Verifier;
use rsa::signature::hazmat::PrehashVerifier;
use sha1::Sha1;
use subtle::ConstantTimeEq;
use tracing::error;

use super::misc::args_date_time;
use super::netdoc::NetdocParser;
use crate::crypto::relay::{RelayId, from_str as relay_from_str};
use crate::errors::{AuthCertError, CertFormatError, CertVerifyError};

pub struct Parser<'a> {
    inner: NetdocParser<'a>,
}

pub struct Item<'a> {
    s: &'a str,
    byte_off: usize,

    /// Directory authority fingerprint.
    pub fingerprint: RelayId,
    /// Published date of certificate.
    pub published: SystemTime,
    /// Expired date of certificate.
    pub expired: SystemTime,

    /// Long-term identity key.
    pub id_key: VerifyingKey<Sha1>,
    /// Signing key.
    pub sign_key: VerifyingKey<Sha1>,
}

impl<'a> Parser<'a> {
    /// Create new [`Parser`].
    #[inline(always)]
    pub fn new(s: &'a str) -> Self {
        Self {
            inner: NetdocParser::new(s),
        }
    }

    /// Gets the original string.
    #[inline(always)]
    pub const fn original_string(&self) -> &'a str {
        self.inner.original_string()
    }
}

impl<'a> Iterator for Parser<'a> {
    type Item = Result<Item<'a>, AuthCertError>;

    fn next(&mut self) -> Option<Self::Item> {
        let item = match self.inner.next()? {
            Ok(v) => v,
            Err(e) => return Some(Err(e.into())),
        };
        // Starting item
        if item.keyword() != "dir-key-certificate-version"
            || item.arguments().next() != Some("3")
            || item.has_object()
        {
            return Some(Err(CertFormatError.into()));
        }

        let start_off = item.byte_offset();
        let end_off;
        let end_msg;

        let mut address = None;
        let mut fingerprint = None;
        let mut published = None;
        let mut expired = None;
        let mut identity = None;
        let mut signing = None;
        let mut crosscert = None;
        let signature;

        loop {
            let item = match self.inner.next() {
                Some(Ok(v)) => v,
                Some(Err(e)) => return Some(Err(e.into())),
                None => return Some(Err(CertFormatError.into())),
            };

            match (item.keyword(), item.object()) {
                // dir-address is at most once
                ("dir-address", None) if address.is_none() => {
                    address = match item.arguments().next().map(SocketAddr::from_str) {
                        Some(Ok(v)) => Some(v),
                        _ => return Some(Err(CertFormatError.into())),
                    };
                }
                // fingerprint is exactly once
                ("fingerprint", None) if fingerprint.is_none() => {
                    fingerprint = match item.arguments().next().map(relay_from_str) {
                        Some(Ok(v)) => Some(v),
                        _ => return Some(Err(CertFormatError.into())),
                    };
                }
                // dir-key-published is exactly once
                ("dir-key-published", None) if published.is_none() => {
                    published = match args_date_time(&mut item.arguments()) {
                        Some(v) => Some(SystemTime::from(v)),
                        _ => return Some(Err(CertFormatError.into())),
                    };
                }
                // dir-key-expires is exactly once
                ("dir-key-expires", None) if expired.is_none() => {
                    expired = match args_date_time(&mut item.arguments()) {
                        Some(v) => Some(SystemTime::from(v)),
                        _ => return Some(Err(CertFormatError.into())),
                    };
                }
                // dir-identity-key has object, without extra args, and is exactly once
                ("dir-identity-key", Some(_))
                    if item.arguments().next().is_none() && identity.is_none() =>
                {
                    identity = match <RsaPublicKey as DecodeRsaPublicKey>::from_pkcs1_pem(
                        item.object_raw().expect("object must exist"),
                    ) {
                        Ok(v) => Some(VerifyingKey::<Sha1>::from(v)),
                        _ => return Some(Err(CertFormatError.into())),
                    };
                }
                // dir-signing-key has object, without extra args, and is exactly once
                ("dir-signing-key", Some(_))
                    if item.arguments().next().is_none() && signing.is_none() =>
                {
                    signing = match <RsaPublicKey as DecodeRsaPublicKey>::from_pkcs1_pem(
                        item.object_raw().expect("object must exist"),
                    ) {
                        Ok(v) => Some(VerifyingKey::<Sha1>::from(v)),
                        _ => return Some(Err(CertFormatError.into())),
                    };
                }
                // dir-key-crosscert has object, without extra args, and is exactly once
                ("dir-key-crosscert", Some(("ID SIGNATURE" | "SIGNATURE", s)))
                    if item.arguments().next().is_none() && crosscert.is_none() =>
                {
                    crosscert = match Base64::decode_vec(s)
                        .ok()
                        .and_then(|v| Signature::try_from(&v[..]).ok())
                    {
                        Some(v) => Some(v),
                        _ => return Some(Err(CertFormatError.into())),
                    };
                }
                // dir-key-certification has object, without extra args, and is exactly once
                ("dir-key-certification", Some(("SIGNATURE", s)))
                    if item.arguments().next().is_none() =>
                {
                    signature = match Base64::decode_vec(s)
                        .ok()
                        .and_then(|v| Signature::try_from(&v[..]).ok())
                    {
                        Some(v) => v,
                        _ => return Some(Err(CertFormatError.into())),
                    };

                    end_off = item.byte_offset() + item.len();
                    end_msg = item.byte_offset() + item.line_len();

                    break;
                }
                _ => return Some(Err(CertFormatError.into())),
            }
        }

        let (
            Some(fingerprint),
            Some(published),
            Some(expired),
            Some(identity),
            Some(signing),
            Some(crosscert),
        ) = (
            fingerprint,
            published,
            expired,
            identity,
            signing,
            crosscert,
        )
        else {
            return Some(Err(CertFormatError.into()));
        };

        // Verify certificate
        {
            let msg = &self.inner.original_string().as_bytes()[start_off..end_msg];
            if identity.verify(msg, &signature).is_err() {
                return Some(Err(CertVerifyError.into()));
            }
            drop(signature);
        }

        // Verify published and expired
        let now = SystemTime::now();
        if published > now || expired <= now {
            return Some(Err(CertVerifyError.into()));
        }

        {
            let msg = match identity.to_pkcs1_der() {
                Ok(v) => v,
                Err(e) => {
                    error!(
                        "cannot re-encode identity key (normally this should not happen): {e:?}"
                    );
                    return Some(Err(CertVerifyError.into()));
                }
            };

            // Verify fingerprint
            let hashed = RelayId::from(Sha1::digest(msg.to_vec()));
            if !bool::from(fingerprint.ct_eq(&hashed)) {
                return Some(Err(CertVerifyError.into()));
            }

            // Verify crosscert
            if signing.verify_prehash(&hashed, &crosscert).is_err() {
                return Some(Err(CertVerifyError.into()));
            }
            drop(crosscert);
        }

        Some(Ok(Item {
            s: &self.inner.original_string()[start_off..end_off],
            byte_off: start_off,

            fingerprint,
            published,
            expired,

            id_key: identity,
            sign_key: signing,
        }))
    }
}

impl<'a> Item<'a> {
    /// Returns byte offset of item.
    #[inline(always)]
    pub fn byte_offset(&self) -> usize {
        self.byte_off
    }

    /// Returns the entire certificate string.
    #[inline(always)]
    pub fn as_string(&self) -> &'a str {
        self.s
    }
}
