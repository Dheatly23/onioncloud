//! Directory authority certificate parser.
//!
//! Parses and validate directory authority certificates (at `/tor/keys/all`).

use std::net::SocketAddr;
use std::str::FromStr;
use std::time::SystemTime;

use base64ct::{Base64, Decoder};
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
    /// Address of directory authority.
    pub address: Option<SocketAddr>,

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

        let mut tmp = Vec::with_capacity(1024);

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
                    crosscert = match decode_sig(&mut tmp, s.as_bytes()) {
                        Some(v) => Some(v),
                        _ => return Some(Err(CertFormatError.into())),
                    };
                }
                // dir-key-certification has object, without extra args, and is exactly once
                ("dir-key-certification", Some(("SIGNATURE", s)))
                    if item.arguments().next().is_none() =>
                {
                    signature = match decode_sig(&mut tmp, s.as_bytes()) {
                        Some(v) => v,
                        _ => return Some(Err(CertFormatError.into())),
                    };

                    end_off = item.byte_offset() + item.len() + 1;
                    end_msg = item.byte_offset() + item.line_len() + 1;

                    break;
                }
                _ => return Some(Err(CertFormatError.into())),
            }
        }

        drop(tmp);

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
            let hashed = RelayId::from(Sha1::digest(msg.into_vec()));
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
            address,

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

    /// Verify published and expired dates.
    pub fn verify_expiry(&self, now: SystemTime) -> bool {
        self.published > now || self.expired <= now
    }
}

fn decode_sig(tmp: &mut Vec<u8>, s: &[u8]) -> Option<Signature> {
    tmp.clear();
    Decoder::<Base64>::new_wrapped(s, 64)
        .ok()?
        .decode_to_end(tmp)
        .ok()?
        .try_into()
        .ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::fmt::Write as _;
    use std::net::IpAddr;
    use std::time::Duration;

    use base64ct::{Encoder, LineEnding};
    use chrono::format::strftime::StrftimeItems;
    use chrono::{DateTime, Utc};
    use proptest::prelude::*;
    use rand::thread_rng;
    use rsa::pkcs1v15::SigningKey;
    use rsa::signature::{RandomizedDigestSigner, Signer};

    use crate::util::{print_hex, test_rsa_pk};

    fn write_datetime(s: &mut String, dt: DateTime<Utc>) {
        const FMT: StrftimeItems = StrftimeItems::new("%Y-%m-%d %H:%M:%S");
        write!(s, "{}", dt.naive_utc().format_with_items(FMT.clone())).unwrap();
    }

    fn encode_sig(sig: Signature) -> String {
        let mut buf = [0; 1024];
        let mut enc = Encoder::<Base64>::new_wrapped(&mut buf, 64, LineEnding::LF).unwrap();
        enc.encode(&Box::<[u8]>::from(sig)).unwrap();
        String::from_utf8(enc.finish_with_remaining().unwrap().0.into()).unwrap()
    }

    #[test]
    fn test_auth_cert_example() {
        let mut parser = Parser::new(
            r"dir-key-certificate-version 3
fingerprint 0232AF901C31A04EE9848595AF9BB7620D4C5B2E
dir-key-published 2025-02-23 13:04:14
dir-key-expires 2026-02-23 13:04:14
dir-identity-key
-----BEGIN RSA PUBLIC KEY-----
MIIBigKCAYEAu9O0Pueesn0+29BlxZs60mBqehjdQtgSnKOm9QZxbQ0xrMQgbFnR
hWbKD8erenyeFk2SF6AJkbyzgYC89hyPW+8GBDmg5bE8fRKjgV/nI3tY2m4rkY3u
zSmYIdwqHUUc98Xzt9PaQ8IJAlDBY4XLKrWmJMxSyhBlVEept7+9Tj23qowW44Mz
xPJZ1aFkB1FpkD6qmoCzVZbhXy3cGt1nDwdJK7KqlaXziz9pFiw8PzTVU2xFgJNy
+nEcT72DBtk3G5K2Riu/aXY/D541Cioj9KMV4Nv4g8aBKx58Xq2tq1pFkc1Bqj1y
2MomVR3iskFzlqC8yKWGVe4OP2IaOhtcQJYp5GR9q+dWnr53WWNVxNu3sA9iMal3
PJUk5pIYrsmArGew5gmlCe+Al46nPINxc7ouztmStAV+2F6SpZlKOcstnT+KJ52O
1xnOSaj/WnzG2o4KZ9UrFQoUNOLQJcelPcC+vrinMk9BQPcB072l9NjpUBC9brsW
qTCMStn1jfDDAgMBAAE=
-----END RSA PUBLIC KEY-----
dir-signing-key
-----BEGIN RSA PUBLIC KEY-----
MIIBCgKCAQEAoUlOIijVazsyQ8Ou44IBtJUQigiosmyzXEawNiegdA5UyC5YLRV3
9eKkw0A0AzXOxpmpUIw2woJFQaXjP/gNroRtpXUDX7RR6JEEvK34DnH1eI5LUX9E
pyjEI5tr2NeB3EOUN4pcFcbmG4EPihTS9vOvdgSWNgwAQ12AotBRjezUSefCMhSs
vauvo5UcRuN/8AQtWgt4RkB9AlvP9jvxzR2G/dZ/C8z6FvwrLiCmpsox8Rc6xF39
BZahQb4o67/jUiudFMqzpe7n2IUePWs8lRxnWaA60vyw1X9vmJuwZofj3PuELSk5
aCtI5/nzQqXtEakGj5nenxghEZuuFoZMXwIDAQAB
-----END RSA PUBLIC KEY-----
dir-key-crosscert
-----BEGIN ID SIGNATURE-----
mf5FIELhKihhfXyWqS1PU2izf2CcM8f7vYeUhQSN3ep29m5lD6ipkErBXjffO6rS
GxzWjk/UYB25vYA4Ucje4SNpihNlBhlmvIuPgXNBv1YvFee1acDH/BR+K+DJEOfc
ci8tBUrx6Lty0ZFepvrhEdsPvcY8oxGEP4g60Un8EBB2LxqT3U0JdClSM/vKi7rQ
aP7fcH0sBmVo5IqaFb3g8ihIrtFMR46seG5AM98pd7HJX+aWLHzda8PaPf9nN3Ji
x9V9bX6dspESqmZoVFuetZZqZLdes9qesjrIhuFWmPg6C2BCBJpnajwv8umdkRNS
NkE03EKzi7jZPuPi9rDSGg==
-----END ID SIGNATURE-----
dir-key-certification
-----BEGIN SIGNATURE-----
Ocn1HxX15/Ia2T8po2fZ8SK4219G42NXvz5BEDqD8ezG+c6wTsek87Qns/Kvelgt
JqXRGbZLTJ5ipuHl/ZFk1ewXKSWReuKv+V5XR1VcppbgUlvyIatfZ4Ljey/3LxVu
V7zI/H6Q1Bjd6/ciLfcMTu8tfxFPB6cKLAJWybFS5kFhWgWgKZ/Kr0c7K4AZpYYz
Nuiv7W0d9K4dSl/TNl8l0TC17rPJzS98+W9AA9DdBJzTC7ujEjITW+HVuYcrMLhv
wEg1ydnxvF8TWTwl8/69xHPEcRrkmV8sp3BF0LAtqCrfKdVxbOhdPz7a4HN4kNrL
NzafEZbpqdQEBJ5+rUwJ8KJfEtOgYP3Mj2ngC3w0jpyNGCWEdbSw103uljBe1uZg
xzqFJz1ECOmsjym0sOH/XTb1Jxw2hhDZBnDr5Fzp27KwrEva2I43kwlcv7ip9w3e
kHgepW7IkJFnbeYWVaFDMDr+QwXHSj9SBySlkLlOxix+nopDQZAQQDkeL65ZRLI4
-----END SIGNATURE-----
",
        );

        let _ = parser.next().unwrap().unwrap();
        if let Some(i) = parser.next() {
            panic!("expect None, got {:?}", i.as_ref().map(|v| v.s));
        }
    }

    #[test]
    fn test_auth_cert() {
        let private_key = test_rsa_pk();
        let public_key = private_key.to_public_key();
        let sign_key = SigningKey::<Sha1>::from(private_key.clone());
        let (id_key, fingerprint, crosscert) = {
            let doc = public_key.to_pkcs1_der().unwrap();
            let pem = doc.to_pem("RSA PUBLIC KEY", LineEnding::LF).unwrap();
            let hash = Sha1::new_with_prefix(doc.into_vec());
            (
                pem,
                RelayId::from(hash.clone().finalize()),
                encode_sig(sign_key.sign_digest_with_rng(&mut thread_rng(), hash)),
            )
        };

        proptest!(|(
            published: u32,
            expired: u32,
            addr in any::<Option<(IpAddr, u16)>>().prop_map(|v| v.map(|(ip, port)| SocketAddr::new(ip, port))),
        )| {
            let published = SystemTime::UNIX_EPOCH + Duration::from_secs(published.into());
            let expired = SystemTime::UNIX_EPOCH + Duration::from_secs(expired.into());

            let mut s = String::from("dir-key-certificate-version 3\n");
            if let Some(addr) = &addr {
                writeln!(s, "dir-address {addr}").unwrap();
            }
            writeln!(s, "fingerprint {}", print_hex(&fingerprint)).unwrap();
            write!(s, "dir-key-published ").unwrap();
            write_datetime(&mut s, published.into());
            writeln!(s, "").unwrap();
            write!(s, "dir-key-expires ").unwrap();
            write_datetime(&mut s, expired.into());
            write!(s, "\ndir-identity-key\n{id_key}").unwrap();
            write!(s, "dir-signing-key\n{id_key}").unwrap();
            writeln!(s, "dir-key-crosscert\n-----BEGIN ID SIGNATURE-----\n{crosscert}\n-----END ID SIGNATURE-----").unwrap();
            writeln!(s, "dir-key-certification").unwrap();
            let sig = sign_key.sign(s.as_bytes());
            writeln!(s, "-----BEGIN SIGNATURE-----\n{}\n-----END SIGNATURE-----", encode_sig(sig)).unwrap();

            let mut parser = Parser::new(&s);
            let Item {
                fingerprint: fingerprint_,
                published: published_,
                expired: expired_,
                address,
                id_key,
                sign_key,
                ..
            } = parser.next().unwrap().unwrap();

            assert_eq!(fingerprint_, fingerprint);
            assert_eq!(published_, published);
            assert_eq!(expired_, expired);
            assert_eq!(address, addr);
            assert_eq!(RsaPublicKey::from(id_key), public_key);
            assert_eq!(RsaPublicKey::from(sign_key), public_key);

            if let Some(i) = parser.next() {
                panic!("expect None, got {:?}", i.as_ref().map(|v| v.s));
            }
        });
    }
}
