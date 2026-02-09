//! Microdescriptor parser.
//!
//! Parses and validate microdescriptor.
//!
//! See also:
//! - [Microdescriptor format](https://spec.torproject.org/dir-spec/computing-microdescriptors.html).

use std::iter::FusedIterator;
use std::net::SocketAddr;

use rsa::RsaPublicKey;

use super::ExitPortPolicy;
use super::misc::{args_exit_policy, decode_cert, parse_b64, parse_b64u};
use super::netdoc::{Arguments as NetdocArguments, Item as NetdocItem, NetdocParser};
use crate::crypto::EdPublicKey;
use crate::crypto::relay::{RelayId, RelayIdEd};
use crate::errors::{CertFormatError, MicrodescError};

/// Parser for (concatenated) microdescriptors.
#[derive(Clone)]
pub struct Parser<'a> {
    inner: NetdocParser<'a>,
    item: Option<NetdocItem<'a>>,
}

impl<'a> Parser<'a> {
    /// Create a new [`Parser`].
    pub const fn new(s: &'a str) -> Self {
        Self {
            inner: NetdocParser::new(s),
            item: None,
        }
    }

    /// Gets the original string.
    ///
    /// ```
    /// use onioncloud_lowlevel::parse::microdesc::Parser;
    ///
    /// // Doesn't have to be a valid microdescriptor.
    /// let s = "abc";
    /// let parser = Parser::new(s);
    ///
    /// assert_eq!(parser.original_string(), s);
    /// ```
    pub const fn original_string(&self) -> &'a str {
        self.inner.original_string()
    }

    #[inline(always)]
    fn parse(&mut self) -> Result<Option<Item<'a>>, MicrodescError> {
        // Starting item
        let item = match self.item.take() {
            Some(v) => v,
            None => match self.inner.next().transpose()? {
                Some(v) => v,
                None => return Ok(None),
            },
        };
        if item.keyword() != "onion-key" || !item.arguments().is_empty() {
            return Err(CertFormatError.into());
        }
        let start_off = item.byte_offset();

        let mut tmp = [0; 2048];

        let onion_key = if item.has_object() {
            Some(decode_cert(&mut tmp, &item)?.0)
        } else {
            None
        };

        let mut ntor_onion_key = None::<EdPublicKey>;
        let mut family = None;
        let mut family_ids = None;
        let mut exit_policy = None;
        let mut ipv6_policy = None;
        let mut fingerprint = None::<RelayId>;
        let mut ed_id_pk = None::<RelayIdEd>;
        let mut end_off = self.original_string().len();

        while let Some(item) = self.inner.next().transpose()? {
            match item.keyword() {
                // ntor-onion-key is exactly once
                "ntor-onion-key" => {
                    if ntor_onion_key.is_some() {
                        return Err(CertFormatError.into());
                    }
                    let v = item.arguments().iter().next().ok_or(CertFormatError)?;
                    ntor_onion_key = Some(parse_b64u(v).or_else(|_| parse_b64(v))?);
                }
                // a can be any number
                "a" => {
                    // Process but discard the address.
                    // Relevant OR address should be in consensus.
                    // Is not generated since consensus method 27.
                    let _ = item
                        .arguments()
                        .iter()
                        .next()
                        .and_then(|v| v.parse::<SocketAddr>().ok())
                        .ok_or(CertFormatError)?;
                }
                // family is at most once
                "family" => {
                    if family.is_some() {
                        return Err(CertFormatError.into());
                    }
                    family = Some(item.arguments());
                }
                // family-ids is at most once
                "family-ids" => {
                    if family_ids.is_some() {
                        return Err(CertFormatError.into());
                    }
                    family_ids = Some(item.arguments());
                }
                // p is at most once
                "p" => {
                    if exit_policy.is_some() {
                        return Err(CertFormatError.into());
                    }
                    exit_policy = Some(args_exit_policy(&mut item.arguments().iter())?);
                }
                // p6 is at most once
                "p6" => {
                    if ipv6_policy.is_some() {
                        return Err(CertFormatError.into());
                    }
                    ipv6_policy = Some(args_exit_policy(&mut item.arguments().iter())?);
                }
                // id is at most once for each version
                "id" => {
                    let mut args = item.arguments().iter();
                    match args.next().ok_or(CertFormatError)? {
                        "rsa1024" => {
                            if fingerprint.is_some() {
                                return Err(CertFormatError.into());
                            }
                            fingerprint = Some(parse_b64u(args.next().ok_or(CertFormatError)?)?);
                        }
                        "ed25519" => {
                            if ed_id_pk.is_some() {
                                return Err(CertFormatError.into());
                            }
                            ed_id_pk = Some(parse_b64u(args.next().ok_or(CertFormatError)?)?);
                        }
                        // Unknown identity type, ignore
                        _ => (),
                    }
                }
                // onion-key is beginning of the next microdescriptor
                "onion-key" => {
                    end_off = item.byte_offset();
                    self.item = Some(item);
                    break;
                }
                // Unknown keyword, skip
                _ => (),
            }
        }

        let Some(ntor_onion_key) = ntor_onion_key else {
            return Err(CertFormatError.into());
        };

        Ok(Some(Item {
            // SAFETY: Indices are valid.
            s: unsafe { self.original_string().get_unchecked(start_off..end_off) },
            byte_off: start_off,

            onion_key,
            ntor_onion_key,
            family,
            family_ids,
            exit_policy,
            ipv6_policy,
            fingerprint,
            ed_id_pk,
        }))
    }
}

impl<'a> Iterator for Parser<'a> {
    type Item = Result<Item<'a>, MicrodescError>;

    fn next(&mut self) -> Option<Self::Item> {
        let ret = self.parse();
        if ret.is_err() {
            self.item = None;
            self.inner.terminate();
        }
        ret.transpose()
    }
}

impl FusedIterator for Parser<'_> {}

/// A single microdescriptor.
#[derive(Debug, Clone)]
pub struct Item<'a> {
    /// Original document.
    s: &'a str,
    /// Byte offset.
    byte_off: usize,

    /// Legacy TAP onion key.
    pub onion_key: Option<RsaPublicKey>,
    /// Ntor onion key.
    pub ntor_onion_key: EdPublicKey,
    /// Relay families.
    pub family: Option<NetdocArguments<'a>>,
    /// Relay family ids.
    pub family_ids: Option<NetdocArguments<'a>>,
    /// Ipv4 exit policy.
    ///
    /// If does not exist, assume rejeect everything.
    pub exit_policy: Option<ExitPortPolicy>,
    /// Ipv6 exit policy.
    ///
    /// If does not exist, assume rejeect everything.
    pub ipv6_policy: Option<ExitPortPolicy>,
    /// Included relay fingerprint.
    pub fingerprint: Option<RelayId>,
    /// Included relay Ed25519 identity public key.
    pub ed_id_pk: Option<RelayIdEd>,
}

impl<'a> Item<'a> {
    /// Returns total length of microdescriptor (including trailing newline).
    #[allow(clippy::len_without_is_empty)]
    pub fn len(&self) -> usize {
        self.s.len()
    }

    /// Returns byte offset of item.
    #[inline(always)]
    pub fn byte_offset(&self) -> usize {
        self.byte_off
    }

    /// Returns the entire microdescriptor string.
    #[inline(always)]
    pub fn as_string(&self) -> &'a str {
        self.s
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::fmt::Write as _;

    use base64ct::{Base64Unpadded, Encoding, LineEnding};
    use proptest::collection::vec;
    use proptest::option::of;
    use proptest::prelude::*;
    use rsa::pkcs1::{DecodeRsaPublicKey, EncodeRsaPublicKey};

    use crate::parse::strat_exit_policy;
    use crate::util::{print_hex, socket_strat, test_rsa_pk};

    #[test]
    fn test_microdesc_example() {
        let s = r"onion-key
-----BEGIN RSA PUBLIC KEY-----
MIGJAoGBALTKPNW9Avks7hHJGyVdCkpy1u0Z9o7qd70RNk9uzpzZT4l0tyA2QjbH
HGVOFPyWODM4fP3eiA7tazFUXXr9Es1lU3ZquLygHlvBKuEWjnEYWfvlESfS0FeY
7kcKsIQchfP3KvYeodo0E8+qBYx6UV5shtadmdQlx39jmZQRA4nZAgMBAAE=
-----END RSA PUBLIC KEY-----
ntor-onion-key MMASIIHaeTxh6wtC+QilKUM1jYcbDXquL4qd8B6UOGc
family $0028C91CFBA3601F32F90EF9643BEF5ED031A658 $9DFE9ED2BE1FFE691CCBB7BA324B407C837400DD
id ed25519 LpocaDlIc67UffNSkSYI3PN/T6ZxdNTNPwwNEy8zzo0
";

        let mut parser = Parser::new(s);
        let desc = parser.next().unwrap().unwrap();

        assert_eq!(
            desc.onion_key,
            Some(
                RsaPublicKey::from_pkcs1_pem(
                    r"-----BEGIN RSA PUBLIC KEY-----
MIGJAoGBALTKPNW9Avks7hHJGyVdCkpy1u0Z9o7qd70RNk9uzpzZT4l0tyA2QjbH
HGVOFPyWODM4fP3eiA7tazFUXXr9Es1lU3ZquLygHlvBKuEWjnEYWfvlESfS0FeY
7kcKsIQchfP3KvYeodo0E8+qBYx6UV5shtadmdQlx39jmZQRA4nZAgMBAAE=
-----END RSA PUBLIC KEY-----"
                )
                .unwrap()
            )
        );
        assert_eq!(
            desc.ntor_onion_key,
            [
                0x30, 0xc0, 0x12, 0x20, 0x81, 0xda, 0x79, 0x3c, 0x61, 0xeb, 0x0b, 0x42, 0xf9, 0x08,
                0xa5, 0x29, 0x43, 0x35, 0x8d, 0x87, 0x1b, 0x0d, 0x7a, 0xae, 0x2f, 0x8a, 0x9d, 0xf0,
                0x1e, 0x94, 0x38, 0x67,
            ]
        );
        assert_eq!(desc.family.is_some(), true);
        assert_eq!(desc.family_ids.is_some(), false);
        assert_eq!(desc.exit_policy.is_some(), false);
        assert_eq!(desc.ipv6_policy.is_some(), false);
        assert_eq!(desc.fingerprint, None);
        assert_eq!(
            desc.ed_id_pk,
            Some([
                0x2e, 0x9a, 0x1c, 0x68, 0x39, 0x48, 0x73, 0xae, 0xd4, 0x7d, 0xf3, 0x52, 0x91, 0x26,
                0x08, 0xdc, 0xf3, 0x7f, 0x4f, 0xa6, 0x71, 0x74, 0xd4, 0xcd, 0x3f, 0x0c, 0x0d, 0x13,
                0x2f, 0x33, 0xce, 0x8d,
            ])
        );

        if let Some(desc) = parser.next() {
            panic!("expected parser to end, got {desc:?}");
        }
    }

    #[test]
    fn test_parse_microdesc() {
        let public_key = test_rsa_pk().to_public_key();
        let pem = public_key.to_pkcs1_pem(LineEnding::LF).unwrap();

        fn write_exit_policy(s: &mut String, policy: &ExitPortPolicy) {
            write!(s, " {} ", if policy.accept { "accept" } else { "reject" }).unwrap();
            for (i, v) in policy.ports.iter().enumerate() {
                write!(s, "{}{v}", if i > 0 { "," } else { "" }).unwrap();
            }
            write!(s, "\n").unwrap();
        }

        #[derive(Debug, Clone, Copy, PartialEq, Eq)]
        enum Entry {
            NtorOnionKey,
            Addr,
            Family,
            ExitPolicy,
            Ipv6Policy,
            IdRsa,
            IdEd,
        }

        proptest! {
            |(descs in vec((
                any::<bool>(),
                any::<RelayIdEd>(),
                vec(socket_strat(), 0..=8),
                vec(any::<RelayId>(), 0..=8),
                of(strat_exit_policy()),
                of(strat_exit_policy()),
                any::<Option<RelayId>>(),
                any::<Option<RelayIdEd>>(),
                Just([
                    Entry::NtorOnionKey,
                    Entry::Addr,
                    Entry::Addr,
                    Entry::Addr,
                    Entry::Addr,
                    Entry::Addr,
                    Entry::Addr,
                    Entry::Addr,
                    Entry::Addr,
                    Entry::Family,
                    Entry::ExitPolicy,
                    Entry::Ipv6Policy,
                    Entry::IdRsa,
                    Entry::IdEd,
                ]).prop_shuffle(),
            ), 1..=16))| {
                let mut s = String::new();

                for (
                    has_onion_key,
                    ntor_onion_key,
                    addrs,
                    family,
                    exit_policy,
                    ipv6_policy,
                    id_rsa,
                    id_ed,
                    entries,
                ) in descs.iter() {
                    write!(s, "onion-key\n").unwrap();
                    if *has_onion_key {
                        write!(s, "{pem}").unwrap();
                    }

                    let mut addrs = addrs.iter();
                    for e in entries {
                        match e {
                            Entry::NtorOnionKey => write!(s, "ntor-onion-key {}\n", Base64Unpadded::encode(ntor_onion_key, &mut [0; 43]).unwrap()).unwrap(),
                            Entry::Addr => {
                                if let Some(socket) = addrs.next() {
                                    write!(s, "a {socket}\n").unwrap();
                                }
                            }
                            Entry::Family => {
                                if !family.is_empty() {
                                    write!(s, "family").unwrap();
                                    for v in family.iter() {
                                        write!(s, " ${}", print_hex(v)).unwrap();
                                    }
                                    write!(s, "\n").unwrap();
                                }
                            }
                            Entry::ExitPolicy => {
                                if let Some(p) = exit_policy {
                                    write!(s, "p").unwrap();
                                    write_exit_policy(&mut s, p);
                                }
                            }
                            Entry::Ipv6Policy => {
                                if let Some(p) = ipv6_policy {
                                    write!(s, "p6").unwrap();
                                    write_exit_policy(&mut s, p);
                                }
                            }
                            Entry::IdRsa => {
                                if let Some(id) = id_rsa {
                                    write!(s, "id rsa1024 {}\n", Base64Unpadded::encode(id, &mut [0; 27]).unwrap()).unwrap();
                                }
                            }
                            Entry::IdEd => {
                                if let Some(id) = id_ed {
                                    write!(s, "id ed25519 {}\n", Base64Unpadded::encode(id, &mut [0; 43]).unwrap()).unwrap();
                                }
                            }
                        }
                    }
                    assert_eq!(addrs.next(), None);
                }

                let mut parser = Parser::new(&s);

                for (
                    has_onion_key,
                    ntor_onion_key,
                    _,
                    family,
                    exit_policy,
                    ipv6_policy,
                    id_rsa,
                    id_ed,
                    _,
                ) in descs {
                    let desc = parser.next().unwrap().unwrap();

                    assert_eq!(desc.onion_key.as_ref(), has_onion_key.then_some(&public_key));
                    assert_eq!(desc.ntor_onion_key, ntor_onion_key);
                    if family.is_empty() {
                        assert!(desc.family.is_none(), "family should not exist");
                    } else {
                        let mut it = desc.family.as_ref().unwrap().iter();
                        for v in family {
                            let o = it.next().unwrap();
                            assert_eq!(o, format!("${}", print_hex(&v)));
                        }
                        if let Some(v) = it.next() {
                            panic!("expected family to end, got {v:?}");
                        }
                    }
                    assert_eq!(desc.exit_policy, exit_policy);
                    assert_eq!(desc.ipv6_policy, ipv6_policy);
                    assert_eq!(desc.fingerprint, id_rsa);
                    assert_eq!(desc.ed_id_pk, id_ed);
                }

                if let Some(desc) = parser.next() {
                    panic!("expected parser to end, got {desc:?}");
                }
            }
        };
    }
}
