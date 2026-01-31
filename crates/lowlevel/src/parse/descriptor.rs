//! Descriptor and extra info parser.
//!
//! Parses and validate descriptor and extra info.
//!
//! See also:
//! - [Descriptor format](https://spec.torproject.org/dir-spec/server-descriptor-format.html).
//! - [Extra info format](https://spec.torproject.org/dir-spec/extra-info-document-format.html).

use std::iter::FusedIterator;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::time::SystemTime;

use curve25519_dalek::montgomery::MontgomeryPoint;
use digest::Digest;
use ed25519_dalek::VerifyingKey;
use memchr::{memchr, memrchr};
use rsa::RsaPublicKey;
use rsa::pkcs1v15::Pkcs1v15Sign;
use sha1::Sha1;
use sha2::Sha256;
use subtle::ConstantTimeEq;
use zerocopy::{Immutable, IntoBytes};

use super::misc::{
    args_date_time, args_exit_policy, decode_b64, parse_b64, parse_b64u, parse_cert,
    parse_exit_port,
};
use super::netdoc::{Arguments as NetdocArguments, Item as NetdocItem, NetdocParser};
use super::{ExitPort, ExitPortPolicy};
use crate::crypto::cert::UnverifiedEdCert;
use crate::crypto::relay::{RelayId, from_str_ed as relay_ed_from_str};
use crate::crypto::{EdPublicKey, EdSignature, Sha1Output, Sha256Output, montgomery_to_edwards};
use crate::errors::{CertFormatError, CertVerifyError, DescriptorError};
use crate::util::parse::parse_hex;

/// Parser for (concatenated) descriptors.
pub struct DescriptorParser<'a> {
    inner: NetdocParser<'a>,
}

impl<'a> DescriptorParser<'a> {
    /// Create a new [`DescriptorParser`].
    pub const fn new(s: &'a str) -> Self {
        Self {
            inner: NetdocParser::new(s),
        }
    }

    /// Gets the original string.
    ///
    /// ```
    /// use onioncloud_lowlevel::parse::descriptor::DescriptorParser;
    ///
    /// // Doesn't have to be a valid certificate.
    /// let s = "abc";
    /// let parser = DescriptorParser::new(s);
    ///
    /// assert_eq!(parser.original_string(), s);
    /// ```
    pub const fn original_string(&self) -> &'a str {
        self.inner.original_string()
    }

    #[inline(always)]
    fn parse(&mut self, item: NetdocItem<'a>) -> Result<Descriptor<'a>, DescriptorError> {
        // Starting item
        if item.keyword() != "router" || item.has_object() {
            return Err(CertFormatError.into());
        }
        let start_off = item.byte_offset();

        let nickname;
        let address;
        let orport;
        let dirport;

        {
            let mut args = item.arguments().iter();
            nickname = args.next().ok_or(CertFormatError)?;
            address = args
                .next()
                .and_then(|v| v.parse::<Ipv4Addr>().ok())
                .ok_or(CertFormatError)?;
            orport = args
                .next()
                .and_then(|v| v.parse::<u16>().ok())
                .ok_or(CertFormatError)?;
            args.next()
                .and_then(|v| v.parse::<u16>().ok())
                .ok_or(CertFormatError)?;
            dirport = args
                .next()
                .and_then(|v| v.parse::<u16>().ok())
                .ok_or(CertFormatError)?;
        }

        let item = self.inner.next().ok_or(CertFormatError)??;
        if item.keyword() != "identity-ed25519" || !item.arguments().is_empty() {
            return Err(CertFormatError.into());
        }

        let Some(("ED25519 CERT", cert_cont)) = item.object() else {
            return Err(CertFormatError.into());
        };
        let ed_id_pk;
        let ed_sign_pk;

        let mut tmp = [0; 2048];

        {
            let mut cert = UnverifiedEdCert::new(decode_b64(&mut tmp, cert_cont)?)?;

            if cert.header.cert_ty != 4 || cert.header.key_ty != 1 {
                return Err(CertVerifyError.into());
            }

            let mut id_pk = None;
            while let Some((header, data)) = cert.next_ext().transpose()? {
                if header.ty != 4 {
                    // Extension is not signed-with-ed25519-key
                    if header.flags & 1 != 0 {
                        // Unknown required extension
                        return Err(CertVerifyError.into());
                    } else {
                        continue;
                    }
                }

                id_pk = Some(EdPublicKey::try_from(data).map_err(|_| CertVerifyError)?);
            }

            ed_id_pk = VerifyingKey::from_bytes(&id_pk.ok_or(CertVerifyError)?)
                .map_err(|_| CertVerifyError)?;
            ed_sign_pk = VerifyingKey::from_bytes(&cert.header.key).map_err(|_| CertVerifyError)?;
            cert.verify2(&ed_id_pk)?;
        }

        let mut master_key_ed25519 = false;
        let mut bandwidth = None;
        let mut platform = None;
        let mut published = None;
        let mut fingerprint = None;
        let mut hibernating = None;
        let mut uptime = None;
        let mut onion_key = None;
        let mut onion_key_crosscert = None;
        let mut ntor_onion_key = None::<EdPublicKey>;
        let mut ntor_onion_key_crosscert = None;
        let mut signing_key = None;
        let mut exit_policy = Vec::new();
        let mut ipv6_policy = None;
        let mut overload_general = None;
        let mut contact = None;
        let mut bridge_distribution_request = None;
        let mut family = None;
        let mut family_cert = Vec::new();
        let mut eventdns = None;
        let mut caches_extra_info = false;
        let mut extra_info_digest = None;
        let mut hidden_service_dir = false;
        let mut allow_single_hop_exits = false;
        let mut or_address = None;
        let mut tunnelled_dir_server = false;
        let mut proto = None;

        let item = loop {
            let item = self.inner.next().ok_or(CertFormatError)??;

            match item.keyword() {
                // master-key-ed25519 is exactly once
                "master-key-ed25519" => {
                    if master_key_ed25519 {
                        return Err(CertFormatError.into());
                    }
                    let k = item
                        .arguments()
                        .iter()
                        .next()
                        .and_then(|v| relay_ed_from_str(v).ok())
                        .ok_or(CertFormatError)?;
                    if !bool::from(k.ct_eq(ed_id_pk.as_bytes())) {
                        return Err(CertVerifyError.into());
                    }
                    master_key_ed25519 = true;
                }
                // bandwidth is exactly once
                "bandwidth" => {
                    if bandwidth.is_some() {
                        return Err(CertFormatError.into());
                    }

                    let mut args = item.arguments().iter();
                    let average = args
                        .next()
                        .and_then(|v| v.parse::<u64>().ok())
                        .ok_or(CertFormatError)?;
                    let burst = args
                        .next()
                        .and_then(|v| v.parse::<u64>().ok())
                        .ok_or(CertFormatError)?;
                    let observed = args
                        .next()
                        .and_then(|v| v.parse::<u64>().ok())
                        .ok_or(CertFormatError)?;
                    bandwidth = Some(Bandwidth {
                        average,
                        burst,
                        observed,
                    });
                }
                // platform is at most once and takes the rest of the line
                "platform" => {
                    if platform.is_some() {
                        return Err(CertFormatError.into());
                    }
                    platform = Some(item.arguments().raw_string());
                }
                // published is exactly once
                "published" => {
                    if published.is_some() {
                        return Err(CertFormatError.into());
                    }
                    published = Some(SystemTime::from(
                        args_date_time(&mut item.arguments().iter()).ok_or(CertFormatError)?,
                    ));
                }
                // fingerprint is at most once
                "fingerprint" => {
                    if fingerprint.is_some() {
                        return Err(CertFormatError.into());
                    }
                    let mut args = item.arguments().iter();
                    let mut fp: RelayId = [0; _];
                    for v in fp.chunks_exact_mut(2) {
                        *<&mut [u8; 2]>::try_from(v).expect("size must be 2") =
                            args.next().and_then(parse_hex).ok_or(CertFormatError)?;
                    }
                    fingerprint = Some(fp);
                }
                // hibernating is at most once
                "hibernating" => {
                    if hibernating.is_some() {
                        return Err(CertFormatError.into());
                    }
                    hibernating =
                        Some(item.arguments().iter().next().ok_or(CertFormatError)? == "1");
                }
                // uptime is at most once
                "uptime" => {
                    if uptime.is_some() {
                        return Err(CertFormatError.into());
                    }
                    uptime = Some(
                        item.arguments()
                            .iter()
                            .next()
                            .and_then(|v| v.parse::<u64>().ok())
                            .ok_or(CertFormatError)?,
                    );
                }
                // onion-key is at most once and without extra args
                "onion-key" => {
                    if onion_key.is_some() || !item.arguments().is_empty() {
                        return Err(CertFormatError.into());
                    }
                    let Some(("RSA PUBLIC KEY", s)) = item.object() else {
                        return Err(CertFormatError.into());
                    };
                    onion_key = Some(s);
                }
                // onion-key-crosscert is at most once and without extra args
                "onion-key-crosscert" => {
                    if onion_key_crosscert.is_some() || !item.arguments().is_empty() {
                        return Err(CertFormatError.into());
                    }
                    let Some(("CROSSCERT", s)) = item.object() else {
                        return Err(CertFormatError.into());
                    };
                    onion_key_crosscert = Some(s);
                }
                // ntor-onion-key is exactly once
                "ntor-onion-key" => {
                    if ntor_onion_key.is_some() {
                        return Err(CertFormatError.into());
                    }
                    ntor_onion_key = Some(
                        item.arguments()
                            .iter()
                            .next()
                            .and_then(|v| parse_b64u(v).or_else(|_| parse_b64(v)).ok())
                            .ok_or(CertFormatError)?,
                    );
                }
                // ntor-onion-key-crosscert is exactly once and without extra args
                "ntor-onion-key-crosscert" => {
                    if ntor_onion_key_crosscert.is_some() {
                        return Err(CertFormatError.into());
                    }
                    let mut args = item.arguments().iter();
                    let bit = match args.next() {
                        Some("0") => false,
                        Some("1") => true,
                        _ => return Err(CertFormatError.into()),
                    };
                    if args.next().is_some() {
                        return Err(CertFormatError.into());
                    }
                    let Some(("ED25519 CERT", s)) = item.object() else {
                        return Err(CertFormatError.into());
                    };
                    ntor_onion_key_crosscert = Some((bit, s));
                }
                // signing-key is exactly once and without extra args
                "signing-key" => {
                    if signing_key.is_some() || !item.arguments().is_empty() {
                        return Err(CertFormatError.into());
                    }
                    let Some(("RSA PUBLIC KEY", s)) = item.object() else {
                        return Err(CertFormatError.into());
                    };
                    signing_key = Some(s);
                }
                // accept and reject can be any number
                kw @ ("accept" | "reject") => {
                    let policy = ExitPolicy::parse(
                        kw == "accept",
                        item.arguments().iter().next().ok_or(CertFormatError)?,
                    )
                    .ok_or(CertFormatError)?;
                    if exit_policy.len() >= 128 {
                        // Limit exit policy to 128 entries
                        return Err(CertVerifyError.into());
                    }
                    exit_policy.push(policy);
                }
                // ipv6-policy is at most once
                "ipv6-policy" => {
                    if ipv6_policy.is_some() {
                        return Err(CertFormatError.into());
                    }
                    ipv6_policy = Some(args_exit_policy(&mut item.arguments().iter())?);
                }
                // overload-general is at most once
                "overload-general" => {
                    if overload_general.is_some() {
                        return Err(CertFormatError.into());
                    }
                    let mut args = item.arguments().iter();
                    if !matches!(args.next(), Some("1")) {
                        return Err(CertFormatError.into());
                    }
                    overload_general = Some(SystemTime::from(
                        args_date_time(&mut args).ok_or(CertFormatError)?,
                    ));
                }
                // contact is at most once and takes the rest of the line
                "contact" => {
                    if contact.is_some() {
                        return Err(CertFormatError.into());
                    }
                    contact = Some(item.arguments().raw_string());
                }
                // bridge-distribution-request is at most once
                "bridge-distribution-request" => {
                    if bridge_distribution_request.is_some() {
                        return Err(CertFormatError.into());
                    }
                    bridge_distribution_request =
                        Some(item.arguments().iter().next().ok_or(CertFormatError)?);
                }
                // family is at most once
                "family" => {
                    if family.is_some() {
                        return Err(CertFormatError.into());
                    }
                    family = Some(item.arguments());
                }
                // family-cert can be any number
                "family-cert" => {
                    let Some(("FAMILY CERT", s)) = item.object() else {
                        return Err(CertFormatError.into());
                    };

                    let mut cert = UnverifiedEdCert::new(decode_b64(&mut tmp, s)?)?;

                    if cert.header.cert_ty != 0xc && cert.header.key_ty != 1
                        || !bool::from(cert.header.key.ct_eq(ed_id_pk.as_bytes()))
                    {
                        return Err(CertVerifyError.into());
                    }

                    let mut pk = None;
                    while let Some((header, data)) = cert.next_ext().transpose()? {
                        if header.ty != 4 {
                            // Extension is not signed-with-ed25519-key
                            if header.flags & 1 != 0 {
                                // Unknown required extension
                                return Err(CertVerifyError.into());
                            } else {
                                continue;
                            }
                        }

                        pk = Some(EdPublicKey::try_from(data).map_err(|_| CertVerifyError)?);
                    }

                    let f_pk = pk.ok_or(CertVerifyError)?;
                    cert.verify2(&ed_id_pk)?;

                    if family_cert.len() >= 16 {
                        // Limit family certificates to 16
                        return Err(CertVerifyError.into());
                    }
                    family_cert.push(f_pk);
                }
                // eventdns is at most once
                "eventdns" => {
                    if eventdns.is_some() {
                        return Err(CertFormatError.into());
                    }
                    eventdns = Some(item.arguments().iter().next().ok_or(CertFormatError)? == "1");
                }
                // caches-extra-info is at most once and without extra args
                "caches-extra-info" => {
                    if caches_extra_info || !item.arguments().is_empty() {
                        return Err(CertFormatError.into());
                    }
                    caches_extra_info = true;
                }
                // extra-info-digest is at most once
                "extra-info-digest" => {
                    if extra_info_digest.is_some() {
                        return Err(CertFormatError.into());
                    }
                    let mut args = item.arguments().iter();
                    let sha1: Sha1Output =
                        args.next().and_then(parse_hex).ok_or(CertFormatError)?;
                    let sha256: Option<Sha256Output> = args.next().map(parse_b64u).transpose()?;
                    extra_info_digest = Some(ExtraInfoDigest { sha1, sha256 });
                }
                // hidden-service-dir is at most once
                "hidden-service-dir" => {
                    if hidden_service_dir {
                        return Err(CertFormatError.into());
                    }
                    hidden_service_dir = true;
                }
                // allow-single-hop-exits is at most once and without extra args
                "allow-single-hop-exits" => {
                    if allow_single_hop_exits || !item.arguments().is_empty() {
                        return Err(CertFormatError.into());
                    }
                    allow_single_hop_exits = true;
                }
                // or-address can be any number
                "or-address" => {
                    let addr = item
                        .arguments()
                        .iter()
                        .next()
                        .and_then(|v| v.parse::<SocketAddr>().ok())
                        .ok_or(CertFormatError)?;
                    if let SocketAddr::V4(a) = &addr
                        && *a.ip() == address
                        && a.port() == orport
                    {
                        // or-address should not be equals to address & orport
                        return Err(CertFormatError.into());
                    } else if or_address.is_none() {
                        or_address = Some(addr);
                    }
                }
                // tunnelled-dir-server is at most once
                "tunnelled-dir-server" => {
                    if tunnelled_dir_server || !item.arguments().is_empty() {
                        return Err(CertFormatError.into());
                    }
                    tunnelled_dir_server = true;
                }
                // proto is at exactly once
                "proto" => {
                    if proto.is_some() {
                        return Err(CertFormatError.into());
                    }
                    proto = Some(item.arguments());
                }
                // router-sig-ed25519 is at exactly once at the end
                "router-sig-ed25519" => break item,
                // Unknown keyword, skip
                _ => (),
            }
        };

        let (
            true,
            Some(bandwidth),
            Some(published),
            Some(ntor_onion_key),
            Some(ntor_onion_key_crosscert),
            Some(signing_key),
            Some(proto),
        ) = (
            master_key_ed25519,
            bandwidth,
            published,
            ntor_onion_key,
            ntor_onion_key_crosscert,
            signing_key,
            proto,
        )
        else {
            return Err(CertFormatError.into());
        };

        let (signing_key, der) = parse_cert(&mut tmp, signing_key)?;
        let fp = RelayId::from(Sha1::digest(der));
        if let Some(fp_) = &fingerprint
            && !bool::from(fp_.ct_eq(&fp))
        {
            return Err(CertVerifyError.into());
        }

        let onion_key = match (onion_key, onion_key_crosscert) {
            (Some(key), Some(cert)) => {
                let key = parse_cert(&mut tmp, key)?.0;
                let sig = decode_b64(&mut tmp, cert)?;

                #[derive(IntoBytes, Immutable)]
                #[repr(C)]
                struct Data {
                    fp: RelayId,
                    ed_id: EdPublicKey,
                }

                let buf = Data {
                    fp,
                    ed_id: ed_id_pk.to_bytes(),
                };
                key.verify(Pkcs1v15Sign::new_unprefixed(), buf.as_bytes(), sig)
                    .map_err(|_| CertVerifyError)?;
                Some(key)
            }
            (None, None) => None,
            _ => return Err(CertFormatError.into()),
        };

        let ntor_onion_key_ed = VerifyingKey::from(
            montgomery_to_edwards(MontgomeryPoint(ntor_onion_key), ntor_onion_key_crosscert.0)
                .ok_or(CertVerifyError)?,
        );
        let mut cert = UnverifiedEdCert::new(decode_b64(&mut tmp, ntor_onion_key_crosscert.1)?)?;

        if cert.header.cert_ty != 0xa && cert.header.key_ty != 1
            || !bool::from(cert.header.key.ct_eq(ed_id_pk.as_bytes()))
        {
            return Err(CertVerifyError.into());
        }

        while let Some((header, _)) = cert.next_ext().transpose()? {
            if header.flags & 1 != 0 {
                // Unknown required extension
                return Err(CertVerifyError.into());
            } else {
                continue;
            }
        }

        cert.verify2(&ntor_onion_key_ed)?;

        // End of message is space after keyword.
        // In other word, start of arguments.
        let b = &self.original_string().as_bytes()
            [start_off..item.byte_offset() + item.line_len() - item.arguments().raw_string().len()];
        let sig: EdSignature = item
            .arguments()
            .iter()
            .next()
            .ok_or(CertFormatError)
            .and_then(parse_b64u)?;
        let mut hash = Sha256::new_with_prefix(b"Tor router descriptor signature v1");
        hash.update(b);
        ed_sign_pk
            .verify_strict(&hash.finalize(), &sig.into())
            .map_err(|_| CertVerifyError)?;

        let item = self.inner.next().ok_or(CertFormatError)??;
        if item.keyword() != "router-signature" || !item.arguments().is_empty() {
            return Err(CertFormatError.into());
        }

        let Some(("SIGNATURE", s)) = item.object() else {
            return Err(CertFormatError.into());
        };
        signing_key
            .verify(
                Pkcs1v15Sign::new_unprefixed(),
                &Sha1::digest(
                    &self.original_string().as_bytes()
                        [start_off..item.byte_offset() + item.line_len() + 1],
                ),
                decode_b64(&mut tmp, s)?,
            )
            .map_err(|_| CertVerifyError)?;

        Ok(Descriptor {
            // SAFETY: Indices are valid.
            s: unsafe {
                self.original_string()
                    .get_unchecked(start_off..item.byte_offset() + item.len() + 1)
            },
            byte_off: start_off,

            nickname,
            address,
            orport,
            dirport,
            ed_id_pk,
            ed_sign_pk,
            bandwidth,
            platform,
            published,
            fingerprint: fp,
            hibernating: hibernating.unwrap_or(false),
            uptime,
            onion_key,
            ntor_onion_key,
            ntor_onion_key_ed,
            signing_key,
            exit_policy,
            ipv6_policy,
            overload_general,
            contact,
            bridge_distribution_request,
            family,
            family_cert,
            eventdns: eventdns.unwrap_or(true),
            caches_extra_info,
            extra_info_digest,
            hidden_service_dir,
            allow_single_hop_exits,
            or_address,
            tunnelled_dir_server,
            proto,
        })
    }
}

impl<'a> Iterator for DescriptorParser<'a> {
    type Item = Result<Descriptor<'a>, DescriptorError>;

    fn next(&mut self) -> Option<Self::Item> {
        let ret = match self.inner.next()? {
            Ok(v) => self.parse(v),
            Err(e) => return Some(Err(e.into())),
        };
        if ret.is_err() {
            self.inner.terminate();
        }
        Some(ret)
    }
}

impl FusedIterator for DescriptorParser<'_> {}

/// A single descriptor.
#[derive(Debug, Clone)]
pub struct Descriptor<'a> {
    /// Original document.
    s: &'a str,
    /// Byte offset.
    byte_off: usize,

    /// Relay nickname.
    pub nickname: &'a str,
    /// Relay address.
    pub address: Ipv4Addr,
    /// OR port.
    pub orport: u16,
    /// Dir port.
    pub dirport: u16,
    /// Ed25519 identity key.
    pub ed_id_pk: VerifyingKey,
    /// Ed25519 signing key.
    pub ed_sign_pk: VerifyingKey,
    /// Relay bandwidth.
    pub bandwidth: Bandwidth,
    /// Platform.
    pub platform: Option<&'a str>,
    /// Descriptor publish date.
    pub published: SystemTime,
    /// Relay fingerprint.
    pub fingerprint: RelayId,
    /// Is relay hibernating?
    pub hibernating: bool,
    /// Relay uptime in seconds.
    pub uptime: Option<u64>,
    /// Legacy RSA onion key.
    pub onion_key: Option<RsaPublicKey>,
    /// Ntor onion key.
    pub ntor_onion_key: EdPublicKey,
    /// Ntor onion key converted to ed25519 point.
    ///
    /// Used for some signing operations.
    pub ntor_onion_key_ed: VerifyingKey,
    /// RSA identity key.
    pub signing_key: RsaPublicKey,
    /// Exit policy.
    pub exit_policy: Vec<ExitPolicy>,
    /// Ipv6 exit policy summary.
    pub ipv6_policy: Option<ExitPortPolicy>,
    /// When relay is overloaded.
    pub overload_general: Option<SystemTime>,
    /// Contact info.
    pub contact: Option<&'a str>,
    /// Bridge distribution method.
    ///
    /// **NOTE: Should only be set for bridge descriptor. Normal relay descriptor should not have this field.**
    pub bridge_distribution_request: Option<&'a str>,
    /// Relays that are in the same family as current relay.
    pub family: Option<NetdocArguments<'a>>,
    /// Family public keys where this relay is certified.
    ///
    /// Invalid certificate will result in error. So these are all validated.
    pub family_cert: Vec<EdPublicKey>,
    /// Obsolete eventdns flag.
    pub eventdns: bool,
    /// `true` if relay caches extra-info documents.
    pub caches_extra_info: bool,
    /// Digest of extra-info document for this descriptor.
    pub extra_info_digest: Option<ExtraInfoDigest>,
    /// `true` if relay is a hidden service directory.
    pub hidden_service_dir: bool,
    /// `true` if relay allows single hop exit.
    ///
    /// None of deployed relays support it. It's only used for development purposes.
    pub allow_single_hop_exits: bool,
    /// Alternate OR port address.
    ///
    /// Though relay can declare any number of it, only the first one is parsed and returned.
    pub or_address: Option<SocketAddr>,
    /// `true` if relay supports tunnelling directory circuit.
    pub tunnelled_dir_server: bool,
    /// Subprotocol that this relay supports.
    pub proto: NetdocArguments<'a>,
}

impl<'a> Descriptor<'a> {
    /// Returns total length of descriptor (including trailing newline).
    #[allow(clippy::len_without_is_empty)]
    pub fn len(&self) -> usize {
        self.s.len()
    }

    /// Returns byte offset of item.
    #[inline(always)]
    pub fn byte_offset(&self) -> usize {
        self.byte_off
    }

    /// Returns the entire descriptor string.
    #[inline(always)]
    pub fn as_string(&self) -> &'a str {
        self.s
    }
}

/// Bandwidth data.
///
/// All bandwidth numbers is in bytes per second.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct Bandwidth {
    /// Maximum long-term bandwidth.
    pub average: u64,
    /// Maximum short-term bandwidth.
    pub burst: u64,
    /// Observed maximum bandwidth.
    pub observed: u64,
}

/// Extra info digests.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct ExtraInfoDigest {
    /// SHA1 digest.
    pub sha1: Sha1Output,
    /// (Optional) SHA256 digest.
    pub sha256: Option<Sha256Output>,
}

/// A single exit policy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExitPolicy {
    /// `true` if policy accepts if matches, reject if `false`.
    pub accept: bool,
    /// IP address that it filters.
    pub addr: Addr,
    /// Exit port that it matches.
    ///
    // If [`None`], it matches all ports.
    pub exit_port: Option<ExitPort>,
}

impl ExitPolicy {
    /// Parse exit policy string.
    ///
    /// # Parameters
    /// - `accept` : Werether this exit policy should accept or reject.
    /// - `s` : Exit policy string. [See format](https://spec.torproject.org/dir-spec/server-descriptor-format.html#item:accept).
    ///
    /// # Return
    ///
    /// Returns parsed exit policy or [`None`].
    pub fn parse(accept: bool, s: &str) -> Option<ExitPolicy> {
        let i = memrchr(b':', s.as_bytes())?;
        // SAFETY: Index is at : character.
        let (ip, r) = unsafe { (s.get_unchecked(..i), s.get_unchecked(i + 1..)) };
        let (ip, mask) = if let Some(i) = memchr(b'/', ip.as_bytes()) {
            // SAFETY: Index is at / character.
            unsafe { (ip.get_unchecked(..i), Some(ip.get_unchecked(i + 1..))) }
        } else {
            (ip, None)
        };

        let addr = if ip == "*" && mask.is_none() {
            Addr::Any
        } else if ip.starts_with("[") && ip.ends_with("]") {
            // SAFETY: ip is enclosed in []
            let ip = unsafe { ip.get_unchecked(1..ip.len() - 1) };
            Addr::Ipv6 {
                ip: ip.parse().ok()?,
                bits: match mask.map(|m| m.as_bytes()) {
                    None => 128,
                    Some([a @ b'0'..=b'9']) => a - b'0',
                    Some([a @ b'1'..=b'9', b @ b'0'..=b'9']) => (a - b'0') * 10 + (b - b'0'),
                    Some([b'1', b @ b'0'..=b'2', c @ b'0'..=b'9']) => {
                        match 100 + (b - b'0') * 10 + (c - b'0') {
                            v @ ..=128 => v,
                            _ => return None,
                        }
                    }
                    _ => return None,
                },
            }
        } else {
            Addr::Ipv4 {
                ip: ip.parse().ok()?,
                mask: match mask.map(|m| m.as_bytes()) {
                    None => Ipv4Addr::from_bits(0xffff_ffff),
                    Some([a @ b'0'..=b'9']) => bits_to_mask(a - b'0'),
                    Some([a @ b'1'..=b'3', b @ b'0'..=b'9']) => {
                        match (a - b'0') * 10 + (b - b'0') {
                            v @ ..=32 => bits_to_mask(v),
                            _ => return None,
                        }
                    }
                    // SAFETY: Mask is originally a string
                    Some(m) => unsafe { str::from_utf8_unchecked(m).parse::<Ipv4Addr>().ok()? },
                },
            }
        };

        let exit_port = match r {
            "*" => None,
            _ => Some(parse_exit_port(r).ok()?),
        };
        Some(ExitPolicy {
            accept,
            addr,
            exit_port,
        })
    }

    /// Match socket to exit policy.
    ///
    /// # Return
    ///
    /// Returns [`None`] if it does not match.
    /// Returns `Some(true)` if it's accepted.
    /// Returns `Some(false)` if it's rejected.
    ///
    /// # Example
    ///
    /// ```
    /// use std::net::SocketAddr;
    /// use onioncloud_lowlevel::parse::descriptor::ExitPolicy;
    ///
    /// fn process_exit_policy(policy: &[ExitPolicy], socket: &SocketAddr) -> bool {
    ///     policy
    ///         .iter() // Iterates through all exit policies
    ///         .filter_map(|p| p.match_socket(socket)) // Match each policy to socket
    ///         .next() // Find first policy that matches
    ///         .unwrap_or(false) // Default to reject
    /// }
    /// ```
    pub fn match_socket(&self, socket: &SocketAddr) -> Option<bool> {
        if self.addr.contains(&socket.ip())
            && self
                .exit_port
                .as_ref()
                .is_none_or(|p| p.contains(socket.port()))
        {
            Some(self.accept)
        } else {
            None
        }
    }
}

/// [`ExitPolicy`] IP address.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Addr {
    /// Any IP address matches.
    Any,
    /// IP v4 address with mask.
    Ipv4 { ip: Ipv4Addr, mask: Ipv4Addr },
    /// IP v6 address with prefix bits matches.
    ///
    /// **NOTE: Bits must be between 0 and 128. Any other value is immediate UB.**
    Ipv6 { ip: Ipv6Addr, bits: u8 },
}

impl Addr {
    /// Checks if IP address matches filter.
    ///
    /// # Example
    ///
    /// ```
    /// use std::net::IpAddr;
    /// use onioncloud_lowlevel::parse::descriptor::Addr;
    ///
    /// // Any address will match with anything
    /// assert!(Addr::Any.contains(&([0u8; 4]).into()));
    ///
    /// // Ipv4 address matching with subnet mask
    /// assert!(
    ///     Addr::Ipv4 {
    ///         ip: [192, 168, 0, 1u8].into(),
    ///         mask: [255, 255, 255, 0u8].into(),
    ///     }
    ///     .contains(&([192, 168, 0, 117u8].into()))
    /// );
    ///
    /// // Ipv6 address matching with prefix match
    /// assert!(
    ///     Addr::Ipv6 {
    ///         ip: [0xfc00, 0x0002, 0xdb78, 0x0009, 0x5b3a, 0x0007, 0x1ad4, 0u16].into(),
    ///         bits: 7,
    ///     }
    ///     .contains(&([0xfc00, 0x0008, 0xd536, 0x0005, 0xb1f1, 0x0009, 0x7174, 0u16].into()))
    /// );
    ///
    /// // Mixing ipv4 and ipv6 address
    /// assert!(
    ///     !Addr::Ipv4 {
    ///         ip: [192, 168, 0, 1u8].into(),
    ///         mask: [255, 255, 255, 0u8].into(),
    ///     }
    ///     .contains(&([0, 0, 0, 0, 0, 0xffff, 0xc0a8, 0x0001u16].into()))
    /// );
    /// ```
    pub fn contains(&self, ip: &IpAddr) -> bool {
        match (self, ip) {
            (Self::Any, _) => true,
            (Self::Ipv4 { ip, mask }, IpAddr::V4(v)) => {
                let mask = mask.to_bits();
                ip.to_bits() & mask == v.to_bits() & mask
            }
            // Special case to prevent shift overflow
            (Self::Ipv6 { bits: 0, .. }, IpAddr::V6(_)) => true,
            (Self::Ipv6 { ip, bits }, IpAddr::V6(v)) => {
                let s = 128 - bits;
                ip.to_bits() >> s == v.to_bits() >> s
            }
            _ => false,
        }
    }
}

fn bits_to_mask(b: u8) -> Ipv4Addr {
    debug_assert!(b <= 32);
    Ipv4Addr::from_bits(if b == 0 { 0 } else { 0xffff_ffff << (32 - b) })
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::cmp::PartialEq;
    use std::fmt::Write as _;
    use std::time::Duration;

    use proptest::option::of;
    use proptest::prelude::*;
    use proptest::strategy::LazyJust;
    use rsa::pkcs1::DecodeRsaPublicKey;

    use crate::parse::strat_exit_port;

    #[derive(Debug)]
    enum IpAddrRef {
        Any,
        Ipv4 { ip: Ipv4Addr, mask: Option<Maskv4> },
        Ipv6 { ip: Ipv6Addr, bits: Option<u8> },
    }

    #[derive(Debug)]
    enum Maskv4 {
        Bits(u8),
        Mask(Ipv4Addr),
    }

    impl PartialEq<Addr> for IpAddrRef {
        fn eq(&self, other: &Addr) -> bool {
            match (self, other) {
                (Self::Any, Addr::Any) => true,
                (Self::Ipv4 { ip: ia, mask: ma }, Addr::Ipv4 { ip: ib, mask: mb }) => {
                    *ia == *ib
                        && match ma {
                            None => *mb == Ipv4Addr::from_bits(0xffff_ffff),
                            Some(Maskv4::Bits(b)) => *mb == bits_to_mask(*b),
                            Some(Maskv4::Mask(m)) => *mb == *m,
                        }
                }
                (Self::Ipv6 { ip: ia, bits: ba }, Addr::Ipv6 { ip: ib, bits: bb }) => {
                    *ia == *ib && (*ba).unwrap_or(128) == *bb
                }
                _ => false,
            }
        }
    }

    fn strat_addr_ref() -> impl Strategy<Value = IpAddrRef> {
        let maskv4 = prop_oneof![
            (0..=32u8).prop_map(Maskv4::Bits),
            any::<Ipv4Addr>().prop_map(Maskv4::Mask),
        ];

        prop_oneof![
            LazyJust::new(|| IpAddrRef::Any),
            (any::<Ipv4Addr>(), of(maskv4)).prop_map(|(ip, mask)| IpAddrRef::Ipv4 { ip, mask }),
            (any::<Ipv6Addr>(), of(0..=128u8)).prop_map(|(ip, bits)| IpAddrRef::Ipv6 { ip, bits }),
        ]
    }

    #[test]
    fn test_descriptor_example() {
        let s = r"router Tochar 113.20.28.243 9001 0 0
identity-ed25519
-----BEGIN ED25519 CERT-----
AQQAB4EOAR67ew8uQtD4vc7tF+z+7JLaWMy2PKMobTB05xfJJwlLAQAgBADby+D5
KoSeaI1r2GZiddlMFyJCNXU5IQrIzqzldgq2nXMeSBRXLBFy0Z+/JEWxCnUIrSX2
ZO5S3CZdTCxU+CB3zZ1nGLfJxAEqHBDl9hhZmXvB4sdt/E8EPQin+R3tNQg=
-----END ED25519 CERT-----
master-key-ed25519 28vg+SqEnmiNa9hmYnXZTBciQjV1OSEKyM6s5XYKtp0
platform Tor 0.4.8.21 on Linux
proto Conflux=1 Cons=1-2 Desc=1-2 DirCache=2 FlowCtrl=1-2 HSDir=2 HSIntro=4-5 HSRend=1-2 Link=1-5 LinkAuth=1,3 Microdesc=1-2 Padding=2 Relay=1-4
published 2026-01-24 14:35:17
fingerprint 0F3D 8493 DD75 CB13 E535 9A46 2805 6248 4580 BA73
uptime 2307611
bandwidth 1073741824 1073741824 1042931
extra-info-digest E55427F2C9748408DAE2CEA846BEFB52123C7EEA iS1LGFUT5dc5S98wqJtIdEtO/fthYkIKZ9nO3biYz98
onion-key
-----BEGIN RSA PUBLIC KEY-----
MIGJAoGBAKQcHTteDAa+3Q8i/G6YoGg8zBL1W+7S80itljYbwXDJGEkiHd2iL5yV
Q999GaYalHJnDIcs6uBkYsTsptIFcd+kCErh32ZUAb2KUWY6673ojspTvNlGsrtm
BsJ2aWqWNWgd+DsPH4yAv3O8VfA0CVGANDmrKLsEW9Z9WDpcxwPXAgMBAAE=
-----END RSA PUBLIC KEY-----
signing-key
-----BEGIN RSA PUBLIC KEY-----
MIGJAoGBAMDJc1I9JY2CddkOQ7p1fo/r+4eghk1xFREuQtTE/WLbmJchkF99DUVD
vL6PXMlvp0eJyh2vGMNrBY1kvNrhqRzKiF/wbd3xz5/eDVI4f3zIuGm/jtiVbZP+
THJuycSghEH4TFsDStQMsH4IcGAUUvByi9lh7YwqM7HMzHMiG9bRAgMBAAE=
-----END RSA PUBLIC KEY-----
onion-key-crosscert
-----BEGIN CROSSCERT-----
mPIiNb4tisWuqugFjYqYAe9wvKMADhgR+59OUr8XeLewuYdv6re6veG31GhHxS8s
j4SG9Iu0Ed6qlotrQpQ7Wsr5G+7YFBg+eVA3mLPflncuTgPN1Pm50c6kXKzHbkO4
ZywIY1wyFf47tdcsznxnArOqyvZ6ePcmFn6uGVfNPac=
-----END CROSSCERT-----
ntor-onion-key-crosscert 1
-----BEGIN ED25519 CERT-----
AQoAB4JnAdvL4PkqhJ5ojWvYZmJ12UwXIkI1dTkhCsjOrOV2CradAESNXdPeQDEm
EmlEGcNi0h8ngWPD0q96AqMKNaEKSXmUaMZqObAHcxC47fgxNXCxoJ78dhndKc8P
6b+E/c8RNgg=
-----END ED25519 CERT-----
hidden-service-dir
ntor-onion-key gKrGzUXdFOuU5zXxpANsVAOwkF+WzmGZ2+VPYsrJ5AM
reject *:*
tunnelled-dir-server
router-sig-ed25519 T7QLZ2Hs3s9gQgk+T48IKuvlgwoW71aD7/7J5AuWn3hZyavQgH+5G5SG7xNd4cIfbwAsM5ettTNkd4pku3DeDQ
router-signature
-----BEGIN SIGNATURE-----
dxWusV2eKT6Gd2shfDQSD5csMH95Nz6TpeQTTjhMX0QyrfsrLzZ2wFLY/fSFga8X
gw+EwoJxXbV7Suv7/07sAOoI3uo22f7YoOl2YUWEsmCQYjCVS3BNdcvbvkg/QnZz
fx8lPGcchMA7BdeI6q8jEx8W2Q+7ydRqTnMaFsT2kAw=
-----END SIGNATURE-----
";
        let signing_key = RsaPublicKey::from_pkcs1_pem(
            r"-----BEGIN RSA PUBLIC KEY-----
MIGJAoGBAMDJc1I9JY2CddkOQ7p1fo/r+4eghk1xFREuQtTE/WLbmJchkF99DUVD
vL6PXMlvp0eJyh2vGMNrBY1kvNrhqRzKiF/wbd3xz5/eDVI4f3zIuGm/jtiVbZP+
THJuycSghEH4TFsDStQMsH4IcGAUUvByi9lh7YwqM7HMzHMiG9bRAgMBAAE=
-----END RSA PUBLIC KEY-----",
        )
        .unwrap();
        let onion_key = RsaPublicKey::from_pkcs1_pem(
            r"-----BEGIN RSA PUBLIC KEY-----
MIGJAoGBAKQcHTteDAa+3Q8i/G6YoGg8zBL1W+7S80itljYbwXDJGEkiHd2iL5yV
Q999GaYalHJnDIcs6uBkYsTsptIFcd+kCErh32ZUAb2KUWY6673ojspTvNlGsrtm
BsJ2aWqWNWgd+DsPH4yAv3O8VfA0CVGANDmrKLsEW9Z9WDpcxwPXAgMBAAE=
-----END RSA PUBLIC KEY-----",
        )
        .unwrap();

        let mut parser = DescriptorParser::new(s);
        let desc = parser.next().unwrap().unwrap();

        assert_eq!(desc.nickname, "Tochar");
        assert_eq!(desc.address, Ipv4Addr::new(113, 20, 28, 243));
        assert_eq!(desc.orport, 9001);
        assert_eq!(desc.dirport, 0);
        assert_eq!(
            desc.ed_id_pk.as_bytes(),
            &[
                0xdb, 0xcb, 0xe0, 0xf9, 0x2a, 0x84, 0x9e, 0x68, 0x8d, 0x6b, 0xd8, 0x66, 0x62, 0x75,
                0xd9, 0x4c, 0x17, 0x22, 0x42, 0x35, 0x75, 0x39, 0x21, 0x0a, 0xc8, 0xce, 0xac, 0xe5,
                0x76, 0x0a, 0xb6, 0x9d,
            ]
        );
        assert_eq!(
            desc.ed_sign_pk.as_bytes(),
            &[
                0x1e, 0xbb, 0x7b, 0x0f, 0x2e, 0x42, 0xd0, 0xf8, 0xbd, 0xce, 0xed, 0x17, 0xec, 0xfe,
                0xec, 0x92, 0xda, 0x58, 0xcc, 0xb6, 0x3c, 0xa3, 0x28, 0x6d, 0x30, 0x74, 0xe7, 0x17,
                0xc9, 0x27, 0x09, 0x4b,
            ]
        );
        assert_eq!(desc.bandwidth.average, 1073741824);
        assert_eq!(desc.bandwidth.burst, 1073741824);
        assert_eq!(desc.bandwidth.observed, 1042931);
        assert_eq!(desc.platform, Some("Tor 0.4.8.21 on Linux"));
        assert_eq!(
            desc.published,
            SystemTime::UNIX_EPOCH + Duration::from_secs(1769265317)
        );
        assert_eq!(
            desc.fingerprint,
            [
                0x0f, 0x3d, 0x84, 0x93, 0xdd, 0x75, 0xcb, 0x13, 0xe5, 0x35, 0x9a, 0x46, 0x28, 0x05,
                0x62, 0x48, 0x45, 0x80, 0xba, 0x73,
            ]
        );
        assert_eq!(desc.hibernating, false);
        assert_eq!(desc.uptime, Some(2307611));
        assert_eq!(desc.onion_key.as_ref(), Some(&onion_key));
        assert_eq!(
            desc.ntor_onion_key,
            [
                0x80, 0xaa, 0xc6, 0xcd, 0x45, 0xdd, 0x14, 0xeb, 0x94, 0xe7, 0x35, 0xf1, 0xa4, 0x03,
                0x6c, 0x54, 0x03, 0xb0, 0x90, 0x5f, 0x96, 0xce, 0x61, 0x99, 0xdb, 0xe5, 0x4f, 0x62,
                0xca, 0xc9, 0xe4, 0x03,
            ]
        );
        assert_eq!(desc.signing_key, signing_key);
        assert_eq!(
            desc.exit_policy,
            [ExitPolicy {
                accept: false,
                addr: Addr::Any,
                exit_port: None
            }]
        );
        assert_eq!(desc.ipv6_policy, None);
        assert_eq!(desc.bridge_distribution_request, None);
        assert!(desc.family.is_none());
        assert_eq!(desc.family_cert.len(), 0);
        assert_eq!(desc.eventdns, true);
        assert_eq!(desc.caches_extra_info, false);
        assert_eq!(
            desc.extra_info_digest.as_ref().map(|v| &v.sha1),
            Some(&[
                0xe5, 0x54, 0x27, 0xf2, 0xc9, 0x74, 0x84, 0x08, 0xda, 0xe2, 0xce, 0xa8, 0x46, 0xbe,
                0xfb, 0x52, 0x12, 0x3c, 0x7e, 0xea,
            ])
        );
        assert_eq!(
            desc.extra_info_digest
                .as_ref()
                .and_then(|v| v.sha256.as_ref()),
            Some(&[
                0x89, 0x2d, 0x4b, 0x18, 0x55, 0x13, 0xe5, 0xd7, 0x39, 0x4b, 0xdf, 0x30, 0xa8, 0x9b,
                0x48, 0x74, 0x4b, 0x4e, 0xfd, 0xfb, 0x61, 0x62, 0x42, 0x0a, 0x67, 0xd9, 0xce, 0xdd,
                0xb8, 0x98, 0xcf, 0xdf,
            ])
        );
        assert_eq!(desc.hidden_service_dir, true);
        assert_eq!(desc.allow_single_hop_exits, false);
        assert_eq!(desc.or_address, None);
        assert_eq!(desc.tunnelled_dir_server, true);

        if let Some(desc) = parser.next() {
            panic!("expected parser to end, got {desc:?}");
        }
    }

    proptest! {
        #[test]
        fn test_parse_addr(ip in strat_addr_ref(), port in of(strat_exit_port())) {
            let mut s = match &ip {
                IpAddrRef::Any => format!("*"),
                IpAddrRef::Ipv4 { ip, mask: None } => format!("{ip}"),
                IpAddrRef::Ipv4 { ip, mask: Some(Maskv4::Bits(bits)) } => format!("{ip}/{bits}"),
                IpAddrRef::Ipv4 { ip, mask: Some(Maskv4::Mask(mask)) } => format!("{ip}/{mask}"),
                IpAddrRef::Ipv6 { ip, bits: None } => format!("[{ip}]"),
                IpAddrRef::Ipv6 { ip, bits: Some(bits) } => format!("[{ip}]/{bits}"),
            };
            match port {
                Some(p) => write!(s, ":{p}"),
                None => write!(s, ":*"),
            }.unwrap();

            let ExitPolicy { addr, exit_port, .. } = match ExitPolicy::parse(true, &s) {
                Some(v) => v,
                None => panic!("parsing {s:?} failed"),
            };
            assert_eq!(ip, addr);
            assert_eq!(port, exit_port);
        }

        #[test]
        fn test_addr_contains(addr in strat_addr_ref(), ip: IpAddr) {
            let is_match = match (&addr, &ip) {
                (IpAddrRef::Any, _) => true,
                (IpAddrRef::Ipv4 { ip, mask: None }, IpAddr::V4(t)) => *ip == *t,
                (IpAddrRef::Ipv4 { mask: Some(Maskv4::Bits(0)), .. }, IpAddr::V4(_)) => true,
                (IpAddrRef::Ipv4 { ip, mask: Some(Maskv4::Bits(bits)) }, IpAddr::V4(t)) => {
                    let s = 32 - bits;
                    ip.to_bits() >> s == t.to_bits() >> s
                }
                (IpAddrRef::Ipv4 { ip, mask: Some(Maskv4::Mask(mask)) }, IpAddr::V4(t)) => {
                    let m = mask.to_bits();
                    ip.to_bits() & m == t.to_bits() & m
                }
                (IpAddrRef::Ipv6 { ip, bits: None }, IpAddr::V6(t)) => *ip == *t,
                (IpAddrRef::Ipv6 { bits: Some(0), .. }, IpAddr::V6(_)) => true,
                (IpAddrRef::Ipv6 { ip, bits: Some(bits) }, IpAddr::V6(t)) => {
                    let s = 128 - bits;
                    ip.to_bits() >> s == t.to_bits() >> s
                }
                _ => false,
            };
            let addr = match addr {
                IpAddrRef::Any => Addr::Any,
                IpAddrRef::Ipv4 { ip, mask } => Addr::Ipv4 {
                    ip,
                    mask: match mask {
                        None => Ipv4Addr::from_bits(0xffff_ffff),
                        Some(Maskv4::Bits(bits)) => bits_to_mask(bits),
                        Some(Maskv4::Mask(mask)) => mask,
                    },
                },
                IpAddrRef::Ipv6 { ip, bits } => Addr::Ipv6 {
                    ip,
                    bits: bits.unwrap_or(128),
                },
            };

            assert_eq!(addr.contains(&ip), is_match);
        }
    }
}
