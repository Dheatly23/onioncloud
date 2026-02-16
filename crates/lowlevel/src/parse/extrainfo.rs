//! Extra info parser.
//!
//! Parses and validate extra info.
//!
//! See also:
//! - [Spec](https://spec.torproject.org/dir-spec/extra-info-document-format.html).

use std::iter::FusedIterator;
use std::str::FromStr;
use std::time::SystemTime;

use digest::Digest;
use ed25519_dalek::VerifyingKey;
use rsa::RsaPublicKey;
use rsa::pkcs1v15::Pkcs1v15Sign;
use sha1::Sha1;
use sha2::Sha256;
use subtle::ConstantTimeEq;

use super::misc::{CommaIter, args_date_time, decode_b64, parse_b64u};
use super::netdoc::check::{proto_keyword, pt_keyword};
use super::netdoc::{Item as NetdocItem, NetdocParser};
use crate::crypto::cert::UnverifiedEdCert;
use crate::crypto::relay::RelayId;
use crate::crypto::{EdPublicKey, EdSignature, Sha1Output};
use crate::errors::{CertFormatError, CertVerifyError, ExtraInfoError};
use crate::util::parse::parse_hex;

/// Parser for (concatenated) extra info.
pub struct Parser<'a> {
    inner: NetdocParser<'a>,
}

impl<'a> Parser<'a> {
    /// Create a new [`Parser`].
    pub const fn new(s: &'a str) -> Self {
        Self {
            inner: NetdocParser::new(s),
        }
    }

    /// Gets the original string.
    ///
    /// ```
    /// use onioncloud_lowlevel::parse::extrainfo::Parser;
    ///
    /// // Doesn't have to be a valid certificate.
    /// let s = "abc";
    /// let parser = Parser::new(s);
    ///
    /// assert_eq!(parser.original_string(), s);
    /// ```
    pub const fn original_string(&self) -> &'a str {
        self.inner.original_string()
    }

    #[inline(always)]
    fn parse(&mut self, item: NetdocItem<'a>) -> Result<ExtraInfo<'a>, ExtraInfoError> {
        // Starting item
        if item.keyword() != "extra-info" || item.has_object() {
            return Err(CertFormatError.into());
        }
        let start_off = item.byte_offset();

        let nickname;
        let fingerprint: RelayId;

        {
            let mut args = item.arguments().iter();
            nickname = args.next().ok_or(CertFormatError)?;
            fingerprint = args.next().and_then(parse_hex).ok_or(CertFormatError)?;
        }

        let mut tmp = [0; 2048];

        let mut id_ed = None;
        let mut published = None;
        let mut read_history = None;
        let mut write_history = None;
        let mut ipv6_read_history = None;
        let mut ipv6_write_history = None;
        let mut geoip_db_digest = None::<Sha1Output>;
        let mut geoip6_db_digest = None::<Sha1Output>;
        let mut bridge_stats_end = None;
        let mut bridge_ips = None;
        let mut bridge_ip_versions = None;
        let mut bridge_ip_transports = None;
        let mut dirreq_stats_end = None;
        let mut dirreq_v3_ips = None;
        let mut dirreq_v3_reqs = None;
        //let mut dirreq_v3_share = None;
        let mut dirreq_v3_resp = None;
        let mut dirreq_v3_direct_dl = None;
        let mut dirreq_v3_tunneled_dl = None;
        let mut dirreq_read_history = None;
        let mut dirreq_write_history = None;
        let mut entry_stats_end = None;
        let mut entry_ips = None;

        let item = loop {
            let item = self.inner.next().ok_or(CertFormatError)??;

            match item.keyword() {
                // identity-ed25519 is exactly once and without extra args
                "identity-ed25519" => {
                    if id_ed.is_some() || !item.arguments().is_empty() {
                        return Err(CertFormatError.into());
                    }
                    let Some(("ED25519 CERT", cert_cont)) = item.object() else {
                        return Err(CertFormatError.into());
                    };

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

                    let ed_id_pk = VerifyingKey::from_bytes(&id_pk.ok_or(CertVerifyError)?)
                        .map_err(|_| CertVerifyError)?;
                    let ed_sign_pk =
                        VerifyingKey::from_bytes(&cert.header.key).map_err(|_| CertVerifyError)?;
                    cert.verify2(&ed_id_pk)?;

                    id_ed = Some((ed_id_pk, ed_sign_pk));
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
                // read-history is at most once
                "read-history" => {
                    if read_history.is_some() {
                        return Err(CertFormatError.into());
                    }
                    read_history = Some(History::try_from(item)?);
                }
                // write-history is at most once
                "write-history" => {
                    if write_history.is_some() {
                        return Err(CertFormatError.into());
                    }
                    write_history = Some(History::try_from(item)?);
                }
                // ipv6-read-history is at most once
                "ipv6-read-history" => {
                    if ipv6_read_history.is_some() {
                        return Err(CertFormatError.into());
                    }
                    ipv6_read_history = Some(History::try_from(item)?);
                }
                // ipv6-write-history is at most once
                "ipv6-write-history" => {
                    if ipv6_write_history.is_some() {
                        return Err(CertFormatError.into());
                    }
                    ipv6_write_history = Some(History::try_from(item)?);
                }
                // geoip-db-digest is at most once
                "geoip-db-digest" => {
                    if geoip_db_digest.is_some() {
                        return Err(CertFormatError.into());
                    }
                    geoip_db_digest = Some(
                        item.arguments()
                            .iter()
                            .next()
                            .and_then(parse_hex)
                            .ok_or(CertFormatError)?,
                    );
                }
                // geoip6-db-digest is at most once
                "geoip6-db-digest" => {
                    if geoip6_db_digest.is_some() {
                        return Err(CertFormatError.into());
                    }
                    geoip6_db_digest = Some(
                        item.arguments()
                            .iter()
                            .next()
                            .and_then(parse_hex)
                            .ok_or(CertFormatError)?,
                    );
                }
                // bridge-stats-end is at most once
                "bridge-stats-end" => {
                    if bridge_stats_end.is_some() {
                        return Err(CertFormatError.into());
                    }
                    bridge_stats_end = Some(StatsEnd::try_from(item)?);
                }
                // bridge-ips is at most once
                "bridge-ips" => {
                    if bridge_ips.is_some() {
                        return Err(CertFormatError.into());
                    }
                    bridge_ips = Some(CCMappingData(
                        item.arguments().iter().next().ok_or(CertFormatError)?,
                    ));
                }
                // bridge-ip-versions is at most once
                "bridge-ip-versions" => {
                    if bridge_ip_versions.is_some() {
                        return Err(CertFormatError.into());
                    }

                    let s = item.arguments().iter().next().ok_or(CertFormatError)?;
                    let mut ipv4 = None;
                    let mut ipv6 = None;
                    for s in CommaIter::from(s) {
                        match s.as_bytes() {
                            // SAFETY: Rest is a utf-8 string
                            [b'4', b'=', r @ ..] if ipv4.is_none() => {
                                ipv4 = unsafe {
                                    Some(
                                        str::from_utf8_unchecked(r)
                                            .parse()
                                            .map_err(|_| CertFormatError)?,
                                    )
                                }
                            }
                            // SAFETY: Rest is a utf-8 string
                            [b'6', b'=', r @ ..] if ipv6.is_none() => {
                                ipv6 = unsafe {
                                    Some(
                                        str::from_utf8_unchecked(r)
                                            .parse()
                                            .map_err(|_| CertFormatError)?,
                                    )
                                }
                            }
                            _ => return Err(CertFormatError.into()),
                        }
                    }
                    bridge_ip_versions = Some(BridgeIpVersionsData {
                        ipv4: ipv4.unwrap_or(0),
                        ipv6: ipv6.unwrap_or(0),
                    });
                }
                // bridge-ip-transports is at most once
                "bridge-ip-transports" => {
                    if bridge_ip_transports.is_some() {
                        return Err(CertFormatError.into());
                    }
                    bridge_ip_transports = Some(if let Some(s) = item.arguments().iter().next() {
                        let mut v = Vec::<BridgeIpTransport<'_>>::new();
                        for s in CommaIter::from(s) {
                            let t = BridgeIpTransport::try_from(s)?;
                            if let Some(p) = v.last()
                                && p.pt >= t.pt
                            {
                                return Err(CertFormatError.into());
                            } else if v.len() >= 32 {
                                // Limits length to 32
                                return Err(CertFormatError.into());
                            }
                            v.push(t);
                        }
                        v
                    } else {
                        Vec::new()
                    });
                }
                // dirreq-stats-end is at most once
                "dirreq-stats-end" => {
                    if dirreq_stats_end.is_some() {
                        return Err(CertFormatError.into());
                    }
                    dirreq_stats_end = Some(StatsEnd::try_from(item)?);
                }
                // dirreq-v3-ips is at most once
                "dirreq-v3-ips" => {
                    if dirreq_v3_ips.is_some() {
                        return Err(CertFormatError.into());
                    }
                    dirreq_v3_ips = Some(CCMappingData(
                        item.arguments().iter().next().ok_or(CertFormatError)?,
                    ));
                }
                // dirreq-v3-reqs is at most once
                "dirreq-v3-reqs" => {
                    if dirreq_v3_reqs.is_some() {
                        return Err(CertFormatError.into());
                    }
                    dirreq_v3_reqs = Some(CCMappingData(
                        item.arguments().iter().next().ok_or(CertFormatError)?,
                    ));
                }
                // dirreq-v3-resp is at most once
                "dirreq-v3-resp" => {
                    if dirreq_v3_resp.is_some() {
                        return Err(CertFormatError.into());
                    }
                    dirreq_v3_resp = Some(DirreqRespData::new(
                        item.arguments().iter().next().ok_or(CertFormatError)?,
                    )?);
                }
                // dirreq-v3-direct-dl is at most once
                "dirreq-v3-direct-dl" => {
                    if dirreq_v3_direct_dl.is_some() {
                        return Err(CertFormatError.into());
                    }
                    dirreq_v3_direct_dl = Some(DirreqDlData::new(
                        item.arguments().iter().next().ok_or(CertFormatError)?,
                    )?);
                }
                // dirreq-v3-tunneled-dl is at most once
                "dirreq-v3-tunneled-dl" => {
                    if dirreq_v3_tunneled_dl.is_some() {
                        return Err(CertFormatError.into());
                    }
                    dirreq_v3_tunneled_dl = Some(DirreqDlData::new(
                        item.arguments().iter().next().ok_or(CertFormatError)?,
                    )?);
                }
                // dirreq-read-history is at most once
                "dirreq-read-history" => {
                    if dirreq_read_history.is_some() {
                        return Err(CertFormatError.into());
                    }
                    dirreq_read_history = Some(History::try_from(item)?);
                }
                // dirreq-write-history is at most once
                "dirreq-write-history" => {
                    if dirreq_write_history.is_some() {
                        return Err(CertFormatError.into());
                    }
                    dirreq_write_history = Some(History::try_from(item)?);
                }
                // entry-stats-end is at most once
                "entry-stats-end" => {
                    if entry_stats_end.is_some() {
                        return Err(CertFormatError.into());
                    }
                    entry_stats_end = Some(StatsEnd::try_from(item)?);
                }
                // entry-ips is at most once
                "entry-ips" => {
                    if entry_ips.is_some() {
                        return Err(CertFormatError.into());
                    }
                    entry_ips = Some(CCMappingData(
                        item.arguments().iter().next().ok_or(CertFormatError)?,
                    ));
                }
                // router-sig-ed25519 is at exactly once at the end
                "router-sig-ed25519" => break item,
                // Unknown keyword, skip
                _ => (),
            }
        };

        let (Some((ed_id_pk, ed_sign_pk)), Some(published)) = (id_ed, published) else {
            return Err(CertFormatError.into());
        };

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

        let Some(("SIGNATURE", rsa_sig)) = item.object() else {
            return Err(CertFormatError.into());
        };
        let doc_hash = Sha1::digest(
            &self.original_string().as_bytes()[start_off..item.byte_offset() + item.line_len() + 1],
        );

        Ok(ExtraInfo {
            // SAFETY: Indices are valid.
            s: unsafe {
                self.original_string()
                    .get_unchecked(start_off..item.byte_offset() + item.len() + 1)
            },
            byte_off: start_off,

            nickname,
            fingerprint,
            ed_id_pk,
            ed_sign_pk,
            published,
            read_history,
            write_history,
            ipv6_read_history,
            ipv6_write_history,
            geoip_db_digest,
            geoip6_db_digest,
            bridge_stats_end,
            bridge_ips,
            bridge_ip_versions,
            bridge_ip_transports,
            dirreq_stats_end,
            dirreq_v3_ips,
            dirreq_v3_reqs,
            dirreq_v3_resp,
            dirreq_v3_direct_dl,
            dirreq_v3_tunneled_dl,
            dirreq_read_history,
            dirreq_write_history,
            entry_stats_end,
            entry_ips,

            rsa_sig,
            doc_hash: doc_hash.into(),
        })
    }
}

impl<'a> Iterator for Parser<'a> {
    type Item = Result<ExtraInfo<'a>, ExtraInfoError>;

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

impl FusedIterator for Parser<'_> {}

#[derive(Debug, Clone)]
pub struct ExtraInfo<'a> {
    /// Original document.
    s: &'a str,
    /// Byte offset.
    byte_off: usize,

    /// Relay nickname.
    pub nickname: &'a str,
    /// Relay fingerprint.
    pub fingerprint: RelayId,
    /// Ed25519 identity key.
    pub ed_id_pk: VerifyingKey,
    /// Ed25519 signing key.
    pub ed_sign_pk: VerifyingKey,
    /// Descriptor publish date.
    pub published: SystemTime,
    /// Read history.
    pub read_history: Option<History<'a>>,
    /// Write history.
    pub write_history: Option<History<'a>>,
    /// Ipv6 read history.
    pub ipv6_read_history: Option<History<'a>>,
    /// Ipv6 write history.
    pub ipv6_write_history: Option<History<'a>>,
    /// Geoip DB digest.
    pub geoip_db_digest: Option<Sha1Output>,
    /// Geoip DB digest (ipv6).
    pub geoip6_db_digest: Option<Sha1Output>,
    /// Bridge stats data.
    pub bridge_stats_end: Option<StatsEnd>,
    /// Bridge IPs data per country.
    pub bridge_ips: Option<CCMappingData<'a>>,
    /// Bridge IP versions data.
    pub bridge_ip_versions: Option<BridgeIpVersionsData>,
    /// Bridge IP transport data.
    pub bridge_ip_transports: Option<Vec<BridgeIpTransport<'a>>>,
    /// Directory stats data.
    pub dirreq_stats_end: Option<StatsEnd>,
    /// Directory data unique IP counts.
    pub dirreq_v3_ips: Option<CCMappingData<'a>>,
    /// Directory data number of requests.
    pub dirreq_v3_reqs: Option<CCMappingData<'a>>,
    /// Directory data response code.
    pub dirreq_v3_resp: Option<DirreqRespData>,
    /// Directory data direct connection statistics.
    pub dirreq_v3_direct_dl: Option<DirreqDlData>,
    /// Directory data tunneled connection statistics.
    pub dirreq_v3_tunneled_dl: Option<DirreqDlData>,
    /// Dirreq read history.
    pub dirreq_read_history: Option<History<'a>>,
    /// Dirreq write history.
    pub dirreq_write_history: Option<History<'a>>,
    /// Entry stats data.
    pub entry_stats_end: Option<StatsEnd>,
    /// Unique IP count that is connected to this relay.
    pub entry_ips: Option<CCMappingData<'a>>,

    /// Unverified RSA signature.
    ///
    /// It is PEM format, without header nor footer.
    pub rsa_sig: &'a str,
    /// SHA1 document hash.
    ///
    /// To be verified along with `rsa_sig`.
    pub doc_hash: Sha1Output,
}

impl<'a> ExtraInfo<'a> {
    /// Returns total length of document (including trailing newline).
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

    /// Verifies fingerprint.
    pub fn fingerprint_verify(&self, fp: &RelayId) -> Result<&Self, ExtraInfoError> {
        match bool::from(self.fingerprint.ct_eq(fp)) {
            true => Ok(self),
            false => Err(CertVerifyError.into()),
        }
    }

    /// Verifies RSA signature.
    pub fn rsa_verify(&self, pk: &RsaPublicKey) -> Result<&Self, ExtraInfoError> {
        match pk.verify(
            Pkcs1v15Sign::new_unprefixed(),
            &self.doc_hash,
            decode_b64(&mut [0; 2048], self.rsa_sig)?,
        ) {
            Ok(_) => Ok(self),
            Err(_) => Err(CertVerifyError.into()),
        }
    }
}

#[derive(Debug, Clone)]
pub struct History<'a> {
    /// Most recent interval timestamp.
    pub time: SystemTime,
    /// Interval (in seconds) between measurement.
    pub interval: u32,
    /// History string.
    s: &'a str,
}

/// Parses [`NetdocItem`] into [`History`].
impl<'a> TryFrom<NetdocItem<'a>> for History<'a> {
    type Error = CertFormatError;

    fn try_from(item: NetdocItem<'a>) -> Result<Self, Self::Error> {
        let mut args = item.arguments().iter();
        let time = SystemTime::from(args_date_time(&mut args).ok_or(CertFormatError)?);
        let interval = args
            .next()
            .and_then(|s| s.strip_prefix("("))
            .ok_or(CertFormatError)?
            .parse::<u32>()
            .map_err(|_| CertFormatError)?;
        let Some("s)") = args.next() else {
            return Err(CertFormatError);
        };
        let s = args.next().ok_or(CertFormatError)?;
        Ok(Self { time, interval, s })
    }
}

impl<'a> IntoIterator for History<'a> {
    type IntoIter = HistoryIter<'a>;
    type Item = <Self::IntoIter as Iterator>::Item;

    fn into_iter(self) -> Self::IntoIter {
        self.iter()
    }
}

impl<'a> IntoIterator for &History<'a> {
    type IntoIter = HistoryIter<'a>;
    type Item = <Self::IntoIter as Iterator>::Item;

    fn into_iter(self) -> Self::IntoIter {
        self.iter()
    }
}

impl<'a> History<'a> {
    /// Gets raw, unparsed history string.
    pub fn raw_string(&self) -> &'a str {
        self.s
    }

    /// Iterates through history data.
    pub fn iter(&self) -> HistoryIter<'a> {
        HistoryIter(self.s.into())
    }
}

#[derive(Debug, Clone)]
pub struct HistoryIter<'a>(CommaIter<'a>);

impl<'a> Iterator for HistoryIter<'a> {
    type Item = Result<u64, <u64 as FromStr>::Err>;

    fn next(&mut self) -> Option<Self::Item> {
        let r = self.0.next()?.parse();
        if r.is_err() {
            self.0.terminate();
        }
        Some(r)
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        self.0.size_hint()
    }
}

impl DoubleEndedIterator for HistoryIter<'_> {
    fn next_back(&mut self) -> Option<Self::Item> {
        let r = self.0.next_back()?.parse();
        if r.is_err() {
            self.0.terminate();
        }
        Some(r)
    }
}

impl FusedIterator for HistoryIter<'_> {}

/// `*-stats-end` data.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct StatsEnd {
    /// Most recent interval timestamp.
    pub time: SystemTime,
    /// Interval (in seconds) between measurement.
    pub interval: u32,
}

impl<'a> TryFrom<NetdocItem<'a>> for StatsEnd {
    type Error = CertFormatError;

    fn try_from(item: NetdocItem<'a>) -> Result<Self, Self::Error> {
        let mut args = item.arguments().iter();
        let time = SystemTime::from(args_date_time(&mut args).ok_or(CertFormatError)?);
        let interval = args
            .next()
            .and_then(|s| s.strip_prefix("("))
            .ok_or(CertFormatError)?
            .parse::<u32>()
            .map_err(|_| CertFormatError)?;
        let Some("s)") = args.next() else {
            return Err(CertFormatError);
        };
        Ok(Self { time, interval })
    }
}

/// `*-ips` data.
#[derive(Debug, Clone)]
pub struct CCMappingData<'a>(&'a str);

impl<'a> IntoIterator for CCMappingData<'a> {
    type IntoIter = CCMappingIter<'a>;
    type Item = <Self::IntoIter as Iterator>::Item;

    fn into_iter(self) -> Self::IntoIter {
        self.iter()
    }
}

impl<'a> IntoIterator for &CCMappingData<'a> {
    type IntoIter = CCMappingIter<'a>;
    type Item = <Self::IntoIter as Iterator>::Item;

    fn into_iter(self) -> Self::IntoIter {
        self.iter()
    }
}

impl<'a> CCMappingData<'a> {
    /// Gets raw, unparsed string.
    pub fn raw_string(&self) -> &'a str {
        self.0
    }

    /// Iterates through data.
    pub fn iter(&self) -> CCMappingIter<'a> {
        CCMappingIter(self.0.into())
    }
}

#[derive(Debug, Clone)]
pub struct CCMappingIter<'a>(CommaIter<'a>);

#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct CCMapping<'a> {
    /// Country code.
    pub cc: &'a str,
    /// Number of users that connected from that country.
    pub num: u32,
}

impl<'a> TryFrom<&'a str> for CCMapping<'a> {
    type Error = CertFormatError;

    fn try_from(s: &'a str) -> Result<Self, Self::Error> {
        let [
            b'a'..=b'z' | b'A'..=b'Z',
            b'a'..=b'z' | b'A'..=b'Z',
            b'=',
            ..,
        ] = s.as_bytes()
        else {
            return Err(CertFormatError);
        };
        // SAFETY: Prefix has been checked
        let (cc, b) = unsafe { (s.get_unchecked(..2), s.get_unchecked(3..)) };
        Ok(Self {
            cc,
            num: b.parse().map_err(|_| CertFormatError)?,
        })
    }
}

impl<'a> Iterator for CCMappingIter<'a> {
    type Item = Result<CCMapping<'a>, CertFormatError>;

    fn next(&mut self) -> Option<Self::Item> {
        let r = CCMapping::try_from(self.0.next()?);
        if r.is_err() {
            self.0.terminate();
        }
        Some(r)
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        self.0.size_hint()
    }
}

impl DoubleEndedIterator for CCMappingIter<'_> {
    fn next_back(&mut self) -> Option<Self::Item> {
        let r = CCMapping::try_from(self.0.next_back()?);
        if r.is_err() {
            self.0.terminate();
        }
        Some(r)
    }
}

impl FusedIterator for CCMappingIter<'_> {}

/// Bridge IP versions data.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct BridgeIpVersionsData {
    pub ipv4: u32,
    pub ipv6: u32,
}

#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct BridgeIpTransport<'a> {
    /// Pluggable transport.
    pub pt: &'a str,
    /// Number of users that connected with that pluggable transport.
    pub num: u32,
}

impl<'a> TryFrom<&'a str> for BridgeIpTransport<'a> {
    type Error = CertFormatError;

    fn try_from(s: &'a str) -> Result<Self, Self::Error> {
        let i = pt_keyword(s).map_err(|_| CertFormatError)?;
        // SAFETY: Index points to = character in string
        let (pt, b) = unsafe { (s.get_unchecked(..i), s.get_unchecked(i + 1..)) };
        Ok(Self {
            pt,
            num: b.parse().map_err(|_| CertFormatError)?,
        })
    }
}

/// `dirreq-v3-resp` data.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct DirreqRespData {
    /// (added as of 0.4.8.22 / 0.4.9.4-alpha) a network status
    /// request is answered, meaning it was a valid request and the
    /// answer used a 200 OK status code.
    pub served: u32,

    /// a served network status request was successfully sent;
    /// this number is a subset of the "served" number above, and
    /// corresponds to the sum of all requests as reported in
    /// "dirreq-v2-reqs" or "dirreq-v3-reqs", respectively, before
    /// rounding up.
    pub ok: u32,

    /// a version 3 network status is not signed by a
    /// sufficient number of requested authorities.
    pub not_enough_sigs: u32,

    /// a requested network status object is unavailable.
    pub unavailable: u32,

    /// a requested network status is not found.
    pub not_found: u32,

    /// a network status has not been modified since the
    /// If-Modified-Since time that is included in the request.
    pub not_modified: u32,

    /// the directory is busy.
    pub busy: u32,
}

impl DirreqRespData {
    fn new(s: &str) -> Result<Self, CertFormatError> {
        let mut served = None;
        let mut ok = None;
        let mut not_enough_sigs = None;
        let mut unavailable = None;
        let mut not_found = None;
        let mut not_modified = None;
        let mut busy = None;

        for s in CommaIter::from(s) {
            let i = proto_keyword(s).map_err(|_| CertFormatError)?;
            // SAFETY: Index points to = chatacter in string
            let (kw, v) = unsafe { (s.get_unchecked(..i), s.get_unchecked(i + 1..)) };

            let n = v.parse::<u32>().map_err(|_| CertFormatError)?;
            match kw {
                "served" if served.is_none() => served = Some(n),
                "ok" if ok.is_none() => ok = Some(n),
                "not-enough-sigs" if not_enough_sigs.is_none() => not_enough_sigs = Some(n),
                "unavailable" if unavailable.is_none() => unavailable = Some(n),
                "not-found" if not_found.is_none() => not_found = Some(n),
                "not-modified" if not_modified.is_none() => not_modified = Some(n),
                "busy" if busy.is_none() => busy = Some(n),
                _ => (),
            }
        }

        Ok(Self {
            served: served.unwrap_or(0),
            ok: ok.unwrap_or(0),
            not_enough_sigs: not_enough_sigs.unwrap_or(0),
            unavailable: unavailable.unwrap_or(0),
            not_found: not_found.unwrap_or(0),
            not_modified: not_modified.unwrap_or(0),
            busy: busy.unwrap_or(0),
        })
    }
}

/// `dirreq-*-dl` data.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct DirreqDlData {
    /// a client has finished the download successfully.
    pub complete: u32,

    /// a download did not finish within 10 minutes after
    /// starting to send the response.
    pub timeout: u32,

    /// a download is still running at the end of the
    /// measurement period for less than 10 minutes after starting to
    /// send the response.
    pub running: u32,

    /// smallest measured bandwidth in B/s.
    pub min: u32,

    /// largest measured bandwidth in B/s.
    pub max: u32,

    /// 1st to 4th and 6th to 9th decile of measured
    /// bandwidth in B/s. For a given decile i, i/10 of all downloads
    /// had a smaller bandwidth than di, and (10-i)/10 of all downloads
    /// had a larger bandwidth than di.
    pub d1: u32,
    pub d2: u32,
    pub d3: u32,
    pub d4: u32,
    pub d6: u32,
    pub d7: u32,
    pub d8: u32,
    pub d9: u32,

    /// 1st and 3rd quartile of measured bandwidth in B/s. One
    /// fourth of all downloads had a smaller bandwidth than q1, one
    /// fourth of all downloads had a larger bandwidth than q3, and the
    /// remaining half of all downloads had a bandwidth between q1 and
    /// q3.
    pub q1: u32,
    pub q2: u32,
    pub q3: u32,

    /// median of measured bandwidth in B/s. Half of the downloads
    /// had a smaller bandwidth than md, the other half had a larger
    /// bandwidth than md.
    pub md: u32,
}

impl DirreqDlData {
    fn new(s: &str) -> Result<Self, CertFormatError> {
        let mut complete = None;
        let mut timeout = None;
        let mut running = None;
        let mut min = None;
        let mut max = None;
        let mut d1 = None;
        let mut d2 = None;
        let mut d3 = None;
        let mut d4 = None;
        let mut d6 = None;
        let mut d7 = None;
        let mut d8 = None;
        let mut d9 = None;
        let mut q1 = None;
        let mut q2 = None;
        let mut q3 = None;
        let mut md = None;

        for s in CommaIter::from(s) {
            let i = proto_keyword(s).map_err(|_| CertFormatError)?;
            // SAFETY: Index points to = chatacter in string
            let (kw, v) = unsafe { (s.get_unchecked(..i), s.get_unchecked(i + 1..)) };

            let n = v.parse::<u32>().map_err(|_| CertFormatError)?;
            match kw {
                "complete" if complete.is_none() => complete = Some(n),
                "timeout" if timeout.is_none() => timeout = Some(n),
                "running" if running.is_none() => running = Some(n),
                "min" if min.is_none() => min = Some(n),
                "max" if max.is_none() => max = Some(n),
                "d1" if d1.is_none() => d1 = Some(n),
                "d2" if d2.is_none() => d2 = Some(n),
                "d3" if d3.is_none() => d3 = Some(n),
                "d4" if d4.is_none() => d4 = Some(n),
                "d6" if d6.is_none() => d6 = Some(n),
                "d7" if d7.is_none() => d7 = Some(n),
                "d8" if d8.is_none() => d8 = Some(n),
                "d9" if d9.is_none() => d9 = Some(n),
                "q1" if q1.is_none() => q1 = Some(n),
                "q2" if q2.is_none() => q2 = Some(n),
                "q3" if q3.is_none() => q3 = Some(n),
                "md" if md.is_none() => md = Some(n),
                _ => (),
            }
        }

        Ok(Self {
            complete: complete.unwrap_or(0),
            timeout: timeout.unwrap_or(0),
            running: running.unwrap_or(0),
            min: min.unwrap_or(0),
            max: max.unwrap_or(0),
            d1: d1.unwrap_or(0),
            d2: d2.unwrap_or(0),
            d3: d3.unwrap_or(0),
            d4: d4.unwrap_or(0),
            d6: d6.unwrap_or(0),
            d7: d7.unwrap_or(0),
            d8: d8.unwrap_or(0),
            d9: d9.unwrap_or(0),
            q1: q1.unwrap_or(0),
            q2: q2.unwrap_or(0),
            q3: q3.unwrap_or(0),
            md: md.unwrap_or(0),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::cmp::PartialEq;
    use std::collections::BTreeMap;
    use std::fmt::{Debug, Formatter, Result as FmtResult, Write as _};
    use std::ops::Deref;

    use base64ct::{Base64, Base64Unpadded, Encoder, Encoding, LineEnding};
    use ed25519_dalek::{Signer, SigningKey};
    use proptest::array::uniform;
    use proptest::collection::{btree_map, vec};
    use proptest::option::of;
    use proptest::prelude::*;
    use proptest::strategy::LazyJust;
    use zerocopy::IntoBytes;

    use crate::crypto::cert::{EdCertExtHeader, EdCertHeader};
    use crate::util::{print_hex, test_ed_pk, time_strat, write_datetime};

    #[derive(PartialEq, Eq, PartialOrd, Ord, Hash)]
    struct CC([u8; 2]);

    impl Deref for CC {
        type Target = str;

        fn deref(&self) -> &str {
            unsafe { str::from_utf8_unchecked(&self.0) }
        }
    }

    impl PartialEq<String> for CC {
        fn eq(&self, other: &String) -> bool {
            &**self == other
        }
    }

    impl Debug for CC {
        fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
            Debug::fmt(&**self, f)
        }
    }

    #[test]
    fn test_parse_extra_info() {
        let ed_sk = SigningKey::from_bytes(&test_ed_pk());
        let ed_pk = ed_sk.verifying_key();
        let id_cert = {
            let cert = EdCertHeader {
                cert_ty: 4,
                key_ty: 1,
                key: ed_pk.to_bytes(),
                expiry: u32::MAX.into(),
                n_ext: 1,
            };
            let ext = EdCertExtHeader {
                len: 32u16.into(),
                ty: 4,
                flags: 1,
            };

            let mut v = Vec::with_capacity(
                1 + cert.as_bytes().len() + ext.as_bytes().len() + ed_pk.as_bytes().len() + 64,
            );
            v.push(1);
            v.extend_from_slice(cert.as_bytes());
            v.extend_from_slice(ext.as_bytes());
            v.extend_from_slice(ed_pk.as_bytes());

            let sig = ed_sk.sign(&v).to_bytes();
            v.extend(sig);
            let mut buf = [0; 1024];
            let mut enc = Encoder::<Base64>::new_wrapped(&mut buf, 64, LineEnding::LF).unwrap();
            enc.encode(&v).unwrap();
            drop(v);
            format!(
                "-----BEGIN ED25519 CERT-----\n{}\n-----END ED25519 CERT-----\n",
                enc.finish().unwrap()
            )
        };

        let f = move |extrainfo: Vec<(
            (String, RelayId, SystemTime),
            [Option<(SystemTime, u32, Vec<u64>)>; 4],
            [Option<Sha1Output>; 2],
            (
                Option<(SystemTime, u32)>,
                BTreeMap<CC, u32>,
                Option<[u32; 2]>,
                BTreeMap<String, u32>,
            ),
            (
                Option<(SystemTime, u32)>,
                [BTreeMap<CC, u32>; 2],
                Option<[u32; 7]>,
                [Option<[u32; 17]>; 2],
                [Option<(SystemTime, u32, Vec<u64>)>; 2],
            ),
            (Option<(SystemTime, u32)>, BTreeMap<CC, u32>),
        )>| {
            let mut s = String::new();

            for (
                (nickname, fingerprint, published),
                hist,
                [geoip_db_digest, geoip6_db_digest],
                (bridge_stats_end, bridge_ips, bridge_ip_versions, bridge_ip_transports),
                (
                    dirreq_stats_end,
                    dirreq_v3_ips_reqs,
                    dirreq_v3_resp,
                    dirreq_v3_direct_tunneled_dl,
                    dirreq_read_write_history,
                ),
                (entry_stats_end, entry_ips),
            ) in &extrainfo
            {
                let si = s.len();

                writeln!(s, "extra-info {nickname} {}", print_hex(fingerprint)).unwrap();
                s += "identity-ed25519\n";
                s += &id_cert;
                s += "published ";
                write_datetime(&mut s, (*published).into());
                s += "\n";
                for ((time, nsec, data), k) in hist
                    .into_iter()
                    .zip([
                        "read-history",
                        "write-history",
                        "ipv6-read-history",
                        "ipv6-write-history",
                    ])
                    .filter_map(|(h, k)| Some((h.as_ref()?, k)))
                {
                    s += k;
                    s += " ";
                    write_datetime(&mut s, (*time).into());
                    write!(s, " ({nsec} s)").unwrap();
                    for (i, v) in data.iter().enumerate() {
                        write!(s, "{}{v}", if i == 0 { " " } else { "," }).unwrap();
                    }
                    s += "\n";
                }
                if let Some(v) = geoip_db_digest {
                    writeln!(s, "geoip-db-digest {}", print_hex(v)).unwrap();
                }
                if let Some(v) = geoip6_db_digest {
                    writeln!(s, "geoip6-db-digest {}", print_hex(v)).unwrap();
                }
                if let Some((time, nsec)) = bridge_stats_end {
                    s += "bridge-stats-end ";
                    write_datetime(&mut s, (*time).into());
                    writeln!(s, " ({nsec} s)").unwrap();
                }
                if !bridge_ips.is_empty() {
                    for (i, (k, v)) in bridge_ips.iter().enumerate() {
                        write!(
                            s,
                            "{}{}={v}",
                            if i == 0 { "bridge-ips " } else { "," },
                            &**k
                        )
                        .unwrap();
                    }
                    s += "\n";
                }
                if let Some(v) = bridge_ip_versions {
                    for (i, (v, k)) in v
                        .iter()
                        .zip(["4", "6"])
                        .filter(|(v, _)| **v != 0)
                        .enumerate()
                    {
                        write!(
                            s,
                            "{}{k}={v}",
                            if i == 0 { "bridge-ip-versions " } else { "," }
                        )
                        .unwrap();
                    }
                    s += "\n";
                }
                if !bridge_ip_transports.is_empty() {
                    for (i, (k, v)) in bridge_ip_transports.iter().enumerate() {
                        write!(
                            s,
                            "{}{k}={v}",
                            if i == 0 { "bridge-ip-transports " } else { "," }
                        )
                        .unwrap();
                    }
                    s += "\n";
                }
                if let Some((time, nsec)) = dirreq_stats_end {
                    s += "dirreq-stats-end ";
                    write_datetime(&mut s, (*time).into());
                    writeln!(s, " ({nsec} s)").unwrap();
                }
                for (v, h) in dirreq_v3_ips_reqs
                    .iter()
                    .zip(["dirreq-v3-ips ", "dirreq-v3-reqs "])
                    .filter(|(v, _)| !v.is_empty())
                {
                    for (i, (k, v)) in v.iter().enumerate() {
                        write!(s, "{}{}={v}", if i == 0 { h } else { "," }, &**k,).unwrap();
                    }
                    s += "\n";
                }
                if let Some(v) = dirreq_v3_resp {
                    for (i, (v, k)) in v
                        .iter()
                        .zip([
                            "served",
                            "ok",
                            "not-enough-sigs",
                            "unavailable",
                            "not-found",
                            "not-modified",
                            "busy",
                        ])
                        .filter(|(v, _)| **v != 0)
                        .enumerate()
                    {
                        write!(s, "{}{k}={v}", if i == 0 { "dirreq-v3-resp " } else { "," })
                            .unwrap();
                    }
                    s += "\n";
                }
                for (v, h) in dirreq_v3_direct_tunneled_dl
                    .iter()
                    .zip(["dirreq-v3-direct-dl ", "dirreq-v3-tunneled-dl "])
                    .filter_map(|(v, h)| Some((v.as_ref()?, h)))
                {
                    for (i, (v, k)) in v
                        .iter()
                        .zip([
                            "complete", "timeout", "running", "min", "max", "d1", "d2", "d3", "d4",
                            "d6", "d7", "d8", "d9", "q1", "q2", "q3", "md",
                        ])
                        .filter(|(v, _)| **v != 0)
                        .enumerate()
                    {
                        write!(s, "{}{k}={v}", if i == 0 { h } else { "," }).unwrap();
                    }
                    s += "\n";
                }
                for ((time, nsec, data), k) in dirreq_read_write_history
                    .into_iter()
                    .zip(["dirreq-read-history", "dirreq-write-history"])
                    .filter_map(|(h, k)| Some((h.as_ref()?, k)))
                {
                    s += k;
                    s += " ";
                    write_datetime(&mut s, (*time).into());
                    write!(s, " ({nsec} s)").unwrap();
                    for (i, v) in data.iter().enumerate() {
                        write!(s, "{}{v}", if i == 0 { " " } else { "," }).unwrap();
                    }
                    s += "\n";
                }
                if let Some((time, nsec)) = entry_stats_end {
                    s += "entry-stats-end ";
                    write_datetime(&mut s, (*time).into());
                    writeln!(s, " ({nsec} s)").unwrap();
                }
                if !entry_ips.is_empty() {
                    for (i, (k, v)) in entry_ips.iter().enumerate() {
                        write!(s, "{}{}={v}", if i == 0 { "entry-ips " } else { "," }, &**k)
                            .unwrap();
                    }
                    s += "\n";
                }

                s += "\nrouter-sig-ed25519 ";
                let sig = ed_sk
                    .sign(
                        &Sha256::new()
                            .chain_update(b"Tor router descriptor signature v1")
                            .chain_update(s[si..].as_bytes())
                            .finalize(),
                    )
                    .to_bytes();
                writeln!(s, "{}", Base64Unpadded::encode_string(&sig)).unwrap();

                // Dummy signature
                s += "router-signature\n-----BEGIN SIGNATURE-----\naHR0cHM6Ly93d3cueW91dHViZS5jb20vd2F0Y2g/dj1kUXc0dzlXZ1hjUQ==\n-----END SIGNATURE-----\n";
            }

            let mut parser = Parser::new(&s);
            for (
                i,
                (
                    (nickname, fingerprint, published),
                    [
                        read_history,
                        write_history,
                        ipv6_read_history,
                        ipv6_write_history,
                    ],
                    [geoip_db_digest, geoip6_db_digest],
                    (bridge_stats_end, bridge_ips, bridge_ip_versions, bridge_ip_transports),
                    (
                        dirreq_stats_end,
                        [dirreq_v3_ips, dirreq_v3_reqs],
                        dirreq_v3_resp,
                        [dirreq_v3_direct_dl, dirreq_v3_tunneled_dl],
                        [dirreq_read_history, dirreq_write_history],
                    ),
                    (entry_stats_end, entry_ips),
                ),
            ) in extrainfo.into_iter().enumerate()
            {
                let desc = match parser.next() {
                    None => panic!("iteration should produce at least {i} items, but stopped"),
                    Some(Err(e)) => panic!("error at index {i}: {e:?}"),
                    Some(Ok(v)) => v,
                };

                assert_eq!(desc.nickname, nickname, "mismatch at index {i}");
                assert_eq!(desc.fingerprint, fingerprint, "mismatch at index {i}");
                assert_eq!(desc.published, published, "mismatch at index {i}");
                assert_eq!(
                    desc.read_history.is_some(),
                    read_history.is_some(),
                    "mismatch at index {i}"
                );
                if let (Some(v), Some((time, interval, data))) = (&desc.read_history, read_history)
                {
                    assert_eq!(v.time, time, "mismatch at index {i}");
                    assert_eq!(v.interval, interval, "mismatch at index {i}");
                    assert_eq!(
                        v.iter().collect::<Result<Vec<_>, _>>(),
                        Ok(data),
                        "mismatch at index {i}"
                    );
                }
                assert_eq!(
                    desc.write_history.is_some(),
                    write_history.is_some(),
                    "mismatch at index {i}"
                );
                if let (Some(v), Some((time, interval, data))) =
                    (&desc.write_history, write_history)
                {
                    assert_eq!(v.time, time, "mismatch at index {i}");
                    assert_eq!(v.interval, interval, "mismatch at index {i}");
                    assert_eq!(
                        v.iter().collect::<Result<Vec<_>, _>>(),
                        Ok(data),
                        "mismatch at index {i}"
                    );
                }
                assert_eq!(
                    desc.ipv6_read_history.is_some(),
                    ipv6_read_history.is_some(),
                    "mismatch at index {i}"
                );
                if let (Some(v), Some((time, interval, data))) =
                    (&desc.ipv6_read_history, ipv6_read_history)
                {
                    assert_eq!(v.time, time, "mismatch at index {i}");
                    assert_eq!(v.interval, interval, "mismatch at index {i}");
                    assert_eq!(
                        v.iter().collect::<Result<Vec<_>, _>>(),
                        Ok(data),
                        "mismatch at index {i}"
                    );
                }
                assert_eq!(
                    desc.ipv6_write_history.is_some(),
                    ipv6_write_history.is_some(),
                    "mismatch at index {i}"
                );
                if let (Some(v), Some((time, interval, data))) =
                    (&desc.ipv6_write_history, ipv6_write_history)
                {
                    assert_eq!(v.time, time, "mismatch at index {i}");
                    assert_eq!(v.interval, interval, "mismatch at index {i}");
                    assert_eq!(
                        v.iter().collect::<Result<Vec<_>, _>>().unwrap(),
                        data,
                        "mismatch at index {i}"
                    );
                }
                assert_eq!(
                    desc.geoip_db_digest, geoip_db_digest,
                    "mismatch at index {i}"
                );
                assert_eq!(
                    desc.geoip6_db_digest, geoip6_db_digest,
                    "mismatch at index {i}"
                );
                assert_eq!(
                    desc.bridge_stats_end.as_ref().map(|v| (v.time, v.interval)),
                    bridge_stats_end,
                    "mismatch at index {i}"
                );
                assert_eq!(
                    desc.bridge_ips.is_some(),
                    !bridge_ips.is_empty(),
                    "mismatch at index {i}"
                );
                if let Some(v) = &desc.bridge_ips {
                    assert_eq!(
                        v.iter()
                            .map(|v| v.map(|v| (v.cc.to_string(), v.num)))
                            .collect::<Result<Vec<_>, _>>()
                            .unwrap(),
                        bridge_ips
                            .into_iter()
                            .map(|(k, v)| ((*k).to_string(), v))
                            .collect::<Vec<_>>(),
                        "mismatch at index {i}"
                    );
                }
                assert_eq!(
                    desc.bridge_ip_versions.as_ref().map(|v| [v.ipv4, v.ipv6]),
                    bridge_ip_versions,
                    "mismatch at index {i}"
                );
                assert_eq!(
                    desc.bridge_ip_transports.is_some(),
                    !bridge_ip_transports.is_empty(),
                    "mismatch at index {i}"
                );
                if let Some(v) = &desc.bridge_ip_transports {
                    assert_eq!(
                        v.iter()
                            .map(|v| (v.pt.to_string(), v.num))
                            .collect::<Vec<_>>(),
                        bridge_ip_transports.into_iter().collect::<Vec<_>>(),
                        "mismatch at index {i}"
                    );
                }
                assert_eq!(
                    desc.dirreq_stats_end.as_ref().map(|v| (v.time, v.interval)),
                    dirreq_stats_end,
                    "mismatch at index {i}"
                );
                assert_eq!(
                    desc.dirreq_v3_ips.is_some(),
                    !dirreq_v3_ips.is_empty(),
                    "mismatch at index {i}"
                );
                if let Some(v) = &desc.dirreq_v3_ips {
                    assert_eq!(
                        v.iter()
                            .map(|v| v.map(|v| (v.cc.to_string(), v.num)))
                            .collect::<Result<Vec<_>, _>>()
                            .unwrap(),
                        dirreq_v3_ips
                            .into_iter()
                            .map(|(k, v)| ((*k).to_string(), v))
                            .collect::<Vec<_>>(),
                        "mismatch at index {i}"
                    );
                }
                assert_eq!(
                    desc.dirreq_v3_reqs.is_some(),
                    !dirreq_v3_reqs.is_empty(),
                    "mismatch at index {i}"
                );
                if let Some(v) = &desc.dirreq_v3_reqs {
                    assert_eq!(
                        v.iter()
                            .map(|v| v.map(|v| (v.cc.to_string(), v.num)))
                            .collect::<Result<Vec<_>, _>>()
                            .unwrap(),
                        dirreq_v3_reqs
                            .into_iter()
                            .map(|(k, v)| ((*k).to_string(), v))
                            .collect::<Vec<_>>(),
                        "mismatch at index {i}"
                    );
                }
                assert_eq!(
                    desc.dirreq_v3_resp.as_ref().map(|v| [
                        v.served,
                        v.ok,
                        v.not_enough_sigs,
                        v.unavailable,
                        v.not_found,
                        v.not_modified,
                        v.busy,
                    ]),
                    dirreq_v3_resp,
                    "mismatch at index {i}"
                );
                assert_eq!(
                    desc.dirreq_v3_direct_dl.as_ref().map(|v| [
                        v.complete, v.timeout, v.running, v.min, v.max, v.d1, v.d2, v.d3, v.d4,
                        v.d6, v.d7, v.d8, v.d9, v.q1, v.q2, v.q3, v.md,
                    ]),
                    dirreq_v3_direct_dl,
                    "mismatch at index {i}"
                );
                assert_eq!(
                    desc.dirreq_v3_tunneled_dl.as_ref().map(|v| [
                        v.complete, v.timeout, v.running, v.min, v.max, v.d1, v.d2, v.d3, v.d4,
                        v.d6, v.d7, v.d8, v.d9, v.q1, v.q2, v.q3, v.md,
                    ]),
                    dirreq_v3_tunneled_dl,
                    "mismatch at index {i}"
                );
                assert_eq!(
                    desc.dirreq_read_history.is_some(),
                    dirreq_read_history.is_some(),
                    "mismatch at index {i}"
                );
                if let (Some(v), Some((time, interval, data))) =
                    (&desc.dirreq_read_history, dirreq_read_history)
                {
                    assert_eq!(v.time, time, "mismatch at index {i}");
                    assert_eq!(v.interval, interval, "mismatch at index {i}");
                    assert_eq!(
                        v.iter().collect::<Result<Vec<_>, _>>(),
                        Ok(data),
                        "mismatch at index {i}"
                    );
                }
                assert_eq!(
                    desc.dirreq_write_history.is_some(),
                    dirreq_write_history.is_some(),
                    "mismatch at index {i}"
                );
                if let (Some(v), Some((time, interval, data))) =
                    (&desc.dirreq_write_history, dirreq_write_history)
                {
                    assert_eq!(v.time, time, "mismatch at index {i}");
                    assert_eq!(v.interval, interval, "mismatch at index {i}");
                    assert_eq!(
                        v.iter().collect::<Result<Vec<_>, _>>(),
                        Ok(data),
                        "mismatch at index {i}"
                    );
                }
                assert_eq!(
                    desc.entry_stats_end.as_ref().map(|v| (v.time, v.interval)),
                    entry_stats_end,
                    "mismatch at index {i}"
                );
                assert_eq!(
                    desc.entry_ips.is_some(),
                    !entry_ips.is_empty(),
                    "mismatch at index {i}"
                );
                if let Some(v) = &desc.entry_ips {
                    assert_eq!(
                        v.iter()
                            .map(|v| v.map(|v| (v.cc.to_string(), v.num)))
                            .collect::<Result<Vec<_>, _>>()
                            .unwrap(),
                        entry_ips
                            .into_iter()
                            .map(|(k, v)| ((*k).to_string(), v))
                            .collect::<Vec<_>>(),
                        "mismatch at index {i}"
                    );
                }
            }
        };

        proptest! {
            |(extrainfo in vec((
                (
                    "[a-zA-Z0-9]+",
                    any::<RelayId>(),
                    time_strat(),
                ),
                uniform::<_, 4>(of((
                    time_strat(),
                    1u32..,
                    vec(1u64.., 1..=32),
                ))),
                any::<[Option<Sha1Output>; 2]>(),
                (
                    of((time_strat(), 1u32..)),
                    btree_map(uniform::<_, 2>(b'a'..=b'z').prop_map(CC), 1u32.., 0..=32),
                    of(any::<[u32; 2]>().prop_map(|v| if v.iter().all(|v| *v == 0) {
                        None
                    } else {
                        Some(v)
                    })).prop_map(|v| v.flatten()),
                    btree_map(
                        prop_oneof![
                            LazyJust::new(|| "<OR>".to_string()),
                            LazyJust::new(|| "<??>".to_string()),
                            "[a-zA-Z_][a-zA-Z0-9_]*",
                        ],
                        1u32..,
                        0..=16,
                    ),
                ),
                (
                    of((time_strat(), 1u32..)),
                    uniform::<_, 2>(btree_map(uniform::<_, 2>(b'a'..=b'z').prop_map(CC), 1u32.., 0..=32)),
                    of(any::<[u32; 7]>().prop_map(|v| if v.iter().all(|v| *v == 0) {
                        None
                    } else {
                        Some(v)
                    })).prop_map(|v| v.flatten()),
                    uniform::<_, 2>(of(any::<[u32; 17]>().prop_map(|v| if v.iter().all(|v| *v == 0) {
                        None
                    } else {
                        Some(v)
                    })).prop_map(|v| v.flatten())),
                    uniform::<_, 2>(of((
                        time_strat(),
                        1u32..,
                        vec(1u64.., 1..=32),
                    ))),
                ),
                (
                    of((time_strat(), 1u32..)),
                    btree_map(uniform::<_, 2>(b'a'..=b'z').prop_map(CC), 1u32.., 0..=32),
                ),
            ), 1..=16))| f(extrainfo)
        }
    }
}
