//! (Microdescriptor) consensus parser.
//!
//! Parses and validate consensus (at `/tor/status-vote/current/consensus` or `/tor/status-vote/current/consensus-microdesc`).
#![allow(clippy::wrong_self_convention)] // Yeah we like to_footer and to_relay

use std::cmp::{Ord, Ordering, PartialEq, PartialOrd};
use std::iter::FusedIterator;
use std::mem::MaybeUninit;
use std::net::{IpAddr, Ipv4Addr, SocketAddr, SocketAddrV6};
use std::num::NonZeroU16;
use std::time::SystemTime;

use digest::Digest;
use rsa::RsaPublicKey;
use rsa::pkcs1v15::Pkcs1v15Sign;
use sha1::Sha1;
use sha2::Sha256;

use super::ExitPortPolicy;
use super::misc::{args_date_time, args_exit_policy, decode_b64, parse_b64, parse_b64u};
use super::netdoc::{
    Arguments as NetdocArguments, Item as NetdocItem, NetdocParser, get_signature,
};
use crate::crypto::relay::RelayId;
use crate::crypto::{Sha1Output, Sha256Output};
use crate::errors::{
    CertFormatError, CertVerifyError, ConsensusParseError, ConsensusSignatureError,
    TooManySignaturesError,
};
use crate::util::parse::parse_hex;

/// A consensus signature.
#[derive(Debug)]
#[non_exhaustive]
pub struct ConsensusSignature<'a> {
    /// Signature algorithm.
    pub algorithm: &'a str,

    /// Fingerprint of directory authority.
    pub fingerprint: RelayId,

    /// SHA1 digest of signing key.
    pub sig_digest: Sha1Output,

    /// Signature object in PEM format, excluding header and footer.
    ///
    /// Note that it's content is **not** verified.
    pub signature: &'a str,
}

impl PartialEq for ConsensusSignature<'_> {
    fn eq(&self, rhs: &Self) -> bool {
        self.fingerprint == rhs.fingerprint
            && self.sig_digest == rhs.sig_digest
            && self.algorithm == rhs.algorithm
    }
}

impl Eq for ConsensusSignature<'_> {}

impl PartialOrd for ConsensusSignature<'_> {
    fn partial_cmp(&self, rhs: &Self) -> Option<Ordering> {
        Some(self.cmp(rhs))
    }
}

impl Ord for ConsensusSignature<'_> {
    fn cmp(&self, rhs: &Self) -> Ordering {
        self.fingerprint
            .cmp(&rhs.fingerprint)
            .then_with(|| self.sig_digest.cmp(&rhs.sig_digest))
            .then_with(|| self.algorithm.cmp(rhs.algorithm))
    }
}

/// Return value of [`parse_consensus_signature`].
#[non_exhaustive]
pub struct ConsensusSignatureResult<'a, 'b> {
    /// The entire document without signatures.
    ///
    /// **NOTE: Do not use this to verify! Digest `bytes` instead.**
    pub document: &'a str,

    /// Message bytes to be verified.
    pub bytes: &'a [u8],

    /// Signatures extracted.
    pub sigs: &'b mut [ConsensusSignature<'a>],
}

/// Process consensus signatures.
///
/// # Parameters:
/// - `doc` : Consensus document.
/// - `sigs` : Signature array buffer.
///   Ensure at least the number of directory authorities are allocated.
///   Returns [`ConsensusSignatureError::TooManySignaturesError`] if array is too small.
pub fn parse_consensus_signature<'a, 'b>(
    doc: &'a str,
    sigs: &'b mut [MaybeUninit<ConsensusSignature<'a>>],
) -> Result<ConsensusSignatureResult<'a, 'b>, ConsensusSignatureError> {
    let mut s = doc;
    let mut ix = 0;
    let mut last_item = None;

    // Parse signatures until first error.
    // If the document is invalid, it should be caught in verification phase.
    while let Ok(v) = get_signature(s) {
        if v.item.keyword() != "directory-signature" {
            // Unknown keyword.
            break;
        }

        let mut args = v.item.arguments();
        let a1 = args.next().ok_or(CertFormatError)?;
        let a2 = args.next().ok_or(CertFormatError)?;
        let (algorithm, fingerprint, sig_digest);
        (algorithm, fingerprint, sig_digest) = match args.next() {
            Some(a3) => match parse_hex(a1) {
                // Algorithm possibly missing.
                Some(v) => ("", Ok(v), a2),
                None => (a1, Err(a2), a3),
            },
            // Only two arguments.
            None => ("", Err(a1), a2),
        };
        let fingerprint = fingerprint.or_else(|v| parse_hex(v).ok_or(CertFormatError))?;
        let sig_digest = parse_hex(sig_digest).ok_or(CertFormatError)?;

        let Some(("SIGNATURE", signature)) = v.item.object() else {
            return Err(CertFormatError.into());
        };

        let sig = sigs.get_mut(ix).ok_or(TooManySignaturesError)?;
        ix += 1;
        sig.write(ConsensusSignature {
            algorithm,
            fingerprint,
            sig_digest,
            signature,
        });
        last_item = Some(v.item);
        s = v.document;
    }

    let i = last_item.ok_or(CertFormatError)?;
    // End of message is space after keyword.
    // In other word, start of arguments.
    let b = &doc.as_bytes()[..i.byte_offset() + i.line_len() - i.arguments_raw().len()];
    // SAFETY: Everything up to ix is filled.
    let sigs = unsafe { sigs[..ix].assume_init_mut() };

    Ok(ConsensusSignatureResult {
        document: s,
        bytes: b,
        sigs,
    })
}

/// Consensus signature verifier.
pub struct SignatureVerifier<'a> {
    bytes: &'a [u8],
    sha1: Option<Sha1Output>,
    sha256: Option<Sha256Output>,
}

impl<'a> From<&'a [u8]> for SignatureVerifier<'a> {
    fn from(v: &'a [u8]) -> Self {
        Self::new(v)
    }
}

impl<'a> From<&ConsensusSignatureResult<'a, '_>> for SignatureVerifier<'a> {
    fn from(v: &ConsensusSignatureResult<'a, '_>) -> Self {
        Self::new(v.bytes)
    }
}

impl<'a> SignatureVerifier<'a> {
    /// Creates new [`SignatureVerifier`].
    pub fn new(bytes: &'a [u8]) -> Self {
        Self {
            bytes,
            sha1: None,
            sha256: None,
        }
    }

    /// Verify a signature.
    ///
    /// # Parameters
    /// - `sig` : Consensus signature.
    /// - `sign_key` : Signing public key. Must have the same hash as signing key digest in signature.
    pub fn verify(
        &mut self,
        sig: &ConsensusSignature<'_>,
        sign_key: &RsaPublicKey,
    ) -> Result<(), ConsensusSignatureError> {
        let mut tmp = [0; 2048];
        let s = decode_b64(&mut tmp, sig.signature)?;

        let hash = match sig.algorithm {
            "" | "sha1" => &self
                .sha1
                .get_or_insert_with(|| Sha1::digest(self.bytes).into())[..],
            "sha256" => &self
                .sha256
                .get_or_insert_with(|| Sha256::digest(self.bytes).into())[..],
            // Unknown algorithm, ignore
            _ => return Ok(()),
        };

        sign_key
            .verify(Pkcs1v15Sign::new_unprefixed(), hash, s)
            .map_err(|_| CertVerifyError.into())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Flavor {
    Consensus,
    Microdesc,
}

/// Starts parsing consensus data.
///
/// Returns a [`PreambleData`] and an [`AuthorityEntryParser`].
/// Further parsing is done by iterating [`AuthorityEntryParser`].
pub fn parse_consensus(
    doc: &str,
) -> Result<(PreambleData<'_>, AuthorityEntryParser<'_>), ConsensusParseError> {
    let mut parser = NetdocParser::new(doc);

    let flavor = {
        let item = parser.next().ok_or(CertFormatError)??;
        if item.keyword() != "network-status-version" {
            return Err(CertFormatError.into());
        }
        let mut args = item.arguments();
        if args.next() != Some("3") {
            return Err(CertFormatError.into());
        }
        match args.next() {
            Some("microdesc") => Flavor::Microdesc,
            // Unknown flavor.
            _ => Flavor::Consensus,
        }
    };

    let mut status = None;
    let mut method = None;
    let mut valid_after = None;
    let mut fresh_until = None;
    let mut valid_until = None;
    let mut voting_delay = None;
    let mut client_versions = None;
    let mut server_versions = None;
    let mut known_flags = None;
    let mut req_client_proto = None;
    let mut rec_client_proto = None;
    let mut req_relay_proto = None;
    let mut rec_relay_proto = None;
    let mut params = None;
    let mut srv_cur = None;
    let mut srv_prev = None;

    let item = loop {
        let item = parser.next().ok_or(CertFormatError)??;

        match item.keyword() {
            // vote-status is exactly once
            "vote-status" => {
                if status.is_some() {
                    return Err(CertFormatError.into());
                }
                status = Some(item.arguments().next().ok_or(CertFormatError)?);
            }
            // consensus-method is at most once
            "consensus-method" => {
                if method.is_some() {
                    return Err(CertFormatError.into());
                }
                let mut args = item.arguments();
                method = Some(
                    args.next()
                        .ok_or(CertFormatError)?
                        .parse::<u32>()
                        .map_err(|_| CertFormatError)?,
                );
                if args.next().is_some() {
                    return Err(CertFormatError.into());
                }
            }
            // valid-after is exactly once
            "valid-after" => {
                if valid_after.is_some() {
                    return Err(CertFormatError.into());
                }
                valid_after = Some(SystemTime::from(
                    args_date_time(&mut item.arguments()).ok_or(CertFormatError)?,
                ));
            }
            // fresh-until is exactly once
            "fresh-until" => {
                if fresh_until.is_some() {
                    return Err(CertFormatError.into());
                }
                fresh_until = Some(SystemTime::from(
                    args_date_time(&mut item.arguments()).ok_or(CertFormatError)?,
                ));
            }
            // valid-until is exactly once
            "valid-until" => {
                if valid_until.is_some() {
                    return Err(CertFormatError.into());
                }
                valid_until = Some(SystemTime::from(
                    args_date_time(&mut item.arguments()).ok_or(CertFormatError)?,
                ));
            }
            // voting-delay is exactly once
            "voting-delay" => {
                if voting_delay.is_some() {
                    return Err(CertFormatError.into());
                }
                let mut args = item.arguments();
                let vote = args
                    .next()
                    .ok_or(CertFormatError)?
                    .parse::<u32>()
                    .map_err(|_| CertFormatError)?;
                let dist = args
                    .next()
                    .ok_or(CertFormatError)?
                    .parse::<u32>()
                    .map_err(|_| CertFormatError)?;
                voting_delay = Some(VotingDelay { vote, dist });
            }
            // client-versions is at most once
            "client-versions" => {
                if client_versions.is_some() {
                    return Err(CertFormatError.into());
                }
                client_versions = Some(item.arguments());
            }
            // server-versions is at most once
            "server-versions" => {
                if server_versions.is_some() {
                    return Err(CertFormatError.into());
                }
                server_versions = Some(item.arguments());
            }
            // known-flags is exactly once
            "known-flags" => {
                if known_flags.is_some() {
                    return Err(CertFormatError.into());
                }
                known_flags = Some(item.arguments());
            }
            // recommended-client-protocols is at most once
            "recommended-client-protocols" => {
                if rec_client_proto.is_some() {
                    return Err(CertFormatError.into());
                }
                rec_client_proto = Some(item.arguments());
            }
            // required-client-protocols is at most once
            "required-client-protocols" => {
                if req_client_proto.is_some() {
                    return Err(CertFormatError.into());
                }
                req_client_proto = Some(item.arguments());
            }
            // recommended-relay-protocols is at most once
            "recommended-relay-protocols" => {
                if rec_relay_proto.is_some() {
                    return Err(CertFormatError.into());
                }
                rec_relay_proto = Some(item.arguments());
            }
            // required-relay-protocols is at most once
            "required-relay-protocols" => {
                if req_relay_proto.is_some() {
                    return Err(CertFormatError.into());
                }
                req_relay_proto = Some(item.arguments());
            }
            // params is at most once
            "params" => {
                if params.is_some() {
                    return Err(CertFormatError.into());
                }
                params = Some(item.arguments());
            }
            // shared-rand-previous-value is at most once
            "shared-rand-previous-value" => {
                if srv_prev.is_some() {
                    return Err(CertFormatError.into());
                }
                srv_prev = Some(parse_srv(&item)?);
            }
            // shared-rand-current-value is at most once
            "shared-rand-current-value" => {
                if srv_cur.is_some() {
                    return Err(CertFormatError.into());
                }
                srv_cur = Some(parse_srv(&item)?);
            }
            // dir-source is the beginning of directory authority entry
            "dir-source" => break item,
            // r is the beginning of relay data.
            // There should be at least one directory authority entry.
            "r" => return Err(CertFormatError.into()),
            // Unknown keyword, skip
            _ => (),
        }
    };

    let (
        Some(status),
        Some(valid_after),
        Some(fresh_until),
        Some(valid_until),
        Some(voting_delay),
        Some(known_flags),
    ) = (
        status,
        valid_after,
        fresh_until,
        valid_until,
        voting_delay,
        known_flags,
    )
    else {
        return Err(CertFormatError.into());
    };

    let parser = AuthorityEntryParserInner {
        item: Some(item),
        inner: parser,
    };

    Ok((
        PreambleData {
            status,
            method: method.unwrap_or(1),
            valid_after,
            fresh_until,
            valid_until,
            voting_delay,
            client_versions,
            server_versions,
            known_flags,
            req_client_proto,
            rec_client_proto,
            req_relay_proto,
            rec_relay_proto,
            params,
            srv_cur,
            srv_prev,
        },
        match flavor {
            Flavor::Consensus => {
                AuthorityEntryParser::Consensus(ConsensusAuthorityEntryParser(parser))
            }
            Flavor::Microdesc => {
                AuthorityEntryParser::Microdesc(MicrodescAuthorityEntryParser(parser))
            }
        },
    ))
}

/// Consensus preamble data.
#[derive(Debug)]
#[non_exhaustive]
pub struct PreambleData<'a> {
    /// Vote status of consensus.
    pub status: &'a str,
    /// Consensus method version.
    pub method: u32,
    /// Valid after date.
    pub valid_after: SystemTime,
    /// Fresh until date.
    pub fresh_until: SystemTime,
    /// Valid until date.
    pub valid_until: SystemTime,
    /// Voting delay.
    pub voting_delay: VotingDelay,
    /// Client versions.
    pub client_versions: Option<NetdocArguments<'a>>,
    /// Server versions.
    pub server_versions: Option<NetdocArguments<'a>>,
    /// Known flags.
    pub known_flags: NetdocArguments<'a>,
    /// Required client protocol versions.
    pub req_client_proto: Option<NetdocArguments<'a>>,
    /// Recommended client protocol versions.
    pub rec_client_proto: Option<NetdocArguments<'a>>,
    /// Required relay protocol versions.
    pub req_relay_proto: Option<NetdocArguments<'a>>,
    /// Recommended relay protocol versions.
    pub rec_relay_proto: Option<NetdocArguments<'a>>,
    /// Consensus parameters.
    pub params: Option<NetdocArguments<'a>>,
    /// Current shared random value.
    pub srv_cur: Option<Srv>,
    /// Previous shared random value.
    pub srv_prev: Option<Srv>,
}

/// Voting delay structure.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct VotingDelay {
    /// Voting delay in seconds.
    pub vote: u32,
    /// Signature delay in seconds.
    pub dist: u32,
}

/// Shared random value.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct Srv {
    /// Number of commits used for computing shared random value.
    pub n_commits: u32,
    /// Shared random value.
    pub val: [u8; 32],
}

#[derive(Clone)]
#[non_exhaustive]
pub enum AuthorityEntryParser<'a> {
    /// Vanilla consensus flavor.
    Consensus(ConsensusAuthorityEntryParser<'a>),
    /// Microdesc consensus flavor.
    Microdesc(MicrodescAuthorityEntryParser<'a>),
}

impl<'a> From<ConsensusAuthorityEntryParser<'a>> for AuthorityEntryParser<'a> {
    fn from(v: ConsensusAuthorityEntryParser<'a>) -> Self {
        Self::Consensus(v)
    }
}

impl<'a> From<MicrodescAuthorityEntryParser<'a>> for AuthorityEntryParser<'a> {
    fn from(v: MicrodescAuthorityEntryParser<'a>) -> Self {
        Self::Microdesc(v)
    }
}

impl<'a> AuthorityEntryParser<'a> {
    /// Starts processing relay entries.
    ///
    /// # Panic
    ///
    /// Panics if iteration is not finished.
    pub fn to_relay(&mut self) -> RelayEntryParser<'a> {
        match self {
            Self::Consensus(v) => RelayEntryParser::Consensus(v.to_relay()),
            Self::Microdesc(v) => RelayEntryParser::Microdesc(v.to_relay()),
        }
    }
}

impl<'a> Iterator for AuthorityEntryParser<'a> {
    type Item = Result<AuthorityEntry<'a>, ConsensusParseError>;

    fn next(&mut self) -> Option<Self::Item> {
        match self {
            Self::Consensus(v) => v.next(),
            Self::Microdesc(v) => v.next(),
        }
    }
}

impl FusedIterator for AuthorityEntryParser<'_> {}

#[derive(Debug)]
#[non_exhaustive]
pub struct AuthorityEntry<'a> {
    pub nickname: &'a str,
    pub identity: RelayId,
    pub address: &'a str,
    pub ip: IpAddr,
    pub dirport: u16,
    pub orport: u16,
    pub contact: &'a str,
    pub vote_digest: Sha1Output,
}

#[derive(Clone)]
struct AuthorityEntryParserInner<'a> {
    item: Option<NetdocItem<'a>>,
    inner: NetdocParser<'a>,
}

impl<'a> AuthorityEntryParserInner<'a> {
    fn parse(&mut self) -> Result<Option<AuthorityEntry<'a>>, ConsensusParseError> {
        let Some(item) = self.item.as_ref() else {
            return Ok(None);
        };
        if item.keyword() != "dir-source" {
            // Entry does not start with dir-source, possibly ending.
            return Ok(None);
        }

        let nickname;
        let identity: RelayId;
        let address;
        let ip;
        let dirport;
        let orport;

        {
            let mut args = item.arguments();
            nickname = args.next().ok_or(CertFormatError)?;
            identity = args.next().and_then(parse_hex).ok_or(CertFormatError)?;
            address = args.next().ok_or(CertFormatError)?;
            ip = args
                .next()
                .and_then(|v| v.parse::<IpAddr>().ok())
                .ok_or(CertFormatError)?;
            dirport = args
                .next()
                .and_then(|v| v.parse::<u16>().ok())
                .ok_or(CertFormatError)?;
            orport = args
                .next()
                .and_then(|v| v.parse::<u16>().ok())
                .ok_or(CertFormatError)?;
        }

        let mut contact = None;
        let mut vote_digest = None::<Sha1Output>;

        self.item = Some(loop {
            let item = self.inner.next().ok_or(CertFormatError)??;

            match item.keyword() {
                // contact is exactly once and takes the rest of the line
                "contact" => {
                    if contact.is_some() {
                        return Err(CertFormatError.into());
                    }
                    contact = Some(item.arguments_raw());
                }
                // vote-digest is exactly once
                "vote-digest" => {
                    if vote_digest.is_some() {
                        return Err(CertFormatError.into());
                    }
                    vote_digest = Some(
                        item.arguments()
                            .next()
                            .and_then(parse_hex)
                            .ok_or(CertFormatError)?,
                    );
                }
                // dir-source is the beginning of directory authority entry
                "dir-source" => break item,
                // r is the beginning of relay data
                "r" => break item,
                // Unknown keyword, skip
                _ => (),
            }
        });

        let (Some(contact), Some(vote_digest)) = (contact, vote_digest) else {
            return Err(CertFormatError.into());
        };

        Ok(Some(AuthorityEntry {
            nickname,
            identity,
            address,
            ip,
            dirport,
            orport,
            contact,
            vote_digest,
        }))
    }

    fn to_relay(&mut self) -> RelayEntryParserInner<'a> {
        let kw = self
            .item
            .as_ref()
            .expect("iteration must not errored")
            .keyword();
        debug_assert!(
            kw == "r" || kw == "dir-source",
            "{kw} is neither \"r\" or \"dir-source\""
        );
        assert!(kw == "r", "there are more authority entry to be processed");

        RelayEntryParserInner {
            item: self.item.clone(),
            inner: self.inner.clone(),
        }
    }
}

impl<'a> Iterator for AuthorityEntryParserInner<'a> {
    type Item = Result<AuthorityEntry<'a>, ConsensusParseError>;

    fn next(&mut self) -> Option<Self::Item> {
        let ret = self.parse();
        if ret.is_err() {
            self.item = None;
        }
        ret.transpose()
    }
}

impl FusedIterator for AuthorityEntryParserInner<'_> {}

#[derive(Clone)]
pub struct ConsensusAuthorityEntryParser<'a>(AuthorityEntryParserInner<'a>);

impl<'a> ConsensusAuthorityEntryParser<'a> {
    /// Starts processing relay entries.
    ///
    /// # Panic
    ///
    /// Panics if iteration is not finished or errored.
    pub fn to_relay(&mut self) -> ConsensusRelayEntryParser<'a> {
        ConsensusRelayEntryParser(self.0.to_relay())
    }
}

impl<'a> Iterator for ConsensusAuthorityEntryParser<'a> {
    type Item = Result<AuthorityEntry<'a>, ConsensusParseError>;

    fn next(&mut self) -> Option<Self::Item> {
        self.0.next()
    }
}

impl FusedIterator for ConsensusAuthorityEntryParser<'_> {}

#[derive(Clone)]
pub struct MicrodescAuthorityEntryParser<'a>(AuthorityEntryParserInner<'a>);

impl<'a> MicrodescAuthorityEntryParser<'a> {
    /// Starts processing relay entries.
    ///
    /// # Panic
    ///
    /// Panics if iteration is not finished.
    pub fn to_relay(&mut self) -> MicrodescRelayEntryParser<'a> {
        MicrodescRelayEntryParser(self.0.to_relay())
    }
}

impl<'a> Iterator for MicrodescAuthorityEntryParser<'a> {
    type Item = Result<AuthorityEntry<'a>, ConsensusParseError>;

    fn next(&mut self) -> Option<Self::Item> {
        self.0.next()
    }
}

impl FusedIterator for MicrodescAuthorityEntryParser<'_> {}

/// Parser for relay entries.
#[derive(Clone)]
#[non_exhaustive]
pub enum RelayEntryParser<'a> {
    /// Vanilla consensus flavor.
    Consensus(ConsensusRelayEntryParser<'a>),
    /// Microdesc consensus flavor.
    Microdesc(MicrodescRelayEntryParser<'a>),
}

#[derive(Clone)]
struct RelayEntryParserInner<'a> {
    item: Option<NetdocItem<'a>>,
    inner: NetdocParser<'a>,
}

struct RelayEntryInner<'a> {
    pub nickname: &'a str,
    pub identity: RelayId,
    pub digest: Option<Sha1Output>,
    pub publication: SystemTime,
    pub ip: Ipv4Addr,
    pub dirport: Option<NonZeroU16>,
    pub orport: u16,
    pub addr: Option<SocketAddrV6>,
    pub status: Option<NetdocArguments<'a>>,
    pub version: Option<&'a str>,
    pub protocols: Option<NetdocArguments<'a>>,
    pub bandwidth: Option<BandwidthEstimate>,
    pub exit_ports: Option<ExitPortPolicy>,
    pub microdesc: Option<Sha256Output>,
}

impl<'a> RelayEntryParserInner<'a> {
    fn parse(
        &mut self,
        flavor: Flavor,
    ) -> Result<Option<RelayEntryInner<'a>>, ConsensusParseError> {
        let Some(item) = self.item.as_ref() else {
            return Ok(None);
        };
        if item.keyword() != "r" {
            // Entry does not start with r, possibly ending.
            return Ok(None);
        }

        let nickname;
        let identity: RelayId;
        let mut digest = None::<Sha1Output>;
        let publication;
        let ip;
        let dirport;
        let orport;

        {
            let mut args = item.arguments();
            nickname = args.next().ok_or(CertFormatError)?;
            identity = args.next().ok_or(CertFormatError).and_then(parse_b64u)?;
            if flavor == Flavor::Consensus {
                digest = Some(args.next().ok_or(CertFormatError).and_then(parse_b64)?);
            }
            publication = SystemTime::from(args_date_time(&mut args).ok_or(CertFormatError)?);
            ip = args
                .next()
                .and_then(|v| v.parse::<Ipv4Addr>().ok())
                .ok_or(CertFormatError)?;
            orport = args
                .next()
                .and_then(|v| v.parse::<u16>().ok())
                .ok_or(CertFormatError)?;
            dirport = NonZeroU16::new(
                args.next()
                    .and_then(|v| v.parse::<u16>().ok())
                    .ok_or(CertFormatError)?,
            );
        }

        let mut addr = None;
        let mut status = None;
        let mut version = None;
        let mut protocols = None;
        let mut bandwidth = None;
        let mut exit_ports = None;
        let mut microdesc = None;

        self.item = Some(loop {
            let item = self.inner.next().ok_or(CertFormatError)??;

            match dbg!(item.keyword()) {
                // a can be any number
                "a" => {
                    let a = item
                        .arguments()
                        .next()
                        .and_then(|v| v.parse::<SocketAddr>().ok())
                        .ok_or(CertFormatError)?;
                    if addr.is_none()
                        && let SocketAddr::V6(a) = a
                    {
                        addr = Some(a);
                    }
                }
                // s is exactly once
                "s" => {
                    if status.is_some() {
                        return Err(CertFormatError.into());
                    }
                    status = Some(item.arguments());
                }
                // v is at most once and takes the rest of the line
                "v" => {
                    if version.is_some() {
                        return Err(CertFormatError.into());
                    }
                    version = Some(item.arguments_raw());
                }
                // pr is exactly once
                "pr" => {
                    if protocols.is_some() {
                        return Err(CertFormatError.into());
                    }
                    protocols = Some(item.arguments());
                }
                // w is at most once
                "w" => {
                    if bandwidth.is_some() {
                        return Err(CertFormatError.into());
                    }
                    bandwidth = Some(parse_bandwidth(&item)?);
                }
                // p is at most once
                "p" if flavor == Flavor::Consensus => {
                    if exit_ports.is_some() {
                        return Err(CertFormatError.into());
                    }
                    exit_ports = Some(args_exit_policy(&mut item.arguments())?);
                }
                // m is exactly once
                "m" if flavor == Flavor::Microdesc => {
                    if microdesc.is_some() {
                        return Err(CertFormatError.into());
                    }
                    microdesc = Some(
                        item.arguments()
                            .next()
                            .ok_or(CertFormatError)
                            .and_then(parse_b64u)?,
                    );
                }
                // r is the beginning of relay data
                "r" => break item,
                // directory-footer is the beginning of footer entry
                "directory-footer" => break item,
                // Unknown keyword, skip
                _ => (),
            }
        });

        Ok(Some(RelayEntryInner {
            nickname,
            identity,
            digest,
            publication,
            ip,
            dirport,
            orport,
            addr,
            status,
            version,
            protocols,
            bandwidth: bandwidth.flatten(),
            exit_ports,
            microdesc,
        }))
    }

    fn to_footer(&mut self) -> Result<FooterData<'a>, ConsensusParseError> {
        let kw = self
            .item
            .as_ref()
            .expect("iteration must not errored")
            .keyword();
        debug_assert!(
            kw == "r" || kw == "directory-footer",
            "{kw} is neither \"r\" or \"directory-footer\""
        );
        assert!(
            kw == "directory-footer",
            "there are more relay entry to be processed"
        );

        let mut bandwidth_weights = None;

        for item in self.inner.clone() {
            let item = item?;

            // Currently only one footer item exists.
            #[allow(clippy::single_match)]
            match item.keyword() {
                // bandwidth-weights is at most once
                "bandwidth-weights" => {
                    if bandwidth_weights.is_some() {
                        return Err(CertFormatError.into());
                    }
                    bandwidth_weights = Some(item.arguments());
                }
                // Unknown keyword, skip
                _ => (),
            }
        }

        Ok(FooterData { bandwidth_weights })
    }
}

/// A single relay entry.
#[derive(Clone)]
#[non_exhaustive]
pub enum RelayEntry<'a> {
    /// Vanilla consensus flavor.
    Consensus(ConsensusRelayEntry<'a>),
    /// Microdesc consensus flavor.
    Microdesc(MicrodescRelayEntry<'a>),
}

/// Consensus footer data.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct FooterData<'a> {
    /// Bandwidth weights.
    pub bandwidth_weights: Option<NetdocArguments<'a>>,
}

impl<'a> RelayEntryParser<'a> {
    /// Gets the directory footer.
    ///
    /// # Panic
    ///
    /// Panics if iteration is not finished or errored.
    pub fn to_footer(&mut self) -> Result<FooterData<'a>, ConsensusParseError> {
        let (Self::Consensus(ConsensusRelayEntryParser(v))
        | Self::Microdesc(MicrodescRelayEntryParser(v))) = self;
        v.to_footer()
    }
}

impl<'a> Iterator for RelayEntryParser<'a> {
    type Item = Result<RelayEntry<'a>, ConsensusParseError>;

    fn next(&mut self) -> Option<Self::Item> {
        match self {
            Self::Consensus(v) => v.next().map(|v| v.map(RelayEntry::Consensus)),
            Self::Microdesc(v) => v.next().map(|v| v.map(RelayEntry::Microdesc)),
        }
    }
}

impl FusedIterator for RelayEntryParser<'_> {}

#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct ConsensusRelayEntry<'a> {
    pub nickname: &'a str,
    pub identity: RelayId,
    pub digest: Sha1Output,
    pub publication: SystemTime,
    pub ip: Ipv4Addr,
    pub dirport: Option<NonZeroU16>,
    pub orport: u16,
    pub addr: Option<SocketAddrV6>,
    pub status: NetdocArguments<'a>,
    pub version: Option<&'a str>,
    pub protocols: NetdocArguments<'a>,
    pub bandwidth: Option<BandwidthEstimate>,
    pub exit_ports: Option<ExitPortPolicy>,
}

#[derive(Clone)]
pub struct ConsensusRelayEntryParser<'a>(RelayEntryParserInner<'a>);

impl<'a> ConsensusRelayEntryParser<'a> {
    /// Gets the directory footer.
    ///
    /// # Panic
    ///
    /// Panics if iteration is not finished or errored.
    pub fn to_footer(&mut self) -> Result<FooterData<'a>, ConsensusParseError> {
        self.0.to_footer()
    }
}

impl<'a> ConsensusRelayEntryParser<'a> {
    fn parse(&mut self) -> Result<Option<ConsensusRelayEntry<'a>>, ConsensusParseError> {
        let Some(RelayEntryInner {
            nickname,
            identity,
            digest,
            publication,
            ip,
            dirport,
            orport,
            addr,
            status,
            version,
            protocols,
            bandwidth,
            exit_ports,
            ..
        }) = self.0.parse(Flavor::Consensus)?
        else {
            return Ok(None);
        };

        let (Some(status), Some(protocols)) = (status, protocols) else {
            return Err(CertFormatError.into());
        };

        Ok(Some(ConsensusRelayEntry {
            nickname,
            identity,
            digest: digest.expect("digest must exist"),
            publication,
            ip,
            dirport,
            orport,
            addr,
            status,
            version,
            protocols,
            bandwidth,
            exit_ports,
        }))
    }
}

impl<'a> Iterator for ConsensusRelayEntryParser<'a> {
    type Item = Result<ConsensusRelayEntry<'a>, ConsensusParseError>;

    fn next(&mut self) -> Option<Self::Item> {
        let ret = self.parse();
        if ret.is_err() {
            self.0.item = None;
        }
        ret.transpose()
    }
}

impl FusedIterator for ConsensusRelayEntryParser<'_> {}

#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct MicrodescRelayEntry<'a> {
    pub nickname: &'a str,
    pub identity: RelayId,
    pub publication: SystemTime,
    pub ip: Ipv4Addr,
    pub dirport: Option<NonZeroU16>,
    pub orport: u16,
    pub addr: Option<SocketAddrV6>,
    pub status: NetdocArguments<'a>,
    pub version: Option<&'a str>,
    pub protocols: NetdocArguments<'a>,
    pub bandwidth: Option<BandwidthEstimate>,
    pub microdesc: Sha256Output,
}

#[derive(Clone)]
pub struct MicrodescRelayEntryParser<'a>(RelayEntryParserInner<'a>);

impl<'a> MicrodescRelayEntryParser<'a> {
    /// Gets the directory footer.
    ///
    /// # Panic
    ///
    /// Panics if iteration is not finished or errored.
    pub fn to_footer(&mut self) -> Result<FooterData<'a>, ConsensusParseError> {
        self.0.to_footer()
    }
}

impl<'a> MicrodescRelayEntryParser<'a> {
    fn parse(&mut self) -> Result<Option<MicrodescRelayEntry<'a>>, ConsensusParseError> {
        let Some(RelayEntryInner {
            nickname,
            identity,
            publication,
            ip,
            dirport,
            orport,
            addr,
            status,
            version,
            protocols,
            bandwidth,
            microdesc,
            ..
        }) = self.0.parse(Flavor::Microdesc)?
        else {
            return Ok(None);
        };

        let (Some(status), Some(protocols), Some(microdesc)) = (status, protocols, microdesc)
        else {
            return Err(CertFormatError.into());
        };

        Ok(Some(MicrodescRelayEntry {
            nickname,
            identity,
            publication,
            ip,
            dirport,
            orport,
            addr,
            status,
            version,
            protocols,
            bandwidth,
            microdesc,
        }))
    }
}

impl<'a> Iterator for MicrodescRelayEntryParser<'a> {
    type Item = Result<MicrodescRelayEntry<'a>, ConsensusParseError>;

    fn next(&mut self) -> Option<Self::Item> {
        let ret = self.parse();
        if ret.is_err() {
            self.0.item = None;
        }
        ret.transpose()
    }
}

impl FusedIterator for MicrodescRelayEntryParser<'_> {}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum BandwidthEstimate {
    Bandwidth(u64),
    Unmeasured,
}

fn parse_srv(item: &NetdocItem<'_>) -> Result<Srv, CertFormatError> {
    let mut args = item.arguments();
    Ok(Srv {
        n_commits: args
            .next()
            .and_then(|v| v.parse().ok())
            .ok_or(CertFormatError)?,
        val: args.next().ok_or(CertFormatError).and_then(parse_b64)?,
    })
}

fn parse_bandwidth(item: &NetdocItem<'_>) -> Result<Option<BandwidthEstimate>, CertFormatError> {
    let mut ret = None;
    for arg in item.arguments() {
        let (k, v) = arg.split_once('=').unwrap_or((arg, ""));
        match k {
            "Bandwidth" => {
                let bw = BandwidthEstimate::Bandwidth(v.parse().map_err(|_| CertFormatError)?);
                // XXX: Bandwidth overrides Unmeasured?
                if matches!(ret, None | Some(BandwidthEstimate::Unmeasured)) {
                    ret = Some(bw);
                }
            }
            "Unmeasured" => {
                if v != "1" {
                    return Err(CertFormatError);
                } else if ret.is_none() {
                    ret = Some(BandwidthEstimate::Unmeasured);
                }
            }
            _ => (),
        }
    }
    Ok(ret)
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::net::Ipv6Addr;
    use std::time::Duration;

    #[test]
    fn test_extract_signature_example() {
        let document = r"
directory-footer
bandwidth-weights Wbd=1113 Wbe=0 Wbg=4125 Wbm=10000 Wdb=10000 Web=10000 Wed=7774 Wee=10000 Weg=7774 Wem=10000 Wgb=10000 Wgd=1113 Wgg=5875 Wgm=5875 Wmb=10000 Wmd=1113 Wme=0 Wmg=4125 Wmm=10000
";
        let sigs = [
            (
                "0232AF901C31A04EE9848595AF9BB7620D4C5B2E",
                "DBC44B8640348CF9B2C152A6A09173810DF2C3B2",
            ),
            (
                "23D15D965BC35114467363C165C4F724B64B4F66",
                "E3FF1BECB2667D1220838562CBAE41BC07C97720",
            ),
            (
                "27102BC123E7AF1D4741AE047E160C91ADC76B21",
                "A90483D3F5FFC0ECB68142305BAE4E8D27112D13",
            ),
            (
                "2F3DF9CA0E5D36F2685A2DA67184EB8DCB8CBA8C",
                "A0072D9B9E5885934EBB7A5F7F2B4F12C42FDC6A",
            ),
            (
                "49015F787433103580E3B66A1707A00E60F2D15B",
                "C5D153A6F0DA7CC22277D229DCBBF929D0589FE0",
            ),
            (
                "70849B868D606BAECFB6128C5E3D782029AA394F",
                "66450746462288244BC4FB0A7B28A8BA401D7ED9",
            ),
            (
                "E8A9C45EDE6D711294FADF8E7951F4DE6CA56B58",
                "55B24799F423AE6DFEA4A6CC6E33A81D8E51DEC9",
            ),
            (
                "ED03BB616EB2F60BEC80151114BB25CEF515B226",
                "78144C53B9C9CD541D11CC5F0FAF4313018DD9E1",
            ),
            (
                "F533C81CEF0BC0267857C99B2F471ADF249FA232",
                "DA1C03942B54B8F629973E67639754198912B6DB",
            ),
        ];
        // Taken from somewhere
        let s = r"
directory-footer
bandwidth-weights Wbd=1113 Wbe=0 Wbg=4125 Wbm=10000 Wdb=10000 Web=10000 Wed=7774 Wee=10000 Weg=7774 Wem=10000 Wgb=10000 Wgd=1113 Wgg=5875 Wgm=5875 Wmb=10000 Wmd=1113 Wme=0 Wmg=4125 Wmm=10000
directory-signature sha256 0232AF901C31A04EE9848595AF9BB7620D4C5B2E DBC44B8640348CF9B2C152A6A09173810DF2C3B2
-----BEGIN SIGNATURE-----
QQ/XcxgSohkTcAnPigjzDm3gkEacxjwXFdDVnupHAZvH+hExseiPZAm3AThZ7slD
zs94ivBikNHzuMA5uKulF81NdYPp9NfJ0zzC5XWxYUN3XN1TZm93uUCBRRdoR9uF
d8HCUgze14dcYbLW1vinPOith95NjaLvcsmd7hk9whU5wqNOMDTmLQZ+k0FzSY7d
NYsIctZWcq6fuNvzT+XWfFTtYqS0pwZbVHAyjlqR8E2biL4WjehC3ognipNOoJcF
BUNlI5OHZ4FPyZ8IU09kPFakxAgextLOrV5C6BfVXPJHpHANWzM6p2ToCADXYmrO
BL8969ItR3sUbj+01hvS5A==
-----END SIGNATURE-----
directory-signature sha256 23D15D965BC35114467363C165C4F724B64B4F66 E3FF1BECB2667D1220838562CBAE41BC07C97720
-----BEGIN SIGNATURE-----
NZY/2jWXlZiH26uov4f2Q8H9J0Zi/gsiELvfG2vK2ShAlxCntRwOgfZ5njXajK7b
pIPKsCbafMs1WM9vK8sZpEujCccdGfEnbM/CUHebdkZq8Eb6ux0Y5zx42TtsUjeJ
uxKkeuxLEvGmXYU4qwX4Wk4EhWt78W1zTevMnwh0qSHpp6+IDsmNxSfy3AXcT+y3
dJmTloQXcFZ4oEGoTprUdBjKxEb98RkSthEWeo8XrxTW5LjKzCHCGvs49VUWbX68
iLpuaub5bFtn09c3cXYTpRBoDMHyDawcCR5lLprCEw/J5dCSP2kM2h8oToYBRodz
3apJqdg0dZcWrQ/2KxKRgw==
-----END SIGNATURE-----
directory-signature sha256 27102BC123E7AF1D4741AE047E160C91ADC76B21 A90483D3F5FFC0ECB68142305BAE4E8D27112D13
-----BEGIN SIGNATURE-----
Gf7TGKZkWg0gHJOSL06Bw8L7nQ3fvH1NdVrxYqcjs0jkD8tWvSEZ6qZMueENEXbJ
E1D6r/Kufz1Mi1Uk8IVSB8xgz/IU6QLA0pHvASWHVLzFY1v3NEqFSPNKkvJy+oEP
upjtWRa1ccxnIUlFZn49uWGVrwgT7R0lnOxUve+1MKtMWp4BohDSdzLpr5r2eqMc
e009S/eZ1+fy6eTNRv1qlPhYHowMh9wUGHxBHfLj/1aXtuGvqxssGdfuuklg5oEr
pFxtOsL25Z3RC2VKC6jLa5A8ySoZIAQr2c5YpsywD14EI/t/8jf5W2cqyeEP+k+d
8ymusESK9Ybi1qxh1uMWGA==
-----END SIGNATURE-----
directory-signature sha256 2F3DF9CA0E5D36F2685A2DA67184EB8DCB8CBA8C A0072D9B9E5885934EBB7A5F7F2B4F12C42FDC6A
-----BEGIN SIGNATURE-----
j/1tckl5eGm8N2x7Fxg2lLcvf9CC6aa5KcKdz122ddSXf6G+cLM3Kkw68s/dPdWS
2MkoKn0kbbxg6ohoV7/FV2ohEiPGe2ibisXrYwgfq409gGrFwGOwyhlEUM9+H787
mzrwnV6stbUyePx3WxZ5HoyGyXSmX23960vuTmwoqQCYRohogL75Nrmuu0gJ71hm
jYhNv2+YQeZHDXhowN+j9oHnU0DT2jyD96SqsvLQ0Ek4sh46w1MwtOfluRgqQWPA
p7foRLA6xGveBvui3I42h/nJ2IceapmMq7ak9buJDRJL1O2fN0BzSxm+8HJUyy1L
31bEsFQn/mn2ZIyc1yr3O99K94MQJaZNQ9+6WtVl+xjSyPvv5vFGk8TsCKVEotLy
8PFXVFlrl7HY4KwAWmvD4M49aHrcYmD9/wtKVUUSQxDd0RGc+HaHtc3L1Xmxkm+D
MrSR0X507Kh6mAiP1FYuk4yBmv0Auc6Hy558g0WbgSRDL8fvgY6bo843LGaJEJoN
-----END SIGNATURE-----
directory-signature sha256 49015F787433103580E3B66A1707A00E60F2D15B C5D153A6F0DA7CC22277D229DCBBF929D0589FE0
-----BEGIN SIGNATURE-----
jUzHbpiVntvIG9k80ouguiNzH5k6+sSk5eVRDqaMKFdy2yRxljeSwog4vy7MFhkt
Q/esctAk45HNgRp9ff9QiL9LIykKJ+3wzAoMtMIUU8v8xLw1g1oBAh3bNPcCUaCK
TzByRyW98Vd1Lkx5UTD3SP0ev8Pd+dePhPCAtOU6uDjPdjtMIKB7J8cuIlsJSVWH
W9J2eD3sVzTGMmWTN8OuPqvYzMIj4JQQN6Ydup3kLqRBAgA9puuJHfOyc3qwXUp4
CTSY1WII/5jzUF0tvU7T/MhaU9V4FTWisdclRK8XiJEv20mxxdUxbJaJ9p4LWj8l
C6Znb8wOs+zzx1gPPhZXMQ==
-----END SIGNATURE-----
directory-signature sha256 70849B868D606BAECFB6128C5E3D782029AA394F 66450746462288244BC4FB0A7B28A8BA401D7ED9
-----BEGIN SIGNATURE-----
GQj848AEUOakJUWEplFWGpxtdNLzenS/DzExjy6AM5X4OCtifsU8Ta/ARqOkGkVp
K/3v72QArUBKIihPnp3yFfziJijfrO+vAAMkUZu9a5dy8a82AzLEtI+2/fz0A/X3
jjaMeB/5dCqd2Uyr9TJsKtis+0CmQhAa8NoTJDIE7DrpzWLsIgmgxmQsVoNj0z6L
awtvevEI0/zXzej7XFof1DiuNb162W18uH282p09esj+jIY18/An9XYJvdFj2e90
lePuLkUZ99DkHg1M00IuOeJZXM8J9lL+z0KaI+5lqyvWEgbjOFlAwc0EEf7q7/W/
lqMmn5Q+z+5Yy6SfwgycZg==
-----END SIGNATURE-----
directory-signature sha256 E8A9C45EDE6D711294FADF8E7951F4DE6CA56B58 55B24799F423AE6DFEA4A6CC6E33A81D8E51DEC9
-----BEGIN SIGNATURE-----
byMvgxZrqR8KbC6BKdf4WkuTNTDw1Y6MvDjaB2+svO01mOk7Txr+eN70WO2yBVoS
yy8IlXyJtihp1r0c6NeoCzhGufx9iOnT2tPDpgUFnYWLFl0S0Q8rHYZjh51t9ENm
rw78wiC4oNqkTdGMMaNjEjABHNx5xTSKeKC182k/n3FZL7Fay6g0P1+V+oLAHFMn
2wYGw1TzXXiw0Zfr9luwG/iia6UWJaUOhc6cRJCBdPRQ2bTMQFDFe1zzG2dUJZPo
qPOj7ZaHizH8p5fD1Oi28FUcU455fIQKU0weuUZxn3LIPIBDGnAaavrux9Ew2+fO
nDrAjaEcgAz4yvceJ8s0pg==
-----END SIGNATURE-----
directory-signature sha256 ED03BB616EB2F60BEC80151114BB25CEF515B226 78144C53B9C9CD541D11CC5F0FAF4313018DD9E1
-----BEGIN SIGNATURE-----
XCbGEfe5HM/STF09+Y7UxRb8iUDCt5/hzF45CzWdjb2lJJLOHWMwUbyysGItvUuR
4eMBREiEgGwWqS+6uC3CbDEgmkZ77RKZCOEAwwOdZ9YEf+LxlkGri8NZ9CKhtDZc
zb8A7uyn4qdoHMXMUJJS3ecAOwQv3ZLUTDvTIxI2c65lBB+pIUZO645YMHvvyTXG
8bJ6jkbEVsBydbqbCGuMhd/zh6a174QmvW6wWBPcBU/VfMK7wKN0mAlYRLV5b/7R
dM5+nfiRutVYndxtMbNDpS5ZJAgWp/JZ2jSHeZqsJLmfX/NGvM6XjeuuueKq0lXJ
ODlUW3vtQit6l/wv8KUzJg==
-----END SIGNATURE-----
directory-signature sha256 F533C81CEF0BC0267857C99B2F471ADF249FA232 DA1C03942B54B8F629973E67639754198912B6DB
-----BEGIN SIGNATURE-----
rqpgFLLW+8YL9vBQBnEAkPGsIruAkjEdx6abHE+4DRyS6+/aqzP9nsLP8ZVbwULt
wwlRqqdCm2wZt7e6c8DRoIBO1Pwq4HZE+x3z0icWYfaCEX3Z/PdlbfsoTLxOJRR3
FLq0hoIB95oQ7+64W2DJBob8FOnhjtDi/OmPETCvW3dzdPSmLTVZYOXOC7otAR3i
q3o+qOjhjXIT/oL90VPntpTdxri6m+eOqK+e/aqYFYr5WO+1CV7uJSQwX9mzhZX5
bQvhIDrHDXk1P/tCj3SdliUM1uKWUUvR+7i1S2du/S+vrSxT8QV6fq4BftgTc5oR
0Q2Ma3H/20QEyGZFarcqQw==
-----END SIGNATURE-----
";

        let mut tmp = [const { MaybeUninit::uninit() }; 9];
        let res = parse_consensus_signature(s, &mut tmp).unwrap();
        assert_eq!(res.document, document);
        assert_eq!(res.sigs.len(), 9);

        res.sigs.sort_unstable();
        for (i, v) in res.sigs.iter().enumerate() {
            let s = sigs[i];
            assert_eq!(v.algorithm, "sha256");
            assert_eq!(v.fingerprint, parse_hex(s.0).unwrap());
            assert_eq!(v.sig_digest, parse_hex(s.1).unwrap());
        }
    }

    #[test]
    fn test_parse_consensus_example() {
        // Excerp taken from somewhere
        let s = r"
network-status-version 3 microdesc
vote-status consensus
consensus-method 33
valid-after 2026-01-17 13:00:00
fresh-until 2026-01-17 14:00:00
valid-until 2026-01-17 16:00:00
voting-delay 300 300
client-versions 0.4.8.19,0.4.8.20,0.4.8.21,0.4.9.3-alpha
server-versions 0.4.8.21,0.4.9.3-alpha
known-flags Authority BadExit Exit Fast Guard HSDir MiddleOnly NoEdConsensus Running Stable StaleDesc Sybil V2Dir Valid
recommended-client-protocols Cons=2 Desc=2 DirCache=2 FlowCtrl=1-2 HSDir=2 HSIntro=4 HSRend=2 Link=4-5 Microdesc=2 Relay=2-4
recommended-relay-protocols Cons=2 Desc=2 DirCache=2 FlowCtrl=1-2 HSDir=2 HSIntro=4-5 HSRend=2 Link=4-5 LinkAuth=3 Microdesc=2 Relay=2-4
required-client-protocols Cons=2 Desc=2 FlowCtrl=1 Link=4 Microdesc=2 Relay=2
required-relay-protocols Cons=2 Desc=2 DirCache=2 FlowCtrl=1-2 HSDir=2 HSIntro=4-5 HSRend=2 Link=4-5 LinkAuth=3 Microdesc=2 Relay=2-4
params AuthDirMaxServersPerAddr=8 CircuitPriorityHalflifeMsec=30000 DoSCircuitCreationBurst=60 DoSCircuitCreationEnabled=1 DoSCircuitCreationMinConnections=2 DoSCircuitCreationRate=2 DoSConnectionEnabled=1 DoSConnectionMaxConcurrentCount=50 DoSRefuseSingleHopClientRendezvous=1 ExtendByEd25519ID=1 KISTSchedRunInterval=3 NumNTorsPerTAP=100 UseOptimisticData=1 bwauthpid=1 bwscanner_cc=1 cbttestfreq=10 cc_alg=2 cc_cwnd_full_gap=4 cc_cwnd_full_minpct=25 cc_cwnd_inc=1 cc_cwnd_inc_rate=31 cc_cwnd_min=124 cc_sscap_exit=600 cc_sscap_onion=475 cc_sscap_sbws=600 cc_vegas_alpha_exit=186 cc_vegas_alpha_sbws=186 cc_vegas_beta_onion=372 cc_vegas_beta_sbws=248 cc_vegas_delta_exit=310 cc_vegas_delta_onion=434 cc_vegas_delta_sbws=310 cc_vegas_gamma_onion=248 cc_vegas_gamma_sbws=186 cfx_low_exit_threshold=5000 circ_max_cell_queue_size=1250 circ_max_cell_queue_size_out=1000 dos_num_circ_max_outq=5 guard-n-primary-dir-guards-to-use=2 guard-n-primary-guards-to-use=2 hs_service_max_rdv_failures=1 hsdir_spread_store=4 overload_onionskin_ntor_period_secs=10800 overload_onionskin_ntor_scale_percent=500 sendme_accept_min_version=1
shared-rand-previous-value 9 HMKI7YG0BxCTE1TPYjV2lgKkXTM14bwJIuYr/Xq3+gE=
shared-rand-current-value 9 hMftmHR6LsSrtgRRJXeiDKpN6Ju6ZYbv38DGN8TipSw=
dir-source dannenberg 0232AF901C31A04EE9848595AF9BB7620D4C5B2E dannenberg.torauth.de 193.23.244.244 80 443
contact Andreas Lehner
vote-digest D41A74A99A8AEBCEFA13973F0A09A7F5287D079E
dir-source longclaw 23D15D965BC35114467363C165C4F724B64B4F66 199.58.81.140 199.58.81.140 80 443
contact Riseup Networks <collective at riseup dot net> - 1nNzekuHGGzBYRzyjfjFEfeisNvxkn4RT
vote-digest 1780E4E1F967CC4AECA63147A61AEBFF813F6CF3
dir-source bastet 27102BC123E7AF1D4741AE047E160C91ADC76B21 204.13.164.118 204.13.164.118 80 443
contact stefani <nocat at readthefinemanual dot net> 4096/F4B863AD6642E7EE
vote-digest 3168E1837EC46170DED37F19E05056E39952E293
dir-source tor26 2F3DF9CA0E5D36F2685A2DA67184EB8DCB8CBA8C 217.196.147.77 217.196.147.77 80 443
contact Peter Palfrader
vote-digest 811477941409E9659E3089D536E627F13F4D29E7
dir-source maatuska 49015F787433103580E3B66A1707A00E60F2D15B 171.25.193.9 171.25.193.9 443 80
contact 4096R/1E8BF34923291265 Linus Nordberg <linus@nordberg.se>
vote-digest D9441E510963ED03947E4409B43D19A841903806
dir-source faravahar 70849B868D606BAECFB6128C5E3D782029AA394F faravahar.redteam.net 216.218.219.41 80 443
contact Sina Rabbani < sina redteam net >
vote-digest CF389CFDADFB29AAB7E4A56E09D698E598321247
dir-source dizum E8A9C45EDE6D711294FADF8E7951F4DE6CA56B58 45.66.35.11 45.66.35.11 80 443
contact email:usura[]sabotage.org url:https://sabotage.net proof:uri-rsa abuse:abuse[]sabotage.net twitter:adejoode ciissversion:2
vote-digest 2E0B93D9461026BF4EE070E5C28770DD7AA86593
dir-source gabelmoo ED03BB616EB2F60BEC80151114BB25CEF515B226 131.188.40.189 131.188.40.189 80 443
contact 4096R/261C5FBE77285F88FB0C343266C8C2D7C5AA446D Sebastian Hahn <tor@sebastianhahn.net>
vote-digest 932E69899E0C9B4E07691E9C0190AF21DEF321B7
dir-source moria1 F533C81CEF0BC0267857C99B2F471ADF249FA232 128.31.0.39 128.31.0.39 9231 9201
contact 1024D/EB5A896A28988BF5 arma mit edu
vote-digest 809841365F90EA21F68EC9940F39812432AAAD61
r lisdex AAAErLudKby6FyVrs1ko3b/Iq6k 2038-01-01 00:00:00 152.53.144.50 8443 0
a [2a0a:4cc0:c1:2aac::1]:8443
m jauY803ygX19rw14B2x4suqNIIMIPPbtYBAwA9UegdI
s Fast Running Stable V2Dir Valid
v Tor 0.4.8.21
pr Conflux=1 Cons=1-2 Desc=1-2 DirCache=2 FlowCtrl=1-2 HSDir=2 HSIntro=4-5 HSRend=1-2 Link=1-5 LinkAuth=1,3 Microdesc=1-2 Padding=2 Relay=1-4
w Bandwidth=72000
r SharingIsCaring AAB3U5aCNzT5U9IsI48P6F2285A 2038-01-01 00:00:00 188.195.48.170 9001 0
m ItYNOCvL6pooBr6htfS7iQux1xxsrm2o9qKyFLGCQbc
s Fast HSDir Running Stable V2Dir Valid
v Tor 0.4.8.21
pr Conflux=1 Cons=1-2 Desc=1-2 DirCache=2 FlowCtrl=1-2 HSDir=2 HSIntro=4-5 HSRend=1-2 Link=1-5 LinkAuth=1,3 Microdesc=1-2 Padding=2 Relay=1-4
w Bandwidth=370
r donottouchtheconfig AAxxlhMy3ae2qrKoj/B7DDdlD3A 2038-01-01 00:00:00 191.115.245.39 56010 0
m jt2oF+L/8nCz+Wum9MS2u+F5D7O2am5y7woCe0ZTSyY
s Fast Running Valid
v Tor 0.4.8.21
pr Conflux=1 Cons=1-2 Desc=1-2 DirCache=2 FlowCtrl=1-2 HSDir=2 HSIntro=4-5 HSRend=1-2 Link=1-5 LinkAuth=1,3 Microdesc=1-2 Padding=2 Relay=1-4
w Bandwidth=230
directory-footer
bandwidth-weights Wbd=1113 Wbe=0 Wbg=4125 Wbm=10000 Wdb=10000 Web=10000 Wed=7774 Wee=10000 Weg=7774 Wem=10000 Wgb=10000 Wgd=1113 Wgg=5875 Wgm=5875 Wmb=10000 Wmd=1113 Wme=0 Wmg=4125 Wmm=10000
";

        let (preamble, mut parser) = parse_consensus(s).unwrap();

        assert_eq!(preamble.status, "consensus");
        assert_eq!(preamble.method, 33);
        assert_eq!(
            preamble.valid_after,
            SystemTime::UNIX_EPOCH + Duration::from_secs(1768654800)
        );
        assert_eq!(
            preamble.fresh_until,
            SystemTime::UNIX_EPOCH + Duration::from_secs(1768658400)
        );
        assert_eq!(
            preamble.valid_until,
            SystemTime::UNIX_EPOCH + Duration::from_secs(1768665600)
        );
        assert_eq!(preamble.voting_delay.vote, 300);
        assert_eq!(preamble.voting_delay.dist, 300);
        assert_eq!(
            preamble.client_versions.clone().unwrap().next().unwrap(),
            "0.4.8.19,0.4.8.20,0.4.8.21,0.4.9.3-alpha"
        );
        assert_eq!(
            preamble.server_versions.clone().unwrap().next().unwrap(),
            "0.4.8.21,0.4.9.3-alpha"
        );
        assert_eq!(
            preamble.known_flags.clone().collect::<Vec<_>>(),
            [
                "Authority",
                "BadExit",
                "Exit",
                "Fast",
                "Guard",
                "HSDir",
                "MiddleOnly",
                "NoEdConsensus",
                "Running",
                "Stable",
                "StaleDesc",
                "Sybil",
                "V2Dir",
                "Valid",
            ]
        );
        assert_eq!(
            preamble
                .rec_client_proto
                .clone()
                .unwrap()
                .collect::<Vec<_>>(),
            [
                "Cons=2",
                "Desc=2",
                "DirCache=2",
                "FlowCtrl=1-2",
                "HSDir=2",
                "HSIntro=4",
                "HSRend=2",
                "Link=4-5",
                "Microdesc=2",
                "Relay=2-4",
            ]
        );
        assert_eq!(
            preamble
                .rec_relay_proto
                .clone()
                .unwrap()
                .collect::<Vec<_>>(),
            [
                "Cons=2",
                "Desc=2",
                "DirCache=2",
                "FlowCtrl=1-2",
                "HSDir=2",
                "HSIntro=4-5",
                "HSRend=2",
                "Link=4-5",
                "LinkAuth=3",
                "Microdesc=2",
                "Relay=2-4",
            ]
        );
        assert_eq!(
            preamble
                .req_client_proto
                .clone()
                .unwrap()
                .collect::<Vec<_>>(),
            [
                "Cons=2",
                "Desc=2",
                "FlowCtrl=1",
                "Link=4",
                "Microdesc=2",
                "Relay=2",
            ]
        );
        assert_eq!(
            preamble
                .req_relay_proto
                .clone()
                .unwrap()
                .collect::<Vec<_>>(),
            [
                "Cons=2",
                "Desc=2",
                "DirCache=2",
                "FlowCtrl=1-2",
                "HSDir=2",
                "HSIntro=4-5",
                "HSRend=2",
                "Link=4-5",
                "LinkAuth=3",
                "Microdesc=2",
                "Relay=2-4",
            ]
        );
        let srv = preamble.srv_prev.as_ref().unwrap();
        assert_eq!(srv.n_commits, 9);
        assert_eq!(&srv.val, b"\x1c\xc2\x88\xed\x81\xb4\x07\x10\x93\x13\x54\xcf\x62\x35\x76\x96\x02\xa4\x5d\x33\x35\xe1\xbc\x09\x22\xe6\x2b\xfd\x7a\xb7\xfa\x01");
        let srv = preamble.srv_cur.as_ref().unwrap();
        assert_eq!(srv.n_commits, 9);
        assert_eq!(&srv.val, b"\x84\xc7\xed\x98\x74\x7a\x2e\xc4\xab\xb6\x04\x51\x25\x77\xa2\x0c\xaa\x4d\xe8\x9b\xba\x65\x86\xef\xdf\xc0\xc6\x37\xc4\xe2\xa5\x2c");

        assert!(
            matches!(parser, AuthorityEntryParser::Microdesc(_)),
            "document is not a microdescriptors"
        );

        let authorities = [
            (
                "dannenberg",
                b"\x02\x32\xaf\x90\x1c\x31\xa0\x4e\xe9\x84\x85\x95\xaf\x9b\xb7\x62\x0d\x4c\x5b\x2e",
                "dannenberg.torauth.de",
                IpAddr::from([193, 23, 244, 244]),
                80,
                443,
                "Andreas Lehner",
                b"\xd4\x1a\x74\xa9\x9a\x8a\xeb\xce\xfa\x13\x97\x3f\x0a\x09\xa7\xf5\x28\x7d\x07\x9e",
            ),
            (
                "longclaw",
                b"\x23\xd1\x5d\x96\x5b\xc3\x51\x14\x46\x73\x63\xc1\x65\xc4\xf7\x24\xb6\x4b\x4f\x66",
                "199.58.81.140",
                IpAddr::from([199, 58, 81, 140]),
                80,
                443,
                "Riseup Networks <collective at riseup dot net> - 1nNzekuHGGzBYRzyjfjFEfeisNvxkn4RT",
                b"\x17\x80\xe4\xe1\xf9\x67\xcc\x4a\xec\xa6\x31\x47\xa6\x1a\xeb\xff\x81\x3f\x6c\xf3",
            ),
            (
                "bastet",
                b"\x27\x10\x2b\xc1\x23\xe7\xaf\x1d\x47\x41\xae\x04\x7e\x16\x0c\x91\xad\xc7\x6b\x21",
                "204.13.164.118",
                IpAddr::from([204, 13, 164, 118]),
                80,
                443,
                "stefani <nocat at readthefinemanual dot net> 4096/F4B863AD6642E7EE",
                b"\x31\x68\xe1\x83\x7e\xc4\x61\x70\xde\xd3\x7f\x19\xe0\x50\x56\xe3\x99\x52\xe2\x93",
            ),
            (
                "tor26",
                b"\x2f\x3d\xf9\xca\x0e\x5d\x36\xf2\x68\x5a\x2d\xa6\x71\x84\xeb\x8d\xcb\x8c\xba\x8c",
                "217.196.147.77",
                IpAddr::from([217, 196, 147, 77]),
                80,
                443,
                "Peter Palfrader",
                b"\x81\x14\x77\x94\x14\x09\xe9\x65\x9e\x30\x89\xd5\x36\xe6\x27\xf1\x3f\x4d\x29\xe7",
            ),
            (
                "maatuska",
                b"\x49\x01\x5f\x78\x74\x33\x10\x35\x80\xe3\xb6\x6a\x17\x07\xa0\x0e\x60\xf2\xd1\x5b",
                "171.25.193.9",
                IpAddr::from([171, 25, 193, 9]),
                443,
                80,
                "4096R/1E8BF34923291265 Linus Nordberg <linus@nordberg.se>",
                b"\xd9\x44\x1e\x51\x09\x63\xed\x03\x94\x7e\x44\x09\xb4\x3d\x19\xa8\x41\x90\x38\x06",
            ),
            (
                "faravahar",
                b"\x70\x84\x9b\x86\x8d\x60\x6b\xae\xcf\xb6\x12\x8c\x5e\x3d\x78\x20\x29\xaa\x39\x4f",
                "faravahar.redteam.net",
                IpAddr::from([216, 218, 219, 41]),
                80,
                443,
                "Sina Rabbani < sina redteam net >",
                b"\xcf\x38\x9c\xfd\xad\xfb\x29\xaa\xb7\xe4\xa5\x6e\x09\xd6\x98\xe5\x98\x32\x12\x47",
            ),
            (
                "dizum",
                b"\xe8\xa9\xc4\x5e\xde\x6d\x71\x12\x94\xfa\xdf\x8e\x79\x51\xf4\xde\x6c\xa5\x6b\x58",
                "45.66.35.11",
                IpAddr::from([45, 66, 35, 11]),
                80,
                443,
                "email:usura[]sabotage.org url:https://sabotage.net proof:uri-rsa abuse:abuse[]sabotage.net twitter:adejoode ciissversion:2",
                b"\x2e\x0b\x93\xd9\x46\x10\x26\xbf\x4e\xe0\x70\xe5\xc2\x87\x70\xdd\x7a\xa8\x65\x93",
            ),
            (
                "gabelmoo",
                b"\xed\x03\xbb\x61\x6e\xb2\xf6\x0b\xec\x80\x15\x11\x14\xbb\x25\xce\xf5\x15\xb2\x26",
                "131.188.40.189",
                IpAddr::from([131, 188, 40, 189]),
                80,
                443,
                "4096R/261C5FBE77285F88FB0C343266C8C2D7C5AA446D Sebastian Hahn <tor@sebastianhahn.net>",
                b"\x93\x2e\x69\x89\x9e\x0c\x9b\x4e\x07\x69\x1e\x9c\x01\x90\xaf\x21\xde\xf3\x21\xb7",
            ),
            (
                "moria1",
                b"\xf5\x33\xc8\x1c\xef\x0b\xc0\x26\x78\x57\xc9\x9b\x2f\x47\x1a\xdf\x24\x9f\xa2\x32",
                "128.31.0.39",
                IpAddr::from([128, 31, 0, 39]),
                9231,
                9201,
                "1024D/EB5A896A28988BF5 arma mit edu",
                b"\x80\x98\x41\x36\x5f\x90\xea\x21\xf6\x8e\xc9\x94\x0f\x39\x81\x24\x32\xaa\xad\x61",
            ),
        ];
        for (i, v) in (&mut parser).enumerate() {
            let v = v.unwrap();
            let a = &authorities[i];
            assert_eq!(v.nickname, a.0, "failed at index {i}");
            assert_eq!(&v.identity, a.1, "failed at index {i}");
            assert_eq!(v.address, a.2, "failed at index {i}");
            assert_eq!(v.ip, a.3, "failed at index {i}");
            assert_eq!(v.dirport, a.4, "failed at index {i}");
            assert_eq!(v.orport, a.5, "failed at index {i}");
            assert_eq!(v.contact, a.6, "failed at index {i}");
            assert_eq!(&v.vote_digest, a.7, "failed at index {i}");
        }

        let mut parser = parser.to_relay();

        let relays = [
            (
                "lisdex",
                b"\x00\x00\x04\xac\xbb\x9d\x29\xbc\xba\x17\x25\x6b\xb3\x59\x28\xdd\xbf\xc8\xab\xa9",
                2145916800,
                IpAddr::from([152, 53, 144, 50]),
                8443,
                0,
                Some(SocketAddrV6::new(Ipv6Addr::new(0x2a0a, 0x4cc0, 0x00c1, 0x2aac, 0x0000, 0x0000, 0x0000, 0x0001), 8443, 0, 0)),
                "Fast Running Stable V2Dir Valid",
                "Tor 0.4.8.21",
                "Conflux=1 Cons=1-2 Desc=1-2 DirCache=2 FlowCtrl=1-2 HSDir=2 HSIntro=4-5 HSRend=1-2 Link=1-5 LinkAuth=1,3 Microdesc=1-2 Padding=2 Relay=1-4",
                Some(BandwidthEstimate::Bandwidth(72000)),
                b"\x8d\xab\x98\xf3\x4d\xf2\x81\x7d\x7d\xaf\x0d\x78\x07\x6c\x78\xb2\xea\x8d\x20\x83\x08\x3c\xf6\xed\x60\x10\x30\x03\xd5\x1e\x81\xd2",
            ),
            (
                "SharingIsCaring",
                b"\x00\x00\x77\x53\x96\x82\x37\x34\xf9\x53\xd2\x2c\x23\x8f\x0f\xe8\x5d\xb6\xf3\x90",
                2145916800,
                IpAddr::from([188, 195, 48, 170]),
                9001,
                0,
                None,
                "Fast HSDir Running Stable V2Dir Valid",
                "Tor 0.4.8.21",
                "Conflux=1 Cons=1-2 Desc=1-2 DirCache=2 FlowCtrl=1-2 HSDir=2 HSIntro=4-5 HSRend=1-2 Link=1-5 LinkAuth=1,3 Microdesc=1-2 Padding=2 Relay=1-4",
                Some(BandwidthEstimate::Bandwidth(370)),
                b"\x22\xd6\x0d\x38\x2b\xcb\xea\x9a\x28\x06\xbe\xa1\xb5\xf4\xbb\x89\x0b\xb1\xd7\x1c\x6c\xae\x6d\xa8\xf6\xa2\xb2\x14\xb1\x82\x41\xb7",
            ),
            (
                "donottouchtheconfig",
                b"\x00\x0c\x71\x96\x13\x32\xdd\xa7\xb6\xaa\xb2\xa8\x8f\xf0\x7b\x0c\x37\x65\x0f\x70",
                2145916800,
                IpAddr::from([191, 115, 245, 39]),
                56010,
                0,
                None,
                "Fast Running Valid",
                "Tor 0.4.8.21",
                "Conflux=1 Cons=1-2 Desc=1-2 DirCache=2 FlowCtrl=1-2 HSDir=2 HSIntro=4-5 HSRend=1-2 Link=1-5 LinkAuth=1,3 Microdesc=1-2 Padding=2 Relay=1-4",
                Some(BandwidthEstimate::Bandwidth(230)),
                b"\x8e\xdd\xa8\x17\xe2\xff\xf2\x70\xb3\xf9\x6b\xa6\xf4\xc4\xb6\xbb\xe1\x79\x0f\xb3\xb6\x6a\x6e\x72\xef\x0a\x02\x7b\x46\x53\x4b\x26",
            ),
        ];

        for (i, v) in (&mut parser).enumerate() {
            let RelayEntry::Microdesc(v) = v.unwrap() else {
                panic!("relay entry is not a microdescriptor");
            };
            let r = &relays[i];
            assert_eq!(v.nickname, r.0, "failed at index {i}");
            assert_eq!(&v.identity, r.1, "failed at index {i}");
            assert_eq!(
                v.publication,
                SystemTime::UNIX_EPOCH + Duration::from_secs(r.2),
                "failed at index {i}"
            );
            assert_eq!(v.ip, r.3, "failed at index {i}");
            assert_eq!(v.dirport, NonZeroU16::new(r.5), "failed at index {i}");
            assert_eq!(v.orport, r.4, "failed at index {i}");
            assert_eq!(v.addr, r.6, "failed at index {i}");
            assert_eq!(
                v.status.clone().collect::<Vec<_>>(),
                r.7.split(' ').collect::<Vec<_>>(),
                "failed at index {i}"
            );
        }

        let footer = parser.to_footer().unwrap();
        assert_eq!(
            footer
                .bandwidth_weights
                .clone()
                .unwrap()
                .collect::<Vec<_>>(),
            [
                "Wbd=1113",
                "Wbe=0",
                "Wbg=4125",
                "Wbm=10000",
                "Wdb=10000",
                "Web=10000",
                "Wed=7774",
                "Wee=10000",
                "Weg=7774",
                "Wem=10000",
                "Wgb=10000",
                "Wgd=1113",
                "Wgg=5875",
                "Wgm=5875",
                "Wmb=10000",
                "Wmd=1113",
                "Wme=0",
                "Wmg=4125",
                "Wmm=10000",
            ]
        );
    }
}
