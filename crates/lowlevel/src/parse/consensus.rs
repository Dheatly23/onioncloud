//! (Microdescriptor) consensus parser.
//!
//! Parses and validate consensus (at `/tor/status-vote/current/consensus` or `/tor/status-vote/current/consensus-microdesc`).

use std::cmp::{Ord, Ordering, PartialEq, PartialOrd};
use std::fmt::{Debug, Display, Formatter, Result as FmtResult};
use std::iter::FusedIterator;
use std::mem::MaybeUninit;
use std::net::{IpAddr, Ipv4Addr, SocketAddr, SocketAddrV6};
use std::num::NonZeroU16;
use std::ptr::from_mut;
use std::str::FromStr;
use std::time::SystemTime;

use base64ct::{Base64, Base64Unpadded, Decoder, Encoding, Error as B64Error};
use digest::Digest;
use rsa::RsaPublicKey;
use rsa::pkcs1::der::pem::BASE64_WRAP_WIDTH;
use rsa::pkcs1v15::Pkcs1v15Sign;
use rsa::traits::SignatureScheme;
use sha1::Sha1;
use sha2::Sha256;

use super::misc::args_date_time;
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
            .then_with(|| self.algorithm.cmp(&rhs.algorithm))
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
    let sigs = unsafe { &mut *(from_mut(&mut sigs[..ix]) as *mut [ConsensusSignature<'_>]) };

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
        let s = {
            let mut d = Decoder::<Base64>::new_wrapped(sig.signature.as_bytes(), BASE64_WRAP_WIDTH)
                .map_err(map_b64_err)?;
            let tmp = tmp.get_mut(..d.remaining_len()).ok_or(CertVerifyError)?;
            d.decode(tmp).map_err(map_b64_err)?
        };

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

        Pkcs1v15Sign::new_unprefixed()
            .verify(sign_key, hash, s)
            .map_err(|_| CertVerifyError.into())
    }
}

/// Starts parsing consensus data.
///
/// Returns a [`PreambleData`] and an [`AuthorityEntryParser`].
/// Further parsing is done by iterating [`AuthorityEntryParser`].
pub fn parse_consensus(
    doc: &str,
) -> Result<(PreambleData<'_>, AuthorityEntryParser<'_>), ConsensusParseError> {
    let mut parser = NetdocParser::new(doc);

    enum Flavor {
        Consensus,
        Microdesc,
    }

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
        item,
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
#[derive(Debug)]
#[non_exhaustive]
pub struct VotingDelay {
    /// Voting delay in seconds.
    pub vote: u32,
    /// Signature delay in seconds.
    pub dist: u32,
}

/// Shared random value.
#[derive(Debug)]
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
    item: NetdocItem<'a>,
    inner: NetdocParser<'a>,
}

impl<'a> AuthorityEntryParserInner<'a> {
    fn parse(&mut self) -> Result<Option<AuthorityEntry<'a>>, ConsensusParseError> {
        if self.item.keyword() != "dir-source" {
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
            let mut args = self.item.arguments();
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

        self.item = loop {
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
        };

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
        debug_assert!(
            self.item.keyword() == "r" || self.item.keyword() == "dir-source",
            "{} is neither \"r\" or \"dir-source\"",
            self.item.keyword()
        );
        assert!(
            self.item.keyword() == "r",
            "there are more authority entry to be processed"
        );

        RelayEntryParserInner {
            item: self.item.clone(),
            inner: self.inner.clone(),
        }
    }
}

impl<'a> Iterator for AuthorityEntryParserInner<'a> {
    type Item = Result<AuthorityEntry<'a>, ConsensusParseError>;

    fn next(&mut self) -> Option<Self::Item> {
        self.parse().transpose()
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
    /// Panics if iteration is not finished.
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
    item: NetdocItem<'a>,
    inner: NetdocParser<'a>,
}

impl<'a> RelayEntryParserInner<'a> {
    fn to_footer(&mut self) -> Result<FooterData<'a>, ConsensusParseError> {
        debug_assert!(
            self.item.keyword() == "r" || self.item.keyword() == "directory-footer",
            "{} is neither \"r\" or \"directory-footer\"",
            self.item.keyword()
        );
        assert!(
            self.item.keyword() == "directory-footer",
            "there are more relay entry to be processed"
        );

        let mut bandwidth_weights = None;

        for item in self.inner.clone() {
            let item = item?;

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
    /// Panics if iteration is not finished.
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
    /// Panics if iteration is not finished.
    pub fn to_footer(&mut self) -> Result<FooterData<'a>, ConsensusParseError> {
        self.0.to_footer()
    }
}

impl<'a> ConsensusRelayEntryParser<'a> {
    fn parse(&mut self) -> Result<Option<ConsensusRelayEntry<'a>>, ConsensusParseError> {
        if self.0.item.keyword() != "r" {
            // Entry does not start with r, possibly ending.
            return Ok(None);
        }

        let nickname;
        let identity: RelayId;
        let digest: Sha1Output;
        let publication;
        let ip;
        let dirport;
        let orport;

        {
            let mut args = self.0.item.arguments();
            nickname = args.next().ok_or(CertFormatError)?;
            identity = args.next().ok_or(CertFormatError).and_then(parse_b64u)?;
            digest = args.next().ok_or(CertFormatError).and_then(parse_b64)?;
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

        self.0.item = loop {
            let item = self.0.inner.next().ok_or(CertFormatError)??;

            match item.keyword() {
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
                "p" => {
                    if exit_ports.is_some() {
                        return Err(CertFormatError.into());
                    }
                    exit_ports = Some(parse_exit_policy(&item)?);
                }
                // r is the beginning of relay data
                "r" => break item,
                // directory-footer is the beginning of footer entry
                "directory-footer" => break item,
                // Unknown keyword, skip
                _ => (),
            }
        };

        let (Some(status), Some(protocols)) = (status, protocols) else {
            return Err(CertFormatError.into());
        };

        Ok(Some(ConsensusRelayEntry {
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
        }))
    }
}

impl<'a> Iterator for ConsensusRelayEntryParser<'a> {
    type Item = Result<ConsensusRelayEntry<'a>, ConsensusParseError>;

    fn next(&mut self) -> Option<Self::Item> {
        self.parse().transpose()
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
    /// Panics if iteration is not finished.
    pub fn to_footer(&mut self) -> Result<FooterData<'a>, ConsensusParseError> {
        self.0.to_footer()
    }
}

impl<'a> MicrodescRelayEntryParser<'a> {
    fn parse(&mut self) -> Result<Option<MicrodescRelayEntry<'a>>, ConsensusParseError> {
        if self.0.item.keyword() != "r" {
            // Entry does not start with r, possibly ending.
            return Ok(None);
        }

        let nickname;
        let identity: RelayId;
        let publication;
        let ip;
        let dirport;
        let orport;

        {
            let mut args = self.0.item.arguments();
            nickname = args.next().ok_or(CertFormatError)?;
            identity = args.next().ok_or(CertFormatError).and_then(parse_b64u)?;
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
        let mut microdesc = None::<Sha256Output>;

        self.0.item = loop {
            let item = self.0.inner.next().ok_or(CertFormatError)??;

            match item.keyword() {
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
                // m is exactly once
                "m" => {
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
            bandwidth: bandwidth.flatten(),
            microdesc,
        }))
    }
}

impl<'a> Iterator for MicrodescRelayEntryParser<'a> {
    type Item = Result<MicrodescRelayEntry<'a>, ConsensusParseError>;

    fn next(&mut self) -> Option<Self::Item> {
        self.parse().transpose()
    }
}

impl FusedIterator for MicrodescRelayEntryParser<'_> {}

#[derive(Debug, Clone)]
#[non_exhaustive]
pub enum BandwidthEstimate {
    Bandwidth(u64),
    Unmeasured,
}

/// Exit port policy.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub struct ExitPortPolicy {
    /// `true` if accept.
    pub accept: bool,

    /// Ports list.
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
                let r = match (self.ports[i - 1], *v) {
                    (ExitPort::Port(a), ExitPort::Port(b)) => a != b,
                    (ExitPort::PortRange { to, .. }, ExitPort::Port(v)) => v > to,
                    (ExitPort::Port(v), ExitPort::PortRange { from, .. }) => v < from,
                    (ExitPort::PortRange { to, .. }, ExitPort::PortRange { from, .. }) => {
                        to < from && from - to > 1
                    }
                };
                if !r {
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

fn map_b64_err(e: B64Error) -> ConsensusSignatureError {
    match e {
        B64Error::InvalidEncoding => CertFormatError.into(),
        B64Error::InvalidLength => CertVerifyError.into(),
    }
}

fn parse_b64<const N: usize>(s: &str) -> Result<[u8; N], CertFormatError> {
    let mut ret = [0u8; N];
    let t = Base64::decode(s, &mut ret).map_err(|_| CertFormatError)?;
    debug_assert_eq!(t.len(), ret.len());
    Ok(ret)
}

fn parse_b64u<const N: usize>(s: &str) -> Result<[u8; N], CertFormatError> {
    let mut ret = [0u8; N];
    let t = Base64Unpadded::decode(s, &mut ret).map_err(|_| CertFormatError)?;
    debug_assert_eq!(t.len(), ret.len());
    Ok(ret)
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

fn parse_exit_policy(item: &NetdocItem<'_>) -> Result<ExitPortPolicy, CertFormatError> {
    let mut args = item.arguments();
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

fn parse_exit_ports(s: &str) -> Result<Vec<ExitPort>, CertFormatError> {
    s.split(',')
        .map(|s| {
            Ok(match s.split_once('-') {
                Some((f, t)) => ExitPort::PortRange {
                    from: f.parse()?,
                    to: t.parse()?,
                },
                None => ExitPort::Port(s.parse()?),
            })
        })
        .collect::<Result<Vec<_>, <u16 as FromStr>::Err>>()
        .map_err(|_| CertFormatError)
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::fmt::Write as _;

    use proptest::prelude::*;

    type ExitPortList = [u8; 65536 / 8];

    fn map_exit_ports(a: ExitPortList) -> Vec<ExitPort> {
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

    fn strat_exit_ports() -> impl Strategy<Value = Vec<ExitPort>> {
        any::<ExitPortList>().prop_map(map_exit_ports)
    }

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

    proptest! {
        #[test]
        fn test_exit_ports_valid(v in strat_exit_ports()) {
            let mut v = ExitPortPolicy { accept: false, ports: v };
            assert!(v.sort_validate());
        }

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
            a: ExitPortList,
            port: u16,
        ) {
            let ok = a[(port >> 3) as usize] & (1 << (port & 7)) != 0;
            let p = map_exit_ports(a);
            assert_eq!(p.iter().any(|p| p.contains(port)), ok);
            assert_eq!(ExitPort::in_ports(&p, port), ok);
        }
    }
}
