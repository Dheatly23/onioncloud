use std::fmt::{Debug, Display, Formatter, Result as FmtResult};
use std::io::{Read, Write};
use std::marker::PhantomData;
use std::net::IpAddr;
use std::pin::Pin;
use std::time::{Duration, Instant, SystemTime};

use anyhow::Error as AnyError;
use humantime::format_duration;
use onioncloud_ll::cell::cache::{CellCache, CellCacheExt};
use onioncloud_ll::cell::cell::TryFromCell;
use onioncloud_ll::cell::error::{
    CellCastError, CellFormatError, CellIsFixed, CellIsVariable, CellReadError, CellWriteError,
    NonZeroCircID, ZeroCircID,
};
use onioncloud_ll::cell::read::Reader;
use onioncloud_ll::cell::typed::{AuthChallenge, Certs, Netinfo, Versions};
use onioncloud_ll::cell::write::Writer;
use onioncloud_ll::channel::error::{ChannelError, IoError, RustlsError};
use onioncloud_ll::channel::handle::{ChannelHandle, Handle, Return};
use onioncloud_ll::error_from_enum;
use onioncloud_ll::utils::cell_rw::Config as RWConfig;
use onioncloud_ll::utils::{LinkVersion, LinkVersionNegotiateError};
use pin_project::pin_project;
use thiserror::Error;
use tracing::{info, instrument};

/// Channel handle for client.
#[pin_project(project = ClientHandleProj)]
#[derive(Debug)]
pub struct ClientHandle<R, C: CellCache> {
    cache: C,
    inner: Option<Inner<R, C>>,

    phantom: PhantomData<R>,
}

struct Inner<R, C: CellCache> {
    timeout: Instant,
    state: State,
    reader: Reader<RWConfig<C>>,
    writer: Writer<RWConfig<C>>,

    phantom: PhantomData<R>,
}

impl<R: Debug, C: CellCache + Debug> Debug for Inner<R, C> {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        f.debug_struct("Inner")
            .field("state", &self.state)
            .field("timeout", &self.timeout)
            .finish_non_exhaustive()
    }
}

#[derive(Debug, Clone, Copy)]
enum State {
    WriteVersions,
    ReadVersions,
    ReadHandshake { flags: u8 },
    WriteNetinfo,
    Main,
}

const FLAG_READ_HANDSHAKE_CERTS: u8 = 1 << 0;
const FLAG_READ_HANDSHAKE_AUTH_CHALLENGE: u8 = 1 << 1;

impl<R, C: CellCache + Clone> ChannelHandle<R> for ClientHandle<R, C> {
    type Error = ClientError;

    #[instrument(name = "ClientHandle::handle", skip_all)]
    fn handle(self: Pin<&mut Self>, mut args: Handle<R>) -> Result<Return, Self::Error> {
        if args.is_timeout() {
            info!("Channel handshake timeouts, shutting down");
            return Ok(Return::new(&args).with_shutdown());
        }

        let ClientHandleProj { cache, inner, .. } = self.project();
        let cache = &*cache;
        let this = inner.get_or_insert_with(|| {
            let mut this = Inner {
                timeout: args.time(),
                state: State::WriteVersions,
                reader: Reader::new(RWConfig::new(cache.clone())),
                writer: Writer::new(RWConfig::new(cache.clone())),

                phantom: PhantomData,
            };
            if !this.writer.maybe_receive(|| {
                Some(LinkVersion::make_versions(LinkVersion::MIN, LinkVersion::MAX).into())
            }) {
                unreachable!("receive must succeed!");
            }
            this
        });

        loop {
            match &mut this.state {
                State::WriteVersions => {
                    if this.writer.write(&mut args)? {
                        this.state = State::ReadVersions;
                    } else {
                        break;
                    }
                }
                State::ReadVersions => {
                    let mut cell = cache.cache_b(this.reader.read(&mut args)?);
                    let Some(cell) = Versions::try_from_cell(&mut cell)? else {
                        if let Some(cell) = &*cell {
                            return Err(HandshakeErrorInner::ExpectVersions {
                                id: cell.header.command.into(),
                            }
                            .into());
                        } else {
                            break;
                        }
                    };

                    let lv =
                        LinkVersion::versions_negotiate(LinkVersion::MIN, LinkVersion::MAX, &cell)?;
                    this.reader.config.set_link_version(lv);
                    this.writer.config.set_link_version(lv);
                    this.state = State::ReadHandshake { flags: 0 };
                }
                State::ReadHandshake { flags } => {
                    let mut cell = cache.cache_b(this.reader.read(&mut args)?);
                    if let Some(c) = Netinfo::try_from_cell(&mut cell)? {
                        drop(cell);
                        let c = cache.cache_b(c);

                        if cfg!(feature = "check-clock-skew") {
                            let stamp =
                                SystemTime::UNIX_EPOCH + Duration::from_secs(c.timestamp() as _);
                            let delta = match stamp.duration_since(SystemTime::now()) {
                                Ok(v) => Timedelta::Pos(v),
                                Err(v) => Timedelta::Neg(v.duration()),
                            };

                            if delta.get_dur() > Duration::from_mins(1) {
                                return Err(ClockSkewError { delta }.into());
                            }
                        }

                        let peer_ip = args.peer_addr().ip();
                        if c.my_addrs()
                            .filter_map(<Option<IpAddr>>::from)
                            .all(|ip| ip != peer_ip)
                        {
                            return Err(HandshakeErrorInner::NetinfoPeerAddrMismatch.into());
                        }

                        this.state = State::WriteNetinfo;
                    } else if let Some(cell) = Certs::try_from_cell(&mut cell)? {
                        if *flags & FLAG_READ_HANDSHAKE_CERTS != 0 {
                            return Err(HandshakeErrorInner::DuplicateCell {
                                id: Certs::ID.into(),
                            }
                            .into());
                        }
                        *flags |= FLAG_READ_HANDSHAKE_CERTS;
                    } else if let Some(cell) = AuthChallenge::try_from_cell(&mut cell)? {
                        if *flags & FLAG_READ_HANDSHAKE_AUTH_CHALLENGE != 0 {
                            return Err(HandshakeErrorInner::DuplicateCell {
                                id: Certs::ID.into(),
                            }
                            .into());
                        }
                        *flags |= FLAG_READ_HANDSHAKE_AUTH_CHALLENGE;
                    } else {
                        return Err(HandshakeErrorInner::UnexpectedCell {
                            id: (*cell)
                                .as_ref()
                                .expect("cell should not be taken")
                                .header
                                .command
                                .into(),
                        }
                        .into());
                    }
                }
                State::WriteNetinfo => {
                    this.writer.maybe_receive(|| {
                        match Netinfo::new(cache.get_cached(), 0, args.peer_addr().ip(), []) {
                            Ok(v) => Some(v.into()),
                            Err(_) => unreachable!("netinfo creation failed"),
                        }
                    });
                    if this.writer.write(&mut args)? {
                        this.state = State::Main;
                    } else {
                        break;
                    }
                }
                State::Main => break,
            }
        }

        Ok(Return::new(&args).with_timeout(Some(this.timeout)))
    }
}

#[derive(Debug)]
enum Timedelta {
    Neg(Duration),
    Pos(Duration),
}

impl Display for Timedelta {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        write!(
            f,
            "{} in the {}",
            format_duration(self.get_dur()),
            match self {
                Self::Neg(_) => "past",
                Self::Pos(_) => "future",
            }
        )
    }
}

impl Timedelta {
    fn get_dur(&self) -> Duration {
        let (Self::Neg(dur) | Self::Pos(dur)) = self;
        *dur
    }
}

/// Error type for [`ClientHandle`].
#[derive(Error, Debug)]
#[error(transparent)]
#[non_exhaustive]
pub enum ClientError {
    Any(#[from] AnyError),
    Io(#[from] IoError),
    Rustls(#[from] RustlsError),
    LinkVersionNegotiate(#[from] LinkVersionNegotiateError),
    CellFormat(#[from] CellFormatError),
    NonZeroCircID(#[from] NonZeroCircID),
    ZeroCircID(#[from] ZeroCircID),
    CellIsFixed(#[from] CellIsFixed),
    CellIsVariable(#[from] CellIsVariable),
    Handshake(#[from] HandshakeError),
    ClockSkew(#[from] ClockSkewError),
}

error_from_enum! {
    ClientError {
        else v => Self::Any(v.into()),
        ChannelError => [Io, Rustls],
        CellReadError => [Io, CellFormatError],
        CellWriteError => [Io, CellFormatError],
        CellCastError => [CellFormatError, NonZeroCircID, ZeroCircID, CellIsFixed, CellIsVariable],
    }
}

#[derive(Error, Debug)]
#[error("channel handshake error: {err}")]
pub struct HandshakeError {
    #[source]
    err: HandshakeErrorInner,
}

impl From<HandshakeErrorInner> for ClientError {
    fn from(err: HandshakeErrorInner) -> Self {
        HandshakeError { err }.into()
    }
}

#[derive(Error, Debug)]
enum HandshakeErrorInner {
    #[error("expected VERSIONS cell, got cell {id}")]
    ExpectVersions { id: CellID },
    #[error("got unexpected cell {id}")]
    UnexpectedCell { id: CellID },
    #[error("got duplicate cell {id}")]
    DuplicateCell { id: CellID },
    #[error("NETINFO peer address does not match actual connected address")]
    NetinfoPeerAddrMismatch,
}

struct CellID(u8);

impl From<u8> for CellID {
    fn from(v: u8) -> Self {
        Self(v)
    }
}

impl Debug for CellID {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        let id = match self.0 {
            Versions::ID => "VERSIONS",
            Certs::ID => "CERTS",
            _ => return Display::fmt(&self.0, f),
        };
        Display::fmt(id, f)
    }
}

impl Display for CellID {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        Debug::fmt(self, f)
    }
}

#[derive(Error, Debug)]
#[error("clock skew detected! (system clock skews by {delta})")]
pub struct ClockSkewError {
    delta: Timedelta,
}

impl ClockSkewError {
    /// Gets clock skew.
    ///
    /// To get which direction it is, use [`Self::is_skew_past`] or [`Self::is_skew_future`].
    #[inline]
    #[must_use]
    pub fn skew(&self) -> Duration {
        self.delta.get_dur()
    }

    /// Checks if clock skews to the past.
    #[inline]
    #[must_use]
    pub fn is_skew_past(&self) -> bool {
        matches!(self.delta, Timedelta::Neg(_))
    }

    /// Checks if clock skews to the future.
    #[inline]
    #[must_use]
    pub fn is_skew_future(&self) -> bool {
        matches!(self.delta, Timedelta::Pos(_))
    }
}
