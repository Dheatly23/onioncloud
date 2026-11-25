use std::fmt::{Debug, Formatter, Result as FmtResult};
use std::net::IpAddr;
use std::pin::Pin;
use std::time::{Duration, Instant, SystemTime};

use onioncloud_ll::cell::cache::{CellCache, CellCacheExt};
use onioncloud_ll::cell::cell::TryFromCell;
use onioncloud_ll::cell::read::Reader;
use onioncloud_ll::cell::typed::{AuthChallenge, Certs, Netinfo, Versions};
use onioncloud_ll::cell::write::Writer;
use onioncloud_ll::channel::handle::{ChannelHandle, Handle, Return};
use onioncloud_ll::utils::LinkVersion;
use onioncloud_ll::utils::cell_rw::Config as RWConfig;
use onioncloud_runtime::HasSpsc;
use pin_project::pin_project;
use tracing::{Span, debug, info_span, trace};

use crate::error::{ClientError, ClockSkewError, HandshakeErrorInner};
use crate::utils::Timedelta;

/// Circuit request channel buffer size.
const CIRC_REQ_BUF: usize = 8;

/// Configuration for [`ClientHandle`].
///
/// The default configuration is suitable for production system.
#[derive(Debug)]
#[must_use]
pub struct ClientConfig<R, C> {
    cache: C,
    runtime: R,
    config: InnerConfig,
}

#[derive(Debug)]
struct InnerConfig {
    check_clock_skew: bool,
    check_certs: bool,
}

impl Default for ClientConfig<(), ()> {
    fn default() -> Self {
        Self {
            cache: (),
            runtime: (),
            config: InnerConfig {
                check_clock_skew: true,
                check_certs: true,
            },
        }
    }
}

impl<R, C> ClientConfig<R, C> {
    /// Sets runtime.
    #[inline]
    pub fn runtime<R2>(self, runtime: R2) -> ClientConfig<R2, C> {
        ClientConfig {
            cache: self.cache,
            runtime,
            config: self.config,
        }
    }

    /// Sets cache.
    #[inline]
    pub fn cache<C2>(self, cache: C2) -> ClientConfig<R, C2> {
        ClientConfig {
            cache,
            runtime: self.runtime,
            config: self.config,
        }
    }

    /// Sets clock skew check.
    ///
    /// If enabled, checks clock skew and returns error if clock skews from relay.
    ///
    /// Disable this for test environment.
    #[inline]
    pub fn check_clock_skew(mut self, enable: bool) -> Self {
        self.config.check_clock_skew = enable;
        self
    }

    /// Sets clock skew check.
    ///
    /// If enabled, checks CERTS cell certificates.
    ///
    /// Disable this for test environment.
    #[inline]
    pub fn check_certs(mut self, enable: bool) -> Self {
        self.config.check_certs = enable;
        self
    }
}

impl<R, C> ClientConfig<&'_ R, C>
where
    R: HasSpsc,
    C: CellCache + Clone,
{
    /// Builds [`ClientHandle`].
    ///
    /// Returns [`ClientHandle`] and circuit request sender.
    /// Use it to open new circuit.
    pub fn build(self) -> (ClientHandle<R, C>, <R as HasSpsc>::Sender<CircRequest>) {
        let (send, recv) = self.runtime.make_spsc(CIRC_REQ_BUF);
        let handle = ClientHandle {
            inner: None,
            span: None,
            cache: self.cache,
            recv,
            config: self.config,
        };
        (handle, send)
    }
}

/// Channel handle for client.
#[pin_project(project = ClientHandleProj)]
pub struct ClientHandle<R: HasSpsc, C: CellCache> {
    cache: C,
    #[pin]
    recv: R::Receiver<CircRequest>,
    config: InnerConfig,
    inner: Option<Inner<C>>,
    span: Option<Span>,
}

impl<R, C> Debug for ClientHandle<R, C>
where
    R: HasSpsc,
    C: CellCache + Debug,
    <R as HasSpsc>::Receiver<CircRequest>: Debug,
{
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        f.debug_struct("ClientHandle")
            .field("inner", &self.inner)
            .field("config", &self.config)
            .field("cache", &self.cache)
            .field("recv", &self.recv)
            .finish_non_exhaustive()
    }
}

struct Inner<C: CellCache> {
    timeout: Instant,
    state: State,
    reader: Reader<RWConfig<C>>,
    writer: Writer<RWConfig<C>>,
}

impl<C: CellCache + Debug> Debug for Inner<C> {
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

impl<R: HasSpsc, C: CellCache + Clone> ChannelHandle<R> for ClientHandle<R, C> {
    type Error = ClientError;

    #[expect(clippy::too_many_lines)]
    fn handle(self: Pin<&mut Self>, mut args: Handle<R>) -> Result<Return, Self::Error> {
        let ClientHandleProj {
            cache,
            recv,
            config,
            inner,
            span,
        } = self.project();
        let cache = &*cache;
        let config = &*config;
        let _g = span
            .get_or_insert_with(|| info_span!("ClientHandle::handle"))
            .enter();

        if args.is_timeout() {
            debug!("Channel handshake timeouts, shutting down");
            return Ok(Return::new(&args).with_shutdown());
        }

        let this = inner.get_or_insert_with(|| {
            let mut this = Inner {
                timeout: args.time(),
                state: State::WriteVersions,
                reader: Reader::new(RWConfig::new(cache.clone())),
                writer: Writer::new(RWConfig::new(cache.clone())),
            };
            if !this.writer.maybe_receive(|| {
                Some(LinkVersion::make_versions(LinkVersion::MIN, LinkVersion::MAX).into())
            }) {
                unreachable!("receive must succeed!");
            }
            this
        });

        loop {
            trace!(state = ?this.state, "handle inner loop");
            match &mut this.state {
                State::WriteVersions => {
                    if !this.writer.write(&mut args)? {
                        break;
                    }

                    debug!("sent VERSIONS cell");
                    this.state = State::ReadVersions;
                }
                State::ReadVersions => {
                    let mut cell = cache.cache_b(this.reader.read(&mut args)?);
                    let Some(cell) = Versions::try_from_cell(&mut cell)? else {
                        if let Some(cell) = &*cell {
                            return Err(HandshakeErrorInner::ExpectVersions {
                                id: cell.header.command.into(),
                            }
                            .into());
                        }
                        break;
                    };
                    trace!("received VERSIONS cell");

                    let lv =
                        LinkVersion::versions_negotiate(LinkVersion::MIN, LinkVersion::MAX, &cell)?;
                    debug!(linkver = lv.0, "version negotiated");
                    this.reader.config.set_link_version(lv);
                    this.writer.config.set_link_version(lv);

                    this.state = State::ReadHandshake { flags: 0 };
                }
                State::ReadHandshake { flags } => {
                    let cell @ Some(_) = this.reader.read(&mut args)? else {
                        break;
                    };
                    let mut cell = cache.cache_b(cell);

                    if let Some(c) = Netinfo::try_from_cell(&mut cell)? {
                        drop(cell);
                        let c = cache.cache_b(c);
                        trace!("received NETINFO cell");

                        if config.check_clock_skew {
                            let stamp =
                                SystemTime::UNIX_EPOCH + Duration::from_secs(c.timestamp().into());
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

                        debug!("done reading peer authentication cells");
                        this.state = State::WriteNetinfo;

                        assert!(
                            this.writer.maybe_receive(|| {
                                match Netinfo::new(cache.get_cached(), 0, args.peer_addr().ip(), [])
                                {
                                    Ok(v) => Some(v.into()),
                                    Err(_) => unreachable!("netinfo creation failed"),
                                }
                            }),
                            "cannot write NETINFO cell"
                        );
                    } else if let Some(c) = Certs::try_from_cell(&mut cell)? {
                        drop(cell);
                        trace!("received CERTS cell");

                        if *flags & FLAG_READ_HANDSHAKE_CERTS != 0 {
                            return Err(HandshakeErrorInner::DuplicateCell {
                                id: Certs::ID.into(),
                            }
                            .into());
                        }
                        *flags |= FLAG_READ_HANDSHAKE_CERTS;
                    } else if let Some(c) = AuthChallenge::try_from_cell(&mut cell)? {
                        drop(cell);
                        trace!("received AUTH_CHALLENGE cell");

                        if *flags & FLAG_READ_HANDSHAKE_AUTH_CHALLENGE != 0 {
                            return Err(HandshakeErrorInner::DuplicateCell {
                                id: AuthChallenge::ID.into(),
                            }
                            .into());
                        }
                        *flags |= FLAG_READ_HANDSHAKE_AUTH_CHALLENGE;
                    } else if let Some(cell) = &*cell {
                        return Err(HandshakeErrorInner::UnexpectedCell {
                            id: cell.header.command.into(),
                        }
                        .into());
                    } else {
                        break;
                    }
                }
                State::WriteNetinfo => {
                    if !this.writer.write(&mut args)? {
                        break;
                    }

                    debug!("sent NETINFO cell. Handshake finished");
                    this.state = State::Main;
                }
                State::Main => break,
            }
        }

        Ok(Return::new(&args).with_timeout(Some(this.timeout)))
    }
}

impl<R: HasSpsc, C: CellCache> ClientHandle<R, C> {
    /// Checks if handshake has finished.
    #[must_use]
    pub fn handshake_finished(&self) -> bool {
        matches!(
            self.inner,
            Some(Inner {
                state: State::Main,
                ..
            })
        )
    }
}

/// Circuit open request.
pub struct CircRequest;
