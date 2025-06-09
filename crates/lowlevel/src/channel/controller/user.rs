use std::collections::vec_deque::VecDeque;
use std::io::{ErrorKind, Result as IoResult};
use std::mem::take;
use std::num::NonZeroU32;
use std::ops::ControlFlow;
use std::ops::ControlFlow::*;
use std::sync::Arc;
use std::time::{Duration, Instant};

use digest::Digest;
use flume::TrySendError;
use futures_channel::oneshot::{Receiver, Sender, channel};
use scopeguard::guard;
use sha2::Sha256;
use subtle::ConstantTimeEq;
use tracing::{debug, error, info, instrument, trace, warn};

use crate::cache::{Cached, CellCache, cast};
use crate::cell::auth::AuthChallenge;
use crate::cell::certs::Certs;
use crate::cell::create::Create2;
use crate::cell::destroy::{Destroy, DestroyReason};
use crate::cell::dispatch::{CellReader, CellType, WithCellConfig};
use crate::cell::netinfo::Netinfo;
use crate::cell::padding::{Padding, VPadding};
use crate::cell::versions::Versions;
use crate::cell::writer::CellWriter;
use crate::cell::{Cell, CellHeader, CellLike, FixedCell};
use crate::channel::controller::ChannelController;
use crate::channel::{
    CellMsg, CellMsgPause, ChannelConfig, ChannelInput, ChannelOutput, CircuitMap, ControlMsg,
    NewCircuit, Timeout,
};
use crate::crypto::cert::{UnverifiedEdCert, UnverifiedRsaCert, extract_rsa_from_x509};
use crate::crypto::{EdPublicKey, Sha256Output};
use crate::errors;
use crate::linkver::StandardLinkver;
use crate::util::sans_io::Handle;
use crate::util::{InBuffer, OutBuffer, print_ed, print_hex};

/// Trait for [`UserController`] configuration type.
pub trait UserConfig: ChannelConfig {
    /// Get [`CellCache`].
    ///
    /// # Implementer's Note
    ///
    /// To maximize cache utilization, cache should be as global as possible.
    fn get_cache(&self) -> Arc<dyn Send + Sync + CellCache>;
}

#[derive(Clone)]
struct LinkCfg {
    linkver: Arc<StandardLinkver>,
    cache: Arc<dyn Send + Sync + CellCache>,
}

impl WithCellConfig for LinkCfg {
    fn is_circ_id_4bytes(&self) -> bool {
        self.linkver.is_circ_id_4bytes()
    }

    fn cell_type(&self, header: &CellHeader) -> Result<CellType, errors::InvalidCellHeader> {
        self.linkver.cell_type(header)
    }
}

impl CellCache for LinkCfg {
    fn get_cached(&self) -> FixedCell {
        self.cache.get_cached()
    }

    fn cache_cell(&self, cell: FixedCell) {
        self.cache.cache_cell(cell);
    }
}

/// User channel controller.
///
/// It cannot open remote-requested circuit, only user-initiated.
///
/// # Configuration
///
/// Controller's coniguration type must implement [`UserConfig`].
///
/// # User's Notes
///
/// - Controller **does not** automatically send CREATE cell.
///
///   It is the responsibility of circuit controller to do so.
/// - Circuit controllers **must not** send any cell with circuit ID other than their own.
/// - To gracefully shutdown circuit, do the following:
///
///   1. Send DESTROY cell.
///   2. Receive and drop all cells until receiver is closed.
///
///   Controller will automatically intercept DESTROY cells to properly clean up circuit on it's end.
/// - Non-graceful circuit shutdown (AKA receiver gets dropped) will be detected in 5 seconds or upon any cell received.
pub struct UserController<Cfg> {
    link_cfg: LinkCfg,

    state: State<Cfg>,

    last_packet: Option<Instant>,
    is_timeout: bool,
}

/// [`UserController`] control messages.
pub enum UserControlMsg {
    /// Force shutdown of channel.
    Shutdown,
    /// Create new circuit.
    NewCircuit(Sender<Result<NewCircuit<CachedCell>, errors::NoFreeCircIDError>>),
}

impl UserControlMsg {
    pub fn new_circuit() -> (
        Receiver<Result<NewCircuit<CachedCell>, errors::NoFreeCircIDError>>,
        Self,
    ) {
        let (send, recv) = channel();
        (recv, Self::NewCircuit(send))
    }
}

type Reader = CellReader<LinkCfg>;
type CachedCell<C = Cell> = Cached<C, Arc<dyn Send + Sync + CellCache>>;
type CachedCellWriter<C = Cell> = CellWriter<CachedCell<C>>;

// NOTE: Controller isn't going to be moved a lot.
#[allow(clippy::large_enum_variant)]
enum State<Cfg> {
    Init {
        state: InitState,
        cfg: Arc<dyn Send + Sync + AsRef<Cfg>>,
        pending_open: VecDeque<Sender<Result<NewCircuit<CachedCell>, errors::NoFreeCircIDError>>>,
    },
    Steady(SteadyState),
    Shutdown,
}

enum InitState {
    Init,
    VersionsWrite(CellWriter<Versions>),
    ConfigRead(Reader, ConfigReadState),
    NetinfoWrite(CachedCellWriter<Netinfo>),
}

enum ConfigReadState {
    Versions,
    Certs,
    AuthChallenge,
    Netinfo,
}

struct SteadyState {
    cell_read: Reader,
    cell_write: CellWriter<CachedCell>,

    in_buffer: InBuffer<CachedCell<Option<Cell>>>,
    out_buffer: OutBuffer<CachedCell>,

    pending_open: VecDeque<Sender<Result<NewCircuit<CachedCell>, errors::NoFreeCircIDError>>>,
    pending_close: VecDeque<(NonZeroU32, DestroyReason)>,

    close_scan: Instant,
}

/// [`UserController`] circuit metadata type.
///
/// It is marked public only for [`ChannelController`] purposes.
/// It cannot be created.
pub struct CircuitMeta {
    closing: bool,

    /// Time until circuit is allowed to receive cell again.
    last_full: Instant,
    /// Backoff multiplier.
    ///
    /// Using AIMD algorithm for backoff.
    /// Every time it fails to send cell, multiply backoff by 2.
    /// Every time it succeed, reduce backoff by 1.
    /// Backoff is clamped to MAX_BACKOFF.
    backoff_mult: u8,
}

impl<Cfg: 'static + UserConfig + Send + Sync> ChannelController for UserController<Cfg> {
    type Error = errors::UserControllerError;
    type Config = Cfg;
    type ControlMsg = UserControlMsg;
    type Cell = CachedCell;
    type CircMeta = CircuitMeta;

    fn new(config: Arc<dyn Send + Sync + AsRef<Self::Config>>) -> Self {
        Self {
            link_cfg: LinkCfg {
                linkver: Default::default(),
                cache: (*config).as_ref().get_cache(),
            },

            state: State::Init {
                state: InitState::Init,
                cfg: config,
                pending_open: VecDeque::new(),
            },

            last_packet: None,
            is_timeout: false,
        }
    }
}

impl<'a, Cfg: 'static + UserConfig + Send + Sync>
    Handle<(
        ChannelInput<'a>,
        &'a mut CircuitMap<CachedCell, CircuitMeta>,
    )> for UserController<Cfg>
{
    type Return = Result<ChannelOutput, errors::UserControllerError>;

    #[instrument(level = "debug", skip_all)]
    fn handle(
        &mut self,
        (mut input, circ_map): (
            ChannelInput<'a>,
            &'a mut CircuitMap<CachedCell, CircuitMeta>,
        ),
    ) -> Self::Return {
        let last_packet = self
            .last_packet
            .get_or_insert_with(|| input.time() + IDLE_TIMEOUT);
        if self.is_timeout && *last_packet <= input.time() {
            info!("channel idled for 5 minutes, gracefully shutting down");
            self.state = State::Shutdown;
        }

        loop {
            match self.state {
                State::Init {
                    ref mut state,
                    ref cfg,
                    ref mut pending_open,
                } => match state.handle(&self.link_cfg, last_packet, cfg, &mut input)? {
                    Break(()) => break,
                    Continue(false) => (),
                    Continue(true) => {
                        debug!("channel initialization successful");

                        self.state = State::Steady(SteadyState {
                            cell_read: Reader::new(self.link_cfg.clone()),
                            cell_write: CellWriter::new_finished(),

                            in_buffer: InBuffer::new(),
                            out_buffer: OutBuffer::new(),

                            pending_open: take(pending_open),
                            pending_close: VecDeque::new(),

                            close_scan: input.time() + CLOSE_SCAN_TIMEOUT,
                        })
                    }
                },
                State::Steady(ref mut state) => {
                    return state.handle(
                        take(&mut self.is_timeout),
                        &self.link_cfg,
                        last_packet,
                        input,
                        circ_map,
                    );
                }
                State::Shutdown => {
                    let mut ret = ChannelOutput::new();
                    ret.shutdown(true);
                    return Ok(ret);
                }
            }
        }

        self.is_timeout = false;

        let mut ret = ChannelOutput::new();
        ret.timeout(*last_packet);
        // Should not receive cell messages
        ret.cell_msg_pause(true.into());
        Ok(ret)
    }
}

impl InitState {
    #[instrument(level = "debug", name = "handle_init", skip_all)]
    fn handle<Cfg: 'static + UserConfig + Send + Sync>(
        &mut self,
        link_cfg: &LinkCfg,
        last_packet: &mut Instant,
        cfg: &Arc<dyn Send + Sync + AsRef<Cfg>>,
        input: &mut ChannelInput<'_>,
    ) -> Result<ControlFlow<(), bool>, errors::UserControllerError> {
        match self {
            Self::Init => {
                let peer_addr = input.peer_addr();
                let addrs = (**cfg).as_ref().peer_addrs();
                if !addrs.contains(peer_addr) {
                    return Err(
                        errors::PeerSocketMismatchError::new(*peer_addr, addrs.into()).into(),
                    );
                }

                *self = Self::VersionsWrite(CellWriter::with_cell_config(
                    (*link_cfg.linkver).as_ref().versions_cell(),
                    &link_cfg,
                )?);
            }
            Self::VersionsWrite(w) => match write_cell(w, input)? {
                false => return Ok(Break(())),
                true => {
                    update_last_packet(last_packet, input);
                    *self =
                        Self::ConfigRead(Reader::new(link_cfg.clone()), ConfigReadState::Versions);
                }
            },
            Self::ConfigRead(r, state) => {
                let Some(cell) = read_cell(r, input)? else {
                    return Ok(Break(()));
                };
                update_last_packet(last_packet, input);
                let mut cell = link_cfg.cache.cache(Some(cell));

                match state {
                    ConfigReadState::Versions => {
                        if let Some(cell) = cast::<Versions>(&mut cell)? {
                            let linkver = (*link_cfg.linkver).as_ref();
                            linkver.versions_negotiate(cell)?;
                            debug!("version negotiated: {}", linkver.version());

                            *state = ConfigReadState::Certs;
                        }
                    }
                    ConfigReadState::Certs => {
                        if let Some(cell) = cast::<Certs>(&mut cell)? {
                            let mut cert_2 = None;
                            let mut cert_4 = None;
                            let mut cert_5 = None;
                            let mut cert_7 = None;

                            for c in &cell {
                                let p = match c.ty {
                                    2 => &mut cert_2,
                                    4 => &mut cert_4,
                                    5 => &mut cert_5,
                                    7 => &mut cert_7,
                                    _ => continue,
                                };

                                if p.is_some() {
                                    return Err(errors::CertsError::Duplicate(c.ty).into());
                                }
                                *p = Some(c.data);
                            }

                            let cfg = (**cfg).as_ref();

                            let Some(data) = cert_2 else {
                                return Err(errors::CertsError::NotFound(2).into());
                            };
                            let (pk_rsa, id) = extract_rsa_from_x509(data)?;

                            let relay_id = cfg.peer_id();
                            if id.ct_ne(relay_id).into() {
                                error!(
                                    "relay ID mismatch (expect {}, got {})",
                                    print_hex(relay_id),
                                    print_hex(&id)
                                );
                                return Err(errors::CertVerifyError.into());
                            }

                            let Some(data) = cert_7 else {
                                return Err(errors::CertsError::NotFound(7).into());
                            };
                            let pk_id = UnverifiedRsaCert::new(data)?.verify(&pk_rsa)?.key;

                            if let Some(relay_id) = cfg.peer_id_ed() {
                                if id.ct_ne(relay_id).into() {
                                    error!(
                                        "relay ED25519 ID mismatch (expect {}, got {})",
                                        print_ed(relay_id),
                                        print_ed(&pk_id),
                                    );
                                    return Err(errors::CertVerifyError.into());
                                }
                            }

                            let Some(data) = cert_4 else {
                                return Err(errors::CertsError::NotFound(4).into());
                            };
                            let unverified = UnverifiedEdCert::new(data)?;
                            let pk_sign = unverified.header.key;
                            check_cert(unverified, 4, 1, &pk_id, true)?;

                            let Some(data) = cert_5 else {
                                return Err(errors::CertsError::NotFound(5).into());
                            };
                            let unverified = UnverifiedEdCert::new(data)?;
                            let subject = unverified.header.key;
                            check_cert(unverified, 5, 3, &pk_sign, false)?;

                            let Some(link_cert) = input.link_cert() else {
                                return Err(errors::CertsError::NoLinkCert.into());
                            };
                            let hash = Sha256Output::from(Sha256::digest(link_cert));
                            if subject.ct_ne(&hash).into() {
                                error!("link certificate hash does not match");
                                return Err(errors::CertVerifyError.into());
                            }

                            debug!("link certificate authenticated");

                            *state = ConfigReadState::AuthChallenge;
                        }
                    }
                    ConfigReadState::AuthChallenge => {
                        if cast::<AuthChallenge>(&mut cell)?.is_some() {
                            *state = ConfigReadState::Netinfo;
                        }
                    }
                    ConfigReadState::Netinfo => {
                        if let Some(cell) = cast::<Netinfo>(&mut cell)? {
                            let cell = link_cfg.cache.cache(cell);
                            let peer_addr = cell.peer_addr();

                            let Some(peer_addr) = peer_addr else {
                                return Err(errors::NetinfoError::InvalidPeerAddr.into());
                            };
                            let mut addrs = (**cfg)
                                .as_ref()
                                .peer_addrs()
                                .iter()
                                .map(|a| a.ip())
                                .collect::<Vec<_>>();
                            addrs.sort_unstable();
                            addrs.dedup();
                            for a in cell.this_addrs() {
                                if addrs.binary_search(&a).is_err() {
                                    return Err(errors::NetinfoError::ThisAddrNotFound(
                                        errors::PeerIpMismatchError::new(a, addrs.into()),
                                    )
                                    .into());
                                }
                            }

                            debug!("peer NETINFO check successful");

                            *self = Self::NetinfoWrite(CellWriter::with_cell_config(
                                link_cfg.cache.cache(Netinfo::new(
                                    link_cfg.get_cached(),
                                    0,
                                    input.peer_addr().ip(),
                                    [peer_addr],
                                )),
                                &link_cfg,
                            )?);
                        }
                    }
                }

                if let Some(cell) = &*cell {
                    return Err(errors::InvalidCellHeader::with_header(&CellHeader::new(
                        cell.circuit,
                        cell.command,
                    ))
                    .into());
                }
            }
            Self::NetinfoWrite(w) => {
                return Ok(match write_cell(w, input)? {
                    false => Break(()),
                    true => Continue(true),
                });
            }
        }

        Ok(Continue(false))
    }
}

impl<Cfg: 'static + UserConfig + Send + Sync> Handle<Timeout> for UserController<Cfg> {
    type Return = Result<(), errors::UserControllerError>;

    #[instrument(level = "debug", name = "handle_timeout", skip_all)]
    fn handle(&mut self, _: Timeout) -> Self::Return {
        self.is_timeout = true;
        Ok(())
    }
}

impl<Cfg: 'static + UserConfig + Send + Sync> Handle<ControlMsg<UserControlMsg>>
    for UserController<Cfg>
{
    type Return = Result<(), errors::UserControllerError>;

    #[instrument(level = "debug", name = "handle_control", skip_all)]
    fn handle(&mut self, msg: ControlMsg<UserControlMsg>) -> Self::Return {
        match msg.0 {
            UserControlMsg::Shutdown => self.state = State::Shutdown,
            UserControlMsg::NewCircuit(msg) => match self.state {
                State::Init {
                    ref mut pending_open,
                    ..
                } => pending_open.push_back(msg),
                State::Steady(ref mut s) => s.pending_open.push_back(msg),
                State::Shutdown => (),
            },
        }

        Ok(())
    }
}

impl<Cfg: 'static + UserConfig + Send + Sync> Handle<CellMsg<CachedCell>> for UserController<Cfg> {
    type Return = Result<CellMsgPause, errors::UserControllerError>;

    #[instrument(level = "debug", name = "handle_cell", skip_all)]
    fn handle(&mut self, msg: CellMsg<CachedCell>) -> Self::Return {
        match self.state {
            State::Steady(ref mut s) => {
                s.out_buffer.push_back(msg.0);
                Ok(s.out_buffer.is_full().into())
            }
            State::Shutdown => Ok(true.into()),
            State::Init { .. } => unreachable!("init state does not create circuits"),
        }
    }
}

#[instrument(level = "debug", skip_all)]
fn write_cell<T: CellLike>(
    handler: &mut CellWriter<T>,
    input: &mut ChannelInput<'_>,
) -> IoResult<bool> {
    match handler.handle(input.writer()) {
        Ok(()) => Ok(true),
        Err(e) if e.kind() == ErrorKind::WouldBlock => Ok(false),
        Err(e) => Err(e),
    }
}

#[instrument(level = "debug", skip_all)]
fn read_cell(
    handler: &mut Reader,
    input: &mut ChannelInput<'_>,
) -> Result<Option<Cell>, errors::CellError> {
    match handler.handle(input.reader()) {
        Ok(v) => Ok(Some(v)),
        Err(errors::CellError::Io(e)) if e.kind() == ErrorKind::WouldBlock => Ok(None),
        Err(e) => Err(e),
    }
}

#[instrument(level = "debug", skip_all, fields(cert_ty, key_ty, pk = %print_ed(pk), needs_signed_by))]
fn check_cert(
    mut unverified: UnverifiedEdCert<'_>,
    cert_ty: u8,
    key_ty: u8,
    pk: &EdPublicKey,
    needs_signed_by: bool,
) -> Result<(), errors::UserControllerError> {
    unverified.header.check_type(cert_ty, key_ty)?;

    let mut signed_with = None;
    while let Some(v) = unverified.next_ext() {
        let (header, data) = v?;

        match header.ty {
            4 if signed_with.is_none() => signed_with = Some(data),
            4 => continue,
            _ => (),
        }

        if header.flags & 1 != 0 {
            error!(
                "unhandled required certificate extension field {}",
                header.ty
            );
            return Err(errors::CertVerifyError.into());
        }
    }

    if needs_signed_by && signed_with.is_none() {
        error!("certificate does not contain signed-by key extension");
        return Err(errors::CertVerifyError.into());
    }

    unverified.verify(pk)?;

    if let Some(k) = signed_with {
        if k != pk {
            error!("signed-by key does not match signing key");
            return Err(errors::CertVerifyError.into());
        }
    }

    Ok(())
}

fn option_ord_min<T: Ord>(a: Option<T>, b: Option<T>) -> Option<T> {
    match (a, b) {
        (v, None) | (None, v) => v,
        (Some(a), Some(b)) => Some(a.min(b)),
    }
}

const IDLE_TIMEOUT: Duration = Duration::from_secs(60 * 5);
const FULL_TIMEOUT: Duration = Duration::from_millis(100);
const CLOSE_SCAN_TIMEOUT: Duration = Duration::from_secs(5);
const MAX_BACKOFF: u8 = 20;

fn update_last_packet(ptr: &mut Instant, input: &ChannelInput<'_>) {
    *ptr = input.time() + IDLE_TIMEOUT;
}

const FLAG_READ: u8 = 1 << 0;
const FLAG_WRITE: u8 = 1 << 1;
const FLAG_WRITE_EMPTY: u8 = 1 << 2;

impl SteadyState {
    #[instrument(level = "debug", skip_all)]
    fn handle(
        &mut self,
        mut is_timeout: bool,
        cfg: &LinkCfg,
        last_packet: &mut Instant,
        mut input: ChannelInput<'_>,
        circ_map: &mut CircuitMap<CachedCell, CircuitMeta>,
    ) -> Result<ChannelOutput, errors::UserControllerError> {
        // Scan for close circuits
        if self.close_scan <= input.time() {
            for (&id, circuit) in circ_map.items() {
                if !circuit.meta.closing && circuit.is_closed() {
                    debug!(id, "circuit is closing");
                    circuit.meta.closing = true;
                    self.pending_close.push_back((id, DestroyReason::Internal));
                }
            }

            self.close_scan = input.time() + CLOSE_SCAN_TIMEOUT;
        }

        // Process pending open
        for send in self.pending_open.drain(..) {
            if let Err(Ok(NewCircuit { id, .. })) = send.send(
                circ_map
                    .open_with(true, cfg.is_circ_id_4bytes(), 64, |_| CircuitMeta {
                        closing: false,

                        last_full: input.time(),
                        backoff_mult: 0,
                    })
                    .map(|v| v.0),
            ) {
                circ_map.remove(id);
            }
        }

        let mut flags = 0;
        let mut full_timeout = None;
        loop {
            // Read data from stream
            if flags & FLAG_READ == 0 {
                let t;
                (flags, t) = read_handler(
                    self,
                    take(&mut is_timeout),
                    cfg,
                    last_packet,
                    &mut input,
                    circ_map,
                    flags,
                )?;
                full_timeout = option_ord_min(full_timeout, t);
            }

            // Write data into stream
            if flags & (FLAG_WRITE | FLAG_WRITE_EMPTY) == 0 {
                flags = write_handler(self, cfg, last_packet, &mut input, circ_map, flags)?;
            }

            trace!(flags, "processing");
            if flags & FLAG_READ != 0 && flags & (FLAG_WRITE | FLAG_WRITE_EMPTY) != 0 {
                break;
            }
        }

        let mut timeout = *last_packet;
        timeout = timeout.min(self.close_scan);
        if let Some(t) = full_timeout {
            // Full timeout
            timeout = timeout.min(t);
        }

        let mut ret = ChannelOutput::new();
        ret.timeout(timeout);
        // Pause cell messages if out buffer is full
        ret.cell_msg_pause(self.out_buffer.is_full().into());
        Ok(ret)
    }

    #[instrument(level = "debug", skip_all)]
    fn handle_cell(
        &mut self,
        cell: CachedCell,
    ) -> Result<CellMsgPause, errors::UserControllerError> {
        self.out_buffer.push_back(cell);
        Ok(self.out_buffer.is_full().into())
    }
}

#[inline(always)]
fn read_handler(
    this: &mut SteadyState,
    is_timeout: bool,
    cfg: &LinkCfg,
    last_packet: &mut Instant,
    input: &mut ChannelInput<'_>,
    circ_map: &mut CircuitMap<CachedCell, CircuitMeta>,
    mut flags: u8,
) -> Result<(u8, Option<Instant>), errors::UserControllerError> {
    let mut process_in = is_timeout;

    // Read data from stream
    while !this.in_buffer.is_full() {
        let Some(cell) = read_cell(&mut this.cell_read, input)? else {
            flags |= FLAG_READ;
            break;
        };
        if cell.circuit != 0 {
            update_last_packet(last_packet, input);
            this.in_buffer.push(cfg.cache.cache(Some(cell)));
            process_in = true;
            continue;
        }

        let mut cell = cfg.cache.cache(Some(cell));
        // TODO: Handle padding
        cast::<Padding>(&mut cell)?;
        cast::<VPadding>(&mut cell)?;
        cast::<Versions>(&mut cell)?;

        if let Some(cell) = &*cell {
            // NOTE: Potential protocol violation
            trace!("unhandled cell with command {} received", cell.command);
        }
    }

    let mut full_timeout = None;

    // Process in buffer.
    // Should only be done if timeout or in buffer has new data.
    if process_in {
        this.in_buffer.scan_pop(|p| {
            let mut p = guard(p, |p| match p {
                Some(v) if v.is_none() => *p = None,
                _ => (),
            });
            let Some(cell) = p.as_mut() else {
                return Ok(());
            };

            if let Some(cell) = cast::<Create2>(cell)? {
                let id = cell.circuit;
                cfg.cache.cache_cell(cell.into());
                // User controller cannot create circuit by peer
                this.pending_close.push_back((id, DestroyReason::Protocol));
                // Pending DESTROY cell, clear flag
                flags &= !FLAG_WRITE_EMPTY;
                return Ok(());
            }

            let Some(c) = cell.as_ref() else {
                return Ok(());
            };
            let id = NonZeroU32::new(c.circuit).expect("circuit ID should not be zero");
            let Some(circ) = circ_map.get(id) else {
                // Discard all unmapped circuit ID.
                debug!(id, command = c.command, "discard unmapped circuit ID cell");
                **p = None;
                return Ok(());
            };
            if circ.meta.closing {
                // Circuit closing, discard cell
                debug!(id, command = c.command, "discard closing circuit cell");
                **p = None;
                return Ok(());
            }

            if let Some(cell) = cast::<Destroy>(cell)? {
                let reason = cell.display_reason();
                debug!(id, reason = display(reason), "peer is closing circuit");
                match circ.send(cfg.cache.cache(cell.into())) {
                    Ok(()) => (),
                    Err(TrySendError::Full(_)) => warn!(
                        id,
                        reason = display(reason),
                        "cannot send DESTROY cell to handler because channel is full"
                    ),
                    // Circuit is closing while peer is closing.
                    Err(TrySendError::Disconnected(_)) => (),
                }
                circ_map.remove(id);
                return Ok(());
            }

            if circ.meta.last_full > input.time() {
                // Sender recently full
                return Ok(());
            }

            let Some(Some(cell)) = p.take().map(Cached::transpose) else {
                return Ok(());
            };

            match circ.send(cell) {
                // Success, decrease backoff
                Ok(()) => circ.meta.backoff_mult = circ.meta.backoff_mult.saturating_sub(1),
                // Full, return cell and set last full
                Err(TrySendError::Full(cell)) => {
                    **p = Some(Cached::map(cell, Some));

                    let mut mult = circ.meta.backoff_mult;
                    // Multiply backoff
                    mult = mult
                        .checked_mul(2)
                        .map_or(MAX_BACKOFF, |v| v.clamp(1, MAX_BACKOFF));

                    let t = input.time() + FULL_TIMEOUT * u32::from(mult);
                    circ.meta.backoff_mult = mult;
                    circ.meta.last_full = t;
                    full_timeout = option_ord_min(full_timeout, Some(t));

                    debug!(
                        id,
                        mult,
                        time = debug(t),
                        "cannot send cell, circuit is full"
                    );
                }
                // Circuit is closing, drop cell and close it for real
                Err(TrySendError::Disconnected(_)) => {
                    debug!(id, "cannot send cell, circuit is closing");
                    circ.meta.closing = true;

                    this.pending_close.push_back((id, DestroyReason::Internal));
                    // Pending DESTROY cell, clear flag
                    flags &= !FLAG_WRITE_EMPTY;
                }
            }

            Ok::<(), errors::UserControllerError>(())
        })?;
    }

    // Cannot receive anymore
    if this.in_buffer.is_full() {
        flags |= FLAG_READ;
    }

    Ok((flags, full_timeout))
}

#[inline(always)]
fn write_handler(
    this: &mut SteadyState,
    cfg: &LinkCfg,
    last_packet: &mut Instant,
    input: &mut ChannelInput<'_>,
    circ_map: &mut CircuitMap<CachedCell, CircuitMeta>,
    mut flags: u8,
) -> Result<u8, errors::UserControllerError> {
    loop {
        let finished = this.cell_write.is_finished();
        if !write_cell(&mut this.cell_write, input)? {
            flags |= FLAG_WRITE;
            break;
        }
        if !finished {
            // Writer just finished writing
            update_last_packet(last_packet, input);
        }

        let mut found = this.pending_close.pop_front().map(|(id, reason)| {
            let meta = circ_map.remove(id);
            debug_assert!(meta.expect("circuit must exist").closing);
            // Prepend DESTROY cell
            cfg.cache
                .cache(Destroy::new(cfg.cache.get_cached(), id, reason).into())
        });
        while found.is_none() {
            let Some(cell) = this.out_buffer.pop_front() else {
                break;
            };

            if NonZeroU32::new(cell.circuit).is_none_or(|id| !circ_map.has(id)) {
                // Unmapped circuit ID. Probably non-graceful shutdown.
                continue;
            }
            let mut cell = Cached::map(cell, Some);

            found = if let Some(cell) = cast::<Destroy>(&mut cell)? {
                circ_map.remove(cell.circuit);
                Some(cfg.cache.cache(cell.into()))
            } else {
                Cached::transpose(cell)
            };
        }

        let Some(cell) = found else {
            flags |= FLAG_WRITE_EMPTY;
            break;
        };
        this.cell_write = CellWriter::with_cell_config(cell, &cfg)?;
    }

    Ok(flags)
}
