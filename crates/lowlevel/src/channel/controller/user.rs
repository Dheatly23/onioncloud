use std::collections::hash_set::HashSet;
use std::collections::vec_deque::VecDeque;
use std::io::{ErrorKind, Result as IoResult};
use std::mem::{replace, take};
use std::num::NonZeroU32;
use std::ops::ControlFlow;
use std::ops::ControlFlow::*;
use std::time::{Duration, Instant};

use digest::Digest;
use futures_channel::oneshot::{Receiver, Sender, channel};
use rand::distributions::uniform::{UniformInt, UniformSampler};
use rand::prelude::*;
use sha2::Sha256;
use subtle::ConstantTimeEq;
use tracing::{debug, error, info, instrument, trace, warn};

use crate::cache::{Cachable, Cached, CellCache, CellCacheExt as _};
use crate::cell::auth::AuthChallenge;
use crate::cell::certs::Certs;
use crate::cell::create::Create2;
use crate::cell::destroy::{Destroy, DestroyReason};
use crate::cell::dispatch::{CellReader, CellType, WithCellConfig};
use crate::cell::netinfo::Netinfo;
use crate::cell::padding::{
    NegotiateCommand, NegotiateCommandV0, Padding, PaddingNegotiate, VPadding,
};
use crate::cell::versions::Versions;
use crate::cell::writer::CellWriter;
use crate::cell::{Cell, CellHeader, CellLike, FixedCell, cast};
use crate::channel::controller::{
    ChannelController, DEFAULT_CHANNEL_AGGREGATE_CAP, DEFAULT_CHANNEL_CAP,
};
use crate::channel::{ChannelConfig, ChannelInput, ChannelOutput, NewCircuit};
use crate::crypto::cert::{UnverifiedEdCert, UnverifiedRsaCert, extract_rsa_from_x509};
use crate::crypto::{EdPublicKey, Sha256Output};
use crate::errors;
use crate::linkver::StandardLinkver;
use crate::runtime::{Runtime, TrySendError};
use crate::util::cell_map::{IDGeneratorExt as _, InitiatorIDGenerator, NewHandler};
use crate::util::sans_io::event::{ChannelClosed, ChildCellMsg, ControlMsg, Timeout};
use crate::util::sans_io::{CellMsgPause, Handle};
use crate::util::{GenerationalData, InBuffer, OutBuffer, print_ed, print_hex};

/// Trait for [`UserController`] configuration type.
pub trait UserConfig: ChannelConfig + Send + Sync {
    /// Cache type.
    type Cache: 'static + Send + Sync + Clone + CellCache;

    /// Get [`Self::Cache`].
    ///
    /// # Implementer's Note
    ///
    /// To maximize cache utilization, cache should be as global as possible.
    fn get_cache(&self) -> &Self::Cache;

    /// Get padding parameter.
    ///
    /// By default padding is disabled.
    ///
    /// **NOTE: Only at link version 5 or higher do PADDING_NEGOTIATE cell is sent.
    fn get_padding_param(&self, linkver: u16) -> NegotiateCommand {
        let _ = linkver;
        NegotiateCommand::V0(NegotiateCommandV0::Stop)
    }

    /// Get circuit channel capacity.
    fn channel_cap(&self) -> usize {
        DEFAULT_CHANNEL_CAP
    }

    /// Get circuit aggregation channel capacity.
    fn channel_aggregate_cap(&self) -> usize {
        DEFAULT_CHANNEL_AGGREGATE_CAP
    }
}

struct LinkCfg<Cfg> {
    linkver: StandardLinkver,
    cfg: Cfg,
}

impl<Cfg: UserConfig> WithCellConfig for LinkCfg<Cfg> {
    fn is_circ_id_4bytes(&self) -> bool {
        self.linkver.is_circ_id_4bytes()
    }

    fn cell_type(&self, header: &CellHeader) -> Result<CellType, errors::InvalidCellHeader> {
        self.linkver.cell_type(header)
    }
}

impl<Cfg: UserConfig> CellCache for LinkCfg<Cfg> {
    fn get_cached(&self) -> FixedCell {
        self.cfg.get_cache().get_cached()
    }

    fn cache_cell(&self, cell: FixedCell) {
        self.cfg.get_cache().cache_cell(cell);
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
pub struct UserController<R: Runtime, Cfg: UserConfig> {
    link_cfg: LinkCfg<Cfg>,

    state: State<R, Cfg::Cache>,

    last_packet: Option<Instant>,
    is_timeout: bool,
}

/// [`UserController`] control messages.
#[non_exhaustive]
pub enum UserControlMsg<R: Runtime, C: 'static + Send + CellCache> {
    /// Force shutdown of channel.
    Shutdown,
    /// Create new circuit.
    NewCircuit(NewCircuitSender<R, C>),
    /// Set padding configuration.
    SetPadding(NegotiateCommand),
}

impl<R: Runtime, C: 'static + Send + CellCache> UserControlMsg<R, C> {
    pub fn new_circuit() -> (NewCircuitReceiver<R, C>, Self) {
        let (send, recv) = channel();
        (recv, Self::NewCircuit(send))
    }
}

/// Sender for the resulting [`NewCircuit`].
pub type NewCircuitSender<R, C> = Sender<
    Result<NewCircuit<GenerationalData<NonZeroU32>, R, CellTy<C>>, errors::NoFreeCircIDError>,
>;
/// Receiver for the resulting [`NewCircuit`].
pub type NewCircuitReceiver<R, C> = Receiver<
    Result<NewCircuit<GenerationalData<NonZeroU32>, R, CellTy<C>>, errors::NoFreeCircIDError>,
>;

type PendingOpen<R, C> = VecDeque<NewCircuitSender<R, C>>;
type CellTy<Cache, C = Cell> = Cached<GenerationalData<C>, Cache>;
type CIn<'a, 'b, R, C> = ChannelInput<'a, 'b, R, CellTy<C>, CircuitMeta>;

// NOTE: Controller isn't going to be moved a lot.
#[allow(clippy::large_enum_variant)]
enum State<R: Runtime, C: 'static + Send + CellCache> {
    Init {
        state: InitState,
        pending_open: PendingOpen<R, C>,
        padding_type: Option<NegotiateCommand>,
    },
    Steady(SteadyState<R, C>),
    Shutdown,
}

enum InitState {
    Init,
    VersionsWrite(CellWriter<Versions>),
    ConfigRead(CellReader, ConfigReadState),
    NetinfoWrite(CellWriter<Netinfo>),
}

enum ConfigReadState {
    Versions,
    Certs,
    AuthChallenge,
    Netinfo,
}

struct SteadyState<R: Runtime, C: 'static + Send + CellCache> {
    cell_read: CellReader,
    cell_write: CellWriter<Cell>,
    is_write_padding: bool,

    in_buffer: InBuffer<Cell>,
    out_buffer: OutBuffer<GenerationalData<Cell>>,
    scan_cells: bool,

    pending_open: PendingOpen<R, C>,
    pending_close: VecDeque<(NonZeroU32, DestroyReason)>,
    closing: HashSet<NonZeroU32>,
    generation: u64,

    padding_type: NegotiateCommand,
    padding_time: PaddingTime,
}

enum PaddingTime {
    Unnegotiated,
    Time(Instant),
    Stop,
}

/// [`UserController`] circuit metadata type.
///
/// It is marked public only for [`ChannelController`] purposes.
/// It cannot be created.
pub struct CircuitMeta {
    /// Marker if the closing message is coming from peer.
    peer_close: bool,

    /// Generation ID.
    generation: u64,
}

impl<R: Runtime, Cfg: UserConfig> Drop for UserController<R, Cfg> {
    fn drop(&mut self) {
        let c = self.link_cfg.cfg.get_cache();
        match replace(&mut self.state, State::Shutdown) {
            State::Init { state, .. } => match state {
                InitState::ConfigRead(read, _) => c.discard(read),
                InitState::NetinfoWrite(write) => c.discard(write),
                _ => (),
            },
            State::Steady(SteadyState {
                cell_read,
                cell_write,
                in_buffer,
                out_buffer,
                ..
            }) => c.discard((cell_read, cell_write, in_buffer, out_buffer)),
            _ => (),
        }
    }
}

impl<R: 'static + Runtime, Cfg: 'static + UserConfig> ChannelController for UserController<R, Cfg> {
    type Runtime = R;
    type Error = errors::UserControllerError;
    type Config = Cfg;
    type ControlMsg = UserControlMsg<R, Cfg::Cache>;
    type Cell = CellTy<Cfg::Cache>;
    type CircMeta = CircuitMeta;

    fn channel_cap(cfg: &Cfg) -> usize {
        cfg.channel_cap()
    }

    fn channel_aggregate_cap(cfg: &Cfg) -> usize {
        cfg.channel_aggregate_cap()
    }

    fn new(_: &Self::Runtime, cfg: Self::Config) -> Self {
        Self {
            link_cfg: LinkCfg {
                linkver: Default::default(),
                cfg,
            },

            state: State::Init {
                state: InitState::Init,
                pending_open: VecDeque::new(),
                padding_type: None,
            },

            last_packet: None,
            is_timeout: false,
        }
    }
}

impl<'a, 'b, R: Runtime, Cfg: UserConfig> Handle<(&'a R, CIn<'a, 'b, R, Cfg::Cache>)>
    for UserController<R, Cfg>
{
    type Return = Result<ChannelOutput, errors::UserControllerError>;

    #[instrument(level = "debug", skip_all)]
    fn handle(&mut self, (rt, mut input): (&'a R, CIn<'a, 'b, R, Cfg::Cache>)) -> Self::Return {
        let last_packet = self
            .last_packet
            .get_or_insert_with(|| input.time() + IDLE_TIMEOUT);
        if take(&mut self.is_timeout) && *last_packet <= input.time() {
            info!("channel idled for 5 minutes, gracefully shutting down");
            self.state = State::Shutdown;
        }

        loop {
            match self.state {
                State::Init {
                    ref mut state,
                    ref mut pending_open,
                    ref mut padding_type,
                } => match state.handle(&self.link_cfg, last_packet, &mut input)? {
                    Break(()) => break,
                    Continue(false) => (),
                    Continue(true) => {
                        debug!("channel initialization successful");

                        self.state = State::Steady(SteadyState {
                            cell_read: CellReader::new(),
                            cell_write: CellWriter::new_finished(),
                            is_write_padding: false,

                            in_buffer: InBuffer::new(),
                            out_buffer: OutBuffer::new(),
                            scan_cells: false,

                            pending_open: take(pending_open),
                            pending_close: VecDeque::new(),
                            closing: HashSet::new(),
                            generation: 0,

                            padding_type: padding_type.take().unwrap_or_else(|| {
                                self.link_cfg
                                    .cfg
                                    .get_padding_param(self.link_cfg.linkver.as_ref().version())
                            }),
                            padding_time: PaddingTime::Unnegotiated,
                        })
                    }
                },
                State::Steady(ref mut state) => {
                    return state.handle(&self.link_cfg, last_packet, rt, input);
                }
                State::Shutdown => {
                    let mut ret = ChannelOutput::new();
                    ret.shutdown(true);
                    return Ok(ret);
                }
            }
        }

        let mut ret = ChannelOutput::new();
        ret.timeout(*last_packet);
        // Should not receive cell messages
        ret.cell_msg_pause(CellMsgPause(true));
        Ok(ret)
    }
}

impl InitState {
    #[instrument(level = "debug", name = "handle_init", skip_all)]
    fn handle<R: Runtime, Cfg: UserConfig>(
        &mut self,
        cfg: &LinkCfg<Cfg>,
        last_packet: &mut Instant,
        input: &mut CIn<'_, '_, R, Cfg::Cache>,
    ) -> Result<ControlFlow<(), bool>, errors::UserControllerError> {
        match self {
            Self::Init => {
                let peer_addr = input.peer_addr();
                let addrs = cfg.cfg.peer_addrs();
                if !addrs.contains(peer_addr) {
                    return Err(
                        errors::PeerSocketMismatchError::new(*peer_addr, addrs.into()).into(),
                    );
                }

                *self = Self::VersionsWrite(CellWriter::with_cell_config(
                    cfg.linkver.as_ref().versions_cell(),
                    cfg,
                )?);
            }
            Self::VersionsWrite(w) => match write_cell_uncached(w, input)? {
                false => return Ok(Break(())),
                true => {
                    update_last_packet(last_packet, input);
                    *self = Self::ConfigRead(CellReader::new(), ConfigReadState::Versions);
                }
            },
            Self::ConfigRead(r, state) => {
                let Some(cell) = read_cell(r, input, cfg)? else {
                    return Ok(Break(()));
                };
                update_last_packet(last_packet, input);
                let mut cell = cfg.cache_b(Some(cell));

                match state {
                    ConfigReadState::Versions => {
                        if let Some(cell) = cast::<Versions>(&mut cell)? {
                            cfg.linkver.as_ref().versions_negotiate(cell)?;
                            debug!("version negotiated: {}", cfg.linkver.as_ref().version());

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

                            let Some(data) = cert_2 else {
                                return Err(errors::CertsError::NotFound(2).into());
                            };
                            let (pk_rsa, id) = extract_rsa_from_x509(data)?;

                            let relay_id = cfg.cfg.peer_id();
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

                            if let Some(relay_id) = cfg.cfg.peer_id_ed()
                                && id.ct_ne(relay_id).into()
                            {
                                error!(
                                    "relay ED25519 ID mismatch (expect {}, got {})",
                                    print_ed(relay_id),
                                    print_ed(&pk_id),
                                );
                                return Err(errors::CertVerifyError.into());
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
                            let cell = cfg.cache_b(cell);

                            let Some(peer_addr) = cell.peer_addr() else {
                                return Err(errors::NetinfoError::InvalidPeerAddr.into());
                            };
                            let addr = input.peer_addr().ip();
                            if cell.this_addrs().all(|a| a != addr) {
                                return Err(errors::NetinfoError::ThisAddrNotFound(
                                    errors::PeerIpMismatchError::new(
                                        addr,
                                        cell.this_addrs().collect::<Vec<_>>().into(),
                                    ),
                                )
                                .into());
                            }

                            debug!("peer NETINFO check successful");

                            *self = Self::NetinfoWrite(CellWriter::with_cell_config(
                                Netinfo::new(cfg.get_cached(), 0, addr, [peer_addr])?,
                                cfg,
                            )?);
                        }
                    }
                }

                if let Some(cell) = &*cell {
                    return Err(errors::InvalidCellHeader::with_cell(cell).into());
                }
            }
            Self::NetinfoWrite(w) => {
                return Ok(match write_cell(w, input, cfg)? {
                    false => Break(()),
                    true => Continue(true),
                });
            }
        }

        Ok(Continue(false))
    }
}

impl<R: Runtime, Cfg: UserConfig> Handle<Timeout> for UserController<R, Cfg> {
    type Return = Result<(), errors::UserControllerError>;

    #[instrument(level = "debug", name = "handle_timeout", skip_all)]
    fn handle(&mut self, _: Timeout) -> Self::Return {
        self.is_timeout = true;
        Ok(())
    }
}

impl<R: Runtime, Cfg: UserConfig> Handle<ControlMsg<UserControlMsg<R, Cfg::Cache>>>
    for UserController<R, Cfg>
{
    type Return = Result<(), errors::UserControllerError>;

    #[instrument(level = "debug", name = "handle_control", skip_all)]
    fn handle(&mut self, msg: ControlMsg<UserControlMsg<R, Cfg::Cache>>) -> Self::Return {
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
            UserControlMsg::SetPadding(data) => match self.state {
                State::Init {
                    ref mut padding_type,
                    ..
                } => *padding_type = Some(data),
                State::Steady(ref mut s) => {
                    s.padding_type = data;
                    s.padding_time = PaddingTime::Unnegotiated;
                }
                State::Shutdown => (),
            },
        }

        Ok(())
    }
}

impl<R: Runtime, Cfg: UserConfig> Handle<ChildCellMsg<CellTy<Cfg::Cache>>>
    for UserController<R, Cfg>
{
    type Return = Result<CellMsgPause, errors::UserControllerError>;

    #[instrument(level = "debug", name = "handle_cell", skip_all)]
    fn handle(&mut self, msg: ChildCellMsg<CellTy<Cfg::Cache>>) -> Self::Return {
        match self.state {
            State::Steady(ref mut s) => s.handle_cell(msg.0),
            State::Shutdown => Ok(CellMsgPause(true)),
            State::Init { .. } => unreachable!("init state does not create circuits"),
        }
    }
}

impl<'a, R: Runtime, Cfg: UserConfig>
    Handle<ChannelClosed<'a, NonZeroU32, CellTy<Cfg::Cache>, CircuitMeta>>
    for UserController<R, Cfg>
{
    type Return = Result<(), errors::UserControllerError>;

    #[instrument(level = "debug", name = "handle_close", skip_all, fields(id = msg.id))]
    fn handle(
        &mut self,
        msg: ChannelClosed<'a, NonZeroU32, CellTy<Cfg::Cache>, CircuitMeta>,
    ) -> Self::Return {
        match self.state {
            State::Steady(ref mut s) => {
                s.scan_cells = true;
                if !msg.meta.peer_close {
                    let id = msg.id;
                    debug!(id, "circuit is closing");
                    if s.closing.insert(id) {
                        s.pending_close.push_back((id, DestroyReason::Internal));
                    }
                }
            }
            State::Shutdown => (),
            State::Init { .. } => unreachable!("init state does not create circuits"),
        }
        Ok(())
    }
}

#[instrument(level = "debug", skip_all)]
fn write_cell_uncached<R: Runtime, C: 'static + Send + CellCache, T: CellLike>(
    handler: &mut CellWriter<T>,
    input: &mut CIn<'_, '_, R, C>,
) -> IoResult<bool> {
    match handler.handle(input.writer()) {
        Ok(()) => Ok(true),
        Err(e) if e.kind() == ErrorKind::WouldBlock => Ok(false),
        Err(e) => Err(e),
    }
}

#[instrument(level = "debug", skip_all)]
fn write_cell<R: Runtime, C: 'static + Send + CellCache, T: CellLike + Cachable>(
    handler: &mut CellWriter<T>,
    input: &mut CIn<'_, '_, R, C>,
    cfg: impl CellCache,
) -> IoResult<bool> {
    match handler.handle((input.writer(), cfg)) {
        Ok(()) => Ok(true),
        Err(e) if e.kind() == ErrorKind::WouldBlock => Ok(false),
        Err(e) => Err(e),
    }
}

#[instrument(level = "debug", skip_all)]
fn read_cell<R: Runtime, C: 'static + Send + CellCache, Cfg: WithCellConfig + CellCache>(
    handler: &mut CellReader,
    input: &mut CIn<'_, '_, R, C>,
    cfg: Cfg,
) -> Result<Option<Cell>, errors::CellError> {
    match handler.handle((input.reader(), cfg)) {
        Ok(v) => Ok(Some(v)),
        Err(errors::CellError::Io(e)) if e.kind() == ErrorKind::WouldBlock => Ok(None),
        Err(e) => Err(e),
    }
}

#[instrument(level = "debug", skip_all, fields(cert_ty = cert_ty, key_ty = key_ty, pk = %print_ed(pk), needs_signed_by = needs_signed_by))]
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

    if let Some(k) = signed_with
        && k != pk
    {
        error!("signed-by key does not match signing key");
        return Err(errors::CertVerifyError.into());
    }

    Ok(())
}

const IDLE_TIMEOUT: Duration = Duration::from_secs(60 * 5);

fn update_last_packet<R: Runtime, C: 'static + Send + CellCache>(
    ptr: &mut Instant,
    input: &CIn<'_, '_, R, C>,
) {
    *ptr = input.time() + IDLE_TIMEOUT;
}

const FLAG_READ: u8 = 1 << 0;
const FLAG_WRITE: u8 = 1 << 1;
const FLAG_WRITE_EMPTY: u8 = 1 << 2;
const FLAG_TRY_SEND_CELLS: u8 = 1 << 3;

impl<R: Runtime, C: 'static + Send + Sync + Clone + CellCache> SteadyState<R, C> {
    #[instrument(level = "debug", skip_all)]
    fn handle<Cfg: UserConfig<Cache = C>>(
        &mut self,
        cfg: &LinkCfg<Cfg>,
        last_packet: &mut Instant,
        rt: &R,
        mut input: CIn<'_, '_, R, C>,
    ) -> Result<ChannelOutput, errors::UserControllerError> {
        // Scan input buffer
        if take(&mut self.scan_cells) {
            self.in_buffer.scan_pop(|p| {
                let Some(cell) = p else {
                    return Ok(());
                };
                if NonZeroU32::new(cell.circuit).is_none_or(|id| !input.circ_map().has(&id)) {
                    // Discard all unmapped circuit ID
                    trace!(
                        id = cell.circuit,
                        command = cell.command,
                        "discard unmapped circuit ID in cell"
                    );
                    cfg.discard(p.take());
                    return Ok(());
                }

                Ok::<(), errors::UserControllerError>(())
            })?;
        }

        // Process pending open
        for send in self.pending_open.drain(..) {
            let r = input
                .circ_map()
                .open_with(
                    rt,
                    InitiatorIDGenerator::from_config(cfg).filter(|id| !self.closing.contains(id)),
                    64,
                    |_| CircuitMeta {
                        peer_close: false,
                        generation: self.generation,
                    },
                )
                .map(|(v, mut h)| {
                    NewCircuit::new(v.map_id(|id| GenerationalData::new(id, h.meta().generation)))
                        .with_linkver(cfg.linkver.as_ref().version())
                });
            if r.is_ok() {
                self.generation = self.generation.wrapping_add(1);
            }
            if let Err(Ok(NewCircuit {
                inner:
                    NewHandler {
                        id: GenerationalData { inner: id, .. },
                        ..
                    },
                ..
            })) = send.send(r)
            {
                // Instantly discards newly created circuit
                input.circ_map().remove(&id);
                self.generation = self.generation.wrapping_sub(1);
            }
        }

        let mut flags = 0;
        loop {
            // Read data from stream
            if flags & FLAG_READ == 0 {
                flags = self.read_handler(cfg, last_packet, &mut input, flags)?;
            }

            // Write data into stream
            if flags & (FLAG_WRITE | FLAG_WRITE_EMPTY) == 0 {
                flags = self.write_handler(cfg, last_packet, &mut input, flags)?;
            }

            trace!(flags, "processing");
            if flags & FLAG_READ != 0 && flags & (FLAG_WRITE | FLAG_WRITE_EMPTY) != 0 {
                break;
            }
        }

        let mut timeout = *last_packet;
        if flags & FLAG_WRITE_EMPTY != 0
            && let PaddingTime::Time(t) = self.padding_time
        {
            // Padding timeout
            timeout = timeout.min(t);
        }

        let mut ret = ChannelOutput::new();
        ret.timeout(timeout);
        // Pause cell messages if out buffer is full
        ret.cell_msg_pause(CellMsgPause(self.out_buffer.is_full()));
        Ok(ret)
    }

    #[instrument(level = "debug", skip_all)]
    fn handle_cell(
        &mut self,
        cell: CellTy<C>,
    ) -> Result<CellMsgPause, errors::UserControllerError> {
        self.out_buffer.push_back(Cached::into_inner(cell));
        Ok(CellMsgPause(self.out_buffer.is_full()))
    }

    #[inline(always)]
    fn read_handler<Cfg: UserConfig<Cache = C>>(
        &mut self,
        cfg: &LinkCfg<Cfg>,
        last_packet: &mut Instant,
        input: &mut CIn<'_, '_, R, C>,
        mut flags: u8,
    ) -> Result<u8, errors::UserControllerError> {
        let mut process_buf = false;
        if input.has_ready() && flags & FLAG_TRY_SEND_CELLS == 0 {
            flags |= FLAG_TRY_SEND_CELLS;
            process_buf = true;
        }

        // Read data from stream
        while !self.in_buffer.is_full() {
            let Some(cell) = read_cell(&mut self.cell_read, input, cfg)? else {
                flags |= FLAG_READ;
                break;
            };
            if cell.circuit != 0 {
                update_last_packet(last_packet, input);
                self.in_buffer.push(cell);
                process_buf = true;
                continue;
            }

            let mut cell = cfg.cache_b(Some(cell));
            // TODO: Handle padding
            if let Some(c) = cast::<Padding>(&mut cell)? {
                cfg.discard(c);
            }
            cast::<VPadding>(&mut cell)?;
            cast::<Versions>(&mut cell)?;

            if let Some(cell) = &*cell {
                // NOTE: Potential protocol violation
                trace!("unhandled cell with command {} received", cell.command);
            }
        }

        // Process in buffer
        if process_buf {
            self.in_buffer.scan_pop(|p| {
                if let Some(cell) = cast::<Create2>(p)? {
                    let id = cell.circuit;
                    cfg.discard(cell);
                    // User controller cannot create circuit by peer
                    self.pending_close.push_back((id, DestroyReason::Protocol));
                    // Pending DESTROY cell, clear flag
                    flags &= !FLAG_WRITE_EMPTY;
                    return Ok(());
                }

                let Some(cell) = p else {
                    return Ok(());
                };
                let id = NonZeroU32::new(cell.circuit).expect("circuit ID should not be zero");
                let mut circ_map = input.circ_map();
                let Some(mut circ) = circ_map.get(&id) else {
                    // Discard all unmapped circuit ID
                    trace!(
                        id,
                        command = cell.command,
                        "discard unmapped circuit ID in cell"
                    );
                    cfg.discard(p.take());
                    return Ok(());
                };
                if !circ.is_ready() {
                    // Circuit is not ready
                    return Ok(());
                }

                if let Some(cell) = cast::<Destroy>(p)? {
                    // DESTROY cell received, closing circuit.
                    let cell = cfg.cfg.get_cache().cache(cell);
                    let reason = cell.display_reason();
                    let cell = Cached::map(cell, |cell| {
                        GenerationalData::new(cell.into(), circ.meta().generation)
                    });
                    match circ.try_send(cell) {
                        Ok(()) => {
                            debug!(id, %reason, "peer is closing circuit");
                            circ.meta().peer_close = true;
                            circ.start_close();
                        }
                        Err(TrySendError::NotReady(cell)) => {
                            *p = Some(Cached::into_inner(cell).into_inner())
                        }
                        // Circuit is closed while peer is closing.
                        Err(TrySendError::Disconnected(_)) => {
                            circ.meta().peer_close = true;
                            debug!(id, %reason, "discard DESTROY cell, circuit is closed")
                        }
                    }

                    return Ok(());
                }

                let Some(cell) = p.take() else {
                    return Ok(());
                };
                let cell = cfg
                    .cfg
                    .get_cache()
                    .cache(GenerationalData::new(cell, circ.meta().generation));

                match circ.try_send(cell) {
                    // Success
                    Ok(()) => {
                        trace!(id, "sending in cell to circuit");
                    }
                    // Not ready, return cell
                    Err(TrySendError::NotReady(cell)) => {
                        *p = Some(Cached::into_inner(cell).into_inner());
                        trace!(id, "cannot send cell, circuit is not ready");
                    }
                    // Circuit is closed, drop cell
                    Err(TrySendError::Disconnected(_)) => {
                        trace!(id, "cannot send cell, circuit is closed");
                    }
                }

                Ok::<(), errors::UserControllerError>(())
            })?;
        }

        // Cannot receive anymore
        if self.in_buffer.is_full() {
            flags |= FLAG_READ;
        }

        Ok(flags)
    }

    #[inline(always)]
    fn write_handler<Cfg: UserConfig<Cache = C>>(
        &mut self,
        cfg: &LinkCfg<Cfg>,
        last_packet: &mut Instant,
        input: &mut CIn<'_, '_, R, C>,
        mut flags: u8,
    ) -> Result<u8, errors::UserControllerError> {
        let finished = self.cell_write.is_finished();
        if !write_cell(&mut self.cell_write, input, cfg)? {
            flags |= FLAG_WRITE;
            return Ok(flags);
        }
        if !finished {
            // Writer just finished writing
            if !take(&mut self.is_write_padding) {
                update_last_packet(last_packet, input);
            }
            if !matches!(self.padding_time, PaddingTime::Unnegotiated) {
                self.padding_time = match self.padding_type {
                    NegotiateCommand::V0(NegotiateCommandV0::Start { low, high })
                        if high >= low =>
                    {
                        let mut rng = ThreadRng::default();
                        let sampler = UniformInt::<u16>::new_inclusive(low, high);
                        let n = sampler.sample(&mut rng).max(sampler.sample(&mut rng));
                        trace!(time_ms = n, "resetting padding timeout");
                        PaddingTime::Time(input.time() + Duration::from_millis(n.into()))
                    }
                    _ => PaddingTime::Stop,
                };
            }
        }

        let mut found: Option<Cached<Cell, _>> = None;

        while found.is_none()
            && let Some((id, reason)) = self.pending_close.pop_front()
        {
            self.closing.remove(&id);

            // Prepend DESTROY cell
            found = Some(cfg.cache_b(Destroy::new(cfg.get_cached(), id, reason).into()));
        }

        if found.is_none()
            && let PaddingTime::Unnegotiated = self.padding_time
        {
            self.padding_time = PaddingTime::Stop;

            // Prepend PADDING_NEGOTIATE cell.
            if cfg.linkver.inner.version() >= 5 {
                debug!(padding = ?self.padding_type, "negotiate padding");
                found = Some(cfg.cache_b(
                    PaddingNegotiate::new(cfg.get_cached(), self.padding_type.clone()).into(),
                ));
            }
        }

        while found.is_none() {
            let Some(GenerationalData {
                inner: cell,
                generation,
            }) = self.out_buffer.pop_front()
            else {
                break;
            };
            let cell = cfg.cache_b(cell);

            let mut circ_map = input.circ_map();
            let Some(mut handle) = NonZeroU32::new(cell.circuit)
                .and_then(|id| circ_map.get(&id))
                .and_then(|mut handle| {
                    let meta = handle.meta();
                    if meta.peer_close || meta.generation != generation {
                        return None;
                    }
                    Some(handle)
                })
            else {
                // Unmapped circuit ID. Probably non-graceful shutdown.
                trace!(
                    id = cell.circuit,
                    command = cell.command,
                    "discard unmapped circuit ID out cell"
                );
                continue;
            };
            let mut cell = Cached::map(cell, Some);

            found = if let Some(cell) = cast::<Destroy>(&mut cell)? {
                let cell = cfg.cache_b(cell);
                trace!(id = cell.circuit, "sending DISCARD cell, closing circuit");
                handle.meta().peer_close = true;
                handle.start_close();

                Some(Cached::map_into(cell))
            } else {
                if let Some(cell) = &*cell {
                    trace!(id = cell.circuit, "sending output cell");
                }
                Cached::transpose(cell)
            };
        }

        if found.is_none()
            && let PaddingTime::Time(time) = self.padding_time
            && time <= input.time()
        {
            // Append PADDING cell.
            let mut cell = Padding::new(cfg.get_cached());
            cell.fill();
            found = Some(cfg.cache_b(cell.into()));
            trace!("sending padding");
        }

        let Some(cell) = found else {
            flags |= FLAG_WRITE_EMPTY;
            return Ok(flags);
        };
        self.is_write_padding = matches!(cell.command, Padding::ID | VPadding::ID);
        self.cell_write = CellWriter::with_cell_config(Cached::into_inner(cell), &cfg)?;

        Ok(flags)
    }
}
