use std::collections::vec_deque::VecDeque;
use std::io::{ErrorKind, Result as IoResult};
use std::mem::take;
use std::num::NonZeroU32;
use std::ops::ControlFlow;
use std::ops::ControlFlow::*;
use std::sync::Arc;
use std::time::{Duration, Instant};

use base64ct::{Base64Url, Encoding};
use digest::{Digest, Output};
use flume::TrySendError;
use futures_channel::oneshot::Sender;
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
use crate::channel::circ_map::{CircuitMap, NewCircuit};
use crate::channel::controller::{CellMsg, ChannelController, ControlMsg, Timeout};
use crate::channel::{CellMsgPause, ChannelConfig, ChannelInput, ChannelOutput};
use crate::crypto::EdPublicKey;
use crate::crypto::cert::{UnverifiedEdCert, UnverifiedRsaCert, extract_rsa_from_x509};
use crate::errors;
use crate::linkver::StandardLinkver;
use crate::util::print_hex;
use crate::util::sans_io::Handle;

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

pub struct UserController<Cfg> {
    link_cfg: LinkCfg,

    state: State<Cfg>,

    last_packet: Option<Instant>,
    is_timeout: bool,
}

/// User controller control messages.
pub enum UserControlMsg {
    /// Force shutdown of channel.
    Shutdown,
    /// Create new circuit.
    NewCircuit(Sender<Result<NewCircuit<CachedCell>, errors::NoFreeCircIDError>>),
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

    in_buffer: InBuffer<CachedCell>,
    out_buffer: OutBuffer<CachedCell>,

    pending_open: VecDeque<Sender<Result<NewCircuit<CachedCell>, errors::NoFreeCircIDError>>>,
    pending_close: VecDeque<(NonZeroU32, DestroyReason)>,

    close_scan: Instant,
}

pub struct CircuitMeta {
    last_full: Instant,
    closing: bool,
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
                    return state.handle(&self.link_cfg, last_packet, input, circ_map);
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
        ret.cell_msg_pause(true.into());
        Ok(ret)
    }
}

impl InitState {
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
                                        Base64Url::encode_string(relay_id),
                                        Base64Url::encode_string(&pk_id),
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
                            let subject = Output::<Sha256>::from(unverified.header.key);
                            check_cert(unverified, 5, 3, &pk_sign, false)?;

                            let Some(link_cert) = input.link_cert() else {
                                return Err(errors::CertsError::NoLinkCert.into());
                            };
                            let hash = Sha256::digest(link_cert);
                            if subject.ct_ne(&hash).into() {
                                error!("link certificate hash does not match");
                                return Err(errors::CertVerifyError.into());
                            }

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
            Self::NetinfoWrite(w) => match write_cell(w, input)? {
                false => return Ok(Break(())),
                true => todo!(),
            },
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

struct InBuffer<T> {
    buffer: [Option<T>; 64],
    index: [(u8, u8); 64],
    head: u8,
    tail: u8,
    free: u8,
}

impl<T> InBuffer<T> {
    const fn new() -> Self {
        // Keep it compact
        #[rustfmt::skip]
        const INDEX: [(u8, u8); 64] = [
            (1, 64), (2, 64), (3, 64), (4, 64), (5, 64), (6, 64), (7, 64), (8, 64),
            (9, 64), (10, 64), (11, 64), (12, 64), (13, 64), (14, 64), (15, 64), (16, 64),
            (17, 64), (18, 64), (19, 64), (20, 64), (21, 64), (22, 64), (23, 64), (24, 64),
            (25, 64), (26, 64), (27, 64), (28, 64), (29, 64), (30, 64), (31, 64), (32, 64),
            (33, 64), (34, 64), (35, 64), (36, 64), (37, 64), (38, 64), (39, 64), (40, 64),
            (41, 64), (42, 64), (43, 64), (44, 64), (45, 64), (46, 64), (47, 64), (48, 64),
            (49, 64), (50, 64), (51, 64), (52, 64), (53, 64), (54, 64), (55, 64), (56, 64),
            (57, 64), (58, 64), (59, 64), (60, 64), (61, 64), (62, 64), (63, 64), (64, 64),
        ];

        Self {
            head: 64,
            tail: 64,
            free: 0,
            index: INDEX,
            buffer: [const { None }; 64],
        }
    }

    fn is_full(&self) -> bool {
        self.free == 64
    }

    fn push(&mut self, value: T) {
        assert!(self.head <= 64);
        assert!(self.tail <= 64);
        assert!(self.free < 64);

        let i = self.free;
        let ix = usize::from(i);
        debug_assert!(self.buffer[ix].is_none());
        self.buffer[ix] = Some(value);

        let t = self.tail;
        (self.free, self.tail, self.index[ix]) = (self.index[ix].0, i, (64, t));
        if t != 64 {
            debug_assert_ne!(self.head, 64);
            let tx = usize::from(t);
            debug_assert_eq!(self.index[tx].0, 64);
            self.index[tx].0 = i;
        } else {
            debug_assert_eq!(self.head, 64);
            self.head = i;
        }

        debug_assert!(self.head < 64);
        debug_assert!(self.tail < 64);
        debug_assert!(self.free <= 64);
    }

    fn scan_pop<E>(&mut self, mut f: impl FnMut(&mut Option<T>) -> Result<(), E>) -> Result<(), E> {
        assert!(self.head <= 64);
        assert!(self.tail <= 64);
        assert!(self.free <= 64);

        let mut i = self.head;
        loop {
            if i == 64 {
                return Ok(());
            }

            let ix = usize::from(i);
            let data = &mut self.buffer[ix];

            debug_assert!(data.is_some());
            let ret = f(data);

            if data.is_some() {
                ret?;
                break;
            }
            (self.head, self.free, self.index[ix]) = (self.index[ix].0, i, (self.free, 64));
            debug_assert!(self.head <= 64);
            debug_assert!(self.free < 64);
            i = self.head;
            if i != 64 {
                self.index[usize::from(i)].1 = 64;
            } else {
                self.tail = 64;
            }

            ret?;
        }

        let mut j = self.index[usize::from(i)].0;
        debug_assert!(j <= 64);
        while j != 64 {
            let ix = usize::from(j);
            let data = &mut self.buffer[ix];

            debug_assert!(data.is_some());
            let ret = f(data);

            let k = self.index[ix].0;
            debug_assert!(k <= 64);
            if data.is_some() {
                (i, j) = (j, k);
            } else {
                self.index[usize::from(i)].0 = k;
                (self.free, j, self.index[ix]) = (j, k, (self.free, 64));
                if j != 64 {
                    self.index[usize::from(j)].1 = i;
                } else {
                    self.tail = i;
                }
            }

            ret?;
        }

        Ok(())
    }
}

struct OutBuffer<T> {
    buffer: [Option<T>; 64],
    head: u8,
    len: u8,
}

impl<T> OutBuffer<T> {
    const fn new() -> Self {
        Self {
            buffer: [const { None }; 64],
            head: 0,
            len: 0,
        }
    }

    fn is_full(&self) -> bool {
        self.len == 64
    }

    fn push_back(&mut self, value: T) {
        assert!(self.head < 64);
        assert!(self.len < 64);

        self.head = (self.head + 1) % 64;
        self.len += 1;
        let ix = usize::from(self.head);
        debug_assert!(self.buffer[ix].is_none());
        self.buffer[ix] = Some(value);

        debug_assert!(self.head < 64);
        debug_assert!(self.len <= 64);
    }

    fn push_front(&mut self, value: T) {
        assert!(self.head < 64);
        assert!(self.len < 64);

        let ix = usize::from((self.head as i8 - self.len as i8).rem_euclid(64) as u8);
        debug_assert!(self.buffer[ix].is_none());
        self.buffer[ix] = Some(value);
        self.len += 1;

        debug_assert!(self.head < 64);
        debug_assert!(self.len <= 64);
    }

    fn pop(&mut self) -> Option<T> {
        assert!(self.head < 64);
        assert!(self.len <= 64);

        if self.len == 0 {
            return None;
        }
        let ix = usize::from((self.head as i8 - (self.len - 1) as i8).rem_euclid(64) as u8);
        let ret = self.buffer[ix].take();
        debug_assert!(ret.is_some());
        self.len -= 1;
        if self.len == 0 {
            self.head = 0;
        }

        debug_assert!(self.head < 64);
        debug_assert!(self.len < 64);

        ret
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

const IDLE_TIMEOUT: Duration = Duration::from_secs(60 * 5);
const FULL_TIMEOUT: Duration = Duration::from_millis(100);
const CLOSE_SCAN_TIMEOUT: Duration = Duration::from_secs(5);

fn update_last_packet(ptr: &mut Instant, input: &ChannelInput<'_>) {
    *ptr = input.time() + IDLE_TIMEOUT;
}

impl SteadyState {
    #[instrument(level = "debug", skip_all)]
    fn handle(
        &mut self,
        cfg: &LinkCfg,
        last_packet: &mut Instant,
        mut input: ChannelInput<'_>,
        circ_map: &mut CircuitMap<CachedCell, CircuitMeta>,
    ) -> Result<ChannelOutput, errors::UserControllerError> {
        // Scan for close circuits
        if self.close_scan <= input.time() {
            circ_map.retain(|&id, circuit| {
                let r = circuit.is_closed();
                if r {
                    self.pending_close.push_back((id, DestroyReason::Internal));
                }
                !r
            });
            self.close_scan = input.time() + CLOSE_SCAN_TIMEOUT;
        }

        // Process pending open
        for send in self.pending_open.drain(..) {
            if let Err(Ok(NewCircuit { id, .. })) = send.send(
                circ_map
                    .open_with(true, cfg.is_circ_id_4bytes(), 64, |_| CircuitMeta {
                        last_full: input.time(),
                        closing: false,
                    })
                    .map(|v| v.0),
            ) {
                circ_map.remove(id);
            }
        }

        const FLAG_READ: u8 = 1 << 0;
        const FLAG_WRITE: u8 = 1 << 1;
        const FLAG_WRITE_EMPTY: u8 = 1 << 2;
        const FLAG_FULL_TIMEOUT: u8 = 1 << 7;

        let mut flags = 0;
        loop {
            if flags & FLAG_READ == 0 {
                // Read data from stream
                while !self.in_buffer.is_full() {
                    let Some(cell) = read_cell(&mut self.cell_read, &mut input)? else {
                        flags |= FLAG_READ;
                        break;
                    };
                    if cell.circuit != 0 {
                        update_last_packet(last_packet, &input);
                        self.in_buffer.push(cfg.cache.cache(cell));
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

                // Process in buffer
                self.in_buffer.scan_pop(|p| {
                    let Some(cell) = p.take() else { return Ok(()) };
                    let id = NonZeroU32::new(cell.circuit).unwrap();
                    let mut cell = Cached::map(cell, Some);

                    if let Some(cell) = cast::<Create2>(&mut cell)? {
                        cfg.cache.cache_cell(cell.into());
                        // User controller cannot create circuit by peer
                        self.pending_close.push_back((id, DestroyReason::Protocol));
                        // Pending DESTROY cell, clear flag
                        flags &= !FLAG_WRITE_EMPTY;
                        return Ok(());
                    }

                    let Some(circ) = circ_map.get(id) else {
                        // Ignore all unmapped circuit ID.
                        return Ok(());
                    };
                    if circ.meta.closing {
                        // Circuit closing, discard cell
                        return Ok(());
                    }

                    if let Some(cell) = cast::<Destroy>(&mut cell)? {
                        debug!(id, "peer is closing circuit");
                        circ.meta.closing = true;
                        match circ.send(cfg.cache.cache(cell.into())) {
                            Ok(()) => (),
                            Err(TrySendError::Full(_)) => warn!(
                                id,
                                "cannot send DESTROY cell to handler because channel is full"
                            ),
                            // Circuit is closing while peer is closing.
                            Err(TrySendError::Disconnected(_)) => (),
                        }
                    } else if let Ok(cell) = Cached::try_map(cell, |v, _| v.ok_or(())) {
                        if circ.meta.last_full >= input.time() {
                            // Sender recently full, return cell
                            *p = Some(cell);
                        } else {
                            match circ.send(cell) {
                                Ok(()) => (),
                                // Full, return cell and set last full
                                Err(TrySendError::Full(cell)) => {
                                    *p = Some(cell);
                                    circ.meta.last_full = input.time() + FULL_TIMEOUT;
                                    flags |= FLAG_FULL_TIMEOUT;
                                }
                                // Circuit is closing, drop cell and close it for real
                                Err(TrySendError::Disconnected(_)) => {
                                    debug!(id, "cannot send cell, circuit is closing");
                                    circ.meta.closing = true;
                                    self.pending_close.push_back((id, DestroyReason::Internal));
                                    // Pending DESTROY cell, clear flag
                                    flags &= !FLAG_WRITE_EMPTY;
                                }
                            }
                        }
                    }

                    Ok::<(), errors::UserControllerError>(())
                })?;

                // Cannot receive anymore
                if self.in_buffer.is_full() {
                    flags |= FLAG_READ;
                }
            }

            // Write data into stream
            if flags & (FLAG_WRITE | FLAG_WRITE_EMPTY) == 0 {
                loop {
                    let finished = self.cell_write.is_finished();
                    if !write_cell(&mut self.cell_write, &mut input)? {
                        flags |= FLAG_WRITE;
                        break;
                    }
                    if !finished {
                        // Writer just finished writing
                        update_last_packet(last_packet, &input);
                    }

                    let cell = if let Some((id, reason)) = self.pending_close.pop_front() {
                        let meta = circ_map.remove(id);
                        debug_assert!(meta.expect("circuit must exist").closing);
                        // Prepend DESTROY cell
                        cfg.cache
                            .cache(Destroy::new(cfg.cache.get_cached(), id, reason).into())
                    } else if let Some(cell) = self.out_buffer.pop() {
                        let mut cell = cell.map(Some);

                        if let Some(cell) = cast::<Destroy>(&mut cell)? {
                            circ_map.remove(cell.circuit);
                            cfg.cache.cache(cell.into())
                        } else if let Ok(cell) = cell.try_map(|c, _| c.ok_or(())) {
                            cell
                        } else {
                            // Should not happen
                            continue;
                        }
                    } else {
                        flags |= FLAG_WRITE_EMPTY;
                        break;
                    };
                    self.cell_write = CellWriter::with_cell_config(cell, &cfg)?;
                }
            }

            if flags & FLAG_READ != 0 && flags & (FLAG_WRITE | FLAG_WRITE_EMPTY) != 0 {
                break;
            }
        }

        let mut timeout = *last_packet;
        timeout = timeout.min(self.close_scan);
        if flags & FLAG_FULL_TIMEOUT != 0 {
            // Full timeout
            timeout = timeout.min(input.time() + FULL_TIMEOUT);
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

#[cfg(test)]
mod tests {
    use super::*;

    use proptest::prelude::*;
    use proptest::strategy::LazyJust;
    use proptest_state_machine::*;

    #[derive(Debug, Clone)]
    struct RefBuffer {
        buf: VecDeque<u64>,
        i: u64,

        popped: Vec<u64>,
    }

    impl RefBuffer {
        fn new() -> Self {
            Self {
                i: 0,
                buf: VecDeque::with_capacity(64),

                popped: Vec::new(),
            }
        }

        fn is_full(&self) -> bool {
            self.buf.len() == 64
        }

        fn is_empty(&self) -> bool {
            self.buf.is_empty()
        }

        fn len(&self) -> usize {
            self.buf.len()
        }

        fn push(&mut self, n: u8) {
            self.popped.clear();

            for _ in 0..n {
                if self.is_full() {
                    break;
                }

                self.buf.push_back(self.i);
                self.i = self.i.wrapping_add(1);
            }
        }

        fn push_front(&mut self, n: u8) {
            self.popped.clear();

            for _ in 0..n {
                if self.is_full() {
                    break;
                }

                self.buf.push_front(self.i);
                self.i = self.i.wrapping_add(1);
            }
        }

        fn scan_pop(&mut self, v: &[bool; 64]) {
            self.popped.clear();

            let mut it = v.iter().copied();
            self.buf.retain(|&v| {
                if it.next().unwrap() {
                    self.popped.push(v);
                    false
                } else {
                    true
                }
            });
        }

        fn pop(&mut self, n: u8) {
            self.popped.clear();

            for _ in 0..n {
                let Some(v) = self.buf.pop_front() else { break };
                self.popped.push(v);
            }
        }
    }

    #[derive(Debug, Clone)]
    enum InBufferTrans {
        Push(u8),
        ScanPop([bool; 64]),
    }

    struct RefInBuffer;

    impl ReferenceStateMachine for RefInBuffer {
        type State = RefBuffer;
        type Transition = InBufferTrans;

        fn init_state() -> BoxedStrategy<Self::State> {
            LazyJust::new(RefBuffer::new).boxed()
        }

        fn transitions(_: &Self::State) -> BoxedStrategy<Self::Transition> {
            prop_oneof![
                (1u8..=64).prop_map(InBufferTrans::Push),
                any::<[bool; 64]>().prop_map(InBufferTrans::ScanPop),
            ]
            .boxed()
        }

        fn apply(mut state: Self::State, trans: &Self::Transition) -> Self::State {
            match *trans {
                InBufferTrans::Push(n) => state.push(n),
                InBufferTrans::ScanPop(ref v) => state.scan_pop(v),
            }

            state
        }
    }

    struct InBufferTest {
        buf: InBuffer<u64>,
        i: u64,
        popped: Vec<u64>,
    }

    impl StateMachineTest for InBufferTest {
        type SystemUnderTest = Self;
        type Reference = RefInBuffer;

        fn init_test(
            _: &<Self::Reference as ReferenceStateMachine>::State,
        ) -> Self::SystemUnderTest {
            InBufferTest {
                buf: InBuffer::new(),
                i: 0,
                popped: Vec::new(),
            }
        }

        fn apply(
            mut state: Self::SystemUnderTest,
            _: &<Self::Reference as ReferenceStateMachine>::State,
            trans: <Self::Reference as ReferenceStateMachine>::Transition,
        ) -> Self::SystemUnderTest {
            state.popped.clear();
            match trans {
                InBufferTrans::Push(n) => {
                    for _ in 0..n {
                        if state.buf.is_full() {
                            break;
                        }

                        state.buf.push(state.i);
                        state.i = state.i.wrapping_add(1);
                    }
                }
                InBufferTrans::ScanPop(v) => {
                    let mut it = v.into_iter();
                    state
                        .buf
                        .scan_pop(|v| {
                            if it.next().unwrap() {
                                state.popped.push(v.take().unwrap());
                            }
                            Ok::<(), ()>(())
                        })
                        .unwrap();
                }
            }

            state
        }

        fn check_invariants(
            state: &Self::SystemUnderTest,
            ref_state: &<Self::Reference as ReferenceStateMachine>::State,
        ) {
            assert_eq!(state.popped, ref_state.popped);
            assert_eq!(state.i, ref_state.i);

            let mut flags = [false; 64];
            let mut i = state.buf.head;
            let mut p = 64;
            let mut n = 0;

            while i != 64 {
                let ix = usize::from(i);
                assert!(
                    !flags[ix],
                    "loopback at reference index {n} and bufer index {i}"
                );
                flags[ix] = true;

                assert_eq!(
                    state.buf.buffer[ix],
                    Some(ref_state.buf[n]),
                    "value mismatch at reference index {n} and bufer index {i}"
                );
                assert_eq!(
                    state.buf.index[ix].1, p,
                    "previous index mismatch at reference index {n} and bufer index {i}"
                );

                (p, i) = (i, state.buf.index[ix].0);
                n += 1;
            }

            assert_eq!(
                state.buf.tail, p,
                "tail mismatch at reference index {n} and bufer index {i}"
            );
        }
    }

    #[derive(Debug, Clone)]
    enum OutBufferTrans {
        PushBack(u8),
        PushFront(u8),
        Pop(u8),
    }

    struct RefOutBuffer;

    impl ReferenceStateMachine for RefOutBuffer {
        type State = RefBuffer;
        type Transition = OutBufferTrans;

        fn init_state() -> BoxedStrategy<Self::State> {
            LazyJust::new(RefBuffer::new).boxed()
        }

        fn transitions(_: &Self::State) -> BoxedStrategy<Self::Transition> {
            prop_oneof![
                (1u8..=64).prop_map(OutBufferTrans::PushBack),
                (1u8..=64).prop_map(OutBufferTrans::PushFront),
                (1u8..=64).prop_map(OutBufferTrans::Pop),
            ]
            .boxed()
        }

        fn apply(mut state: Self::State, trans: &Self::Transition) -> Self::State {
            match *trans {
                OutBufferTrans::PushBack(n) => state.push(n),
                OutBufferTrans::PushFront(n) => state.push_front(n),
                OutBufferTrans::Pop(n) => state.pop(n),
            }

            state
        }
    }

    struct OutBufferTest {
        buf: OutBuffer<u64>,
        i: u64,
        popped: Vec<u64>,
    }

    impl StateMachineTest for OutBufferTest {
        type SystemUnderTest = Self;
        type Reference = RefOutBuffer;

        fn init_test(
            _: &<Self::Reference as ReferenceStateMachine>::State,
        ) -> Self::SystemUnderTest {
            OutBufferTest {
                buf: OutBuffer::new(),
                i: 0,
                popped: Vec::new(),
            }
        }

        fn apply(
            mut state: Self::SystemUnderTest,
            _: &<Self::Reference as ReferenceStateMachine>::State,
            trans: <Self::Reference as ReferenceStateMachine>::Transition,
        ) -> Self::SystemUnderTest {
            state.popped.clear();
            match trans {
                OutBufferTrans::PushBack(n) => {
                    for _ in 0..n {
                        if state.buf.is_full() {
                            break;
                        }

                        state.buf.push_back(state.i);
                        state.i = state.i.wrapping_add(1);
                    }
                }
                OutBufferTrans::PushFront(n) => {
                    for _ in 0..n {
                        if state.buf.is_full() {
                            break;
                        }

                        state.buf.push_front(state.i);
                        state.i = state.i.wrapping_add(1);
                    }
                }
                OutBufferTrans::Pop(n) => {
                    for _ in 0..n {
                        let Some(v) = state.buf.pop() else { break };
                        state.popped.push(v);
                    }
                }
            }

            state
        }

        fn check_invariants(
            state: &Self::SystemUnderTest,
            ref_state: &<Self::Reference as ReferenceStateMachine>::State,
        ) {
            assert_eq!(state.popped, ref_state.popped);
            assert_eq!(state.i, ref_state.i);

            assert_eq!(state.buf.len as usize, ref_state.len());
            for i in 0..state.buf.len {
                let ix = usize::from((state.buf.head as i8 - i as i8).rem_euclid(64) as u8);
                assert_eq!(
                    state.buf.buffer[ix],
                    Some(ref_state.buf[ref_state.len() - 1 - i as usize]),
                    "value mismatch at index {i}"
                );
            }
        }
    }

    prop_state_machine! {
        #[test]
        fn test_in_buffer(sequential 1..64 => InBufferTest);
        #[test]
        fn test_out_buffer(sequential 1..64 => OutBufferTest);
    }
}
