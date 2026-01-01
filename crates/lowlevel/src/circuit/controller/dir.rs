use std::collections::{HashSet, VecDeque};
use std::mem::{replace, take};
use std::num::{NonZeroU16, NonZeroU32};
use std::time::{Duration, Instant};

use futures_channel::oneshot::{Receiver, Sender, channel};
use tracing::{debug, info, instrument, trace, warn};

use crate::cache::{Cached, CellCache, CellCacheExt};
use crate::cell::create::CreatedFast;
use crate::cell::destroy::{Destroy, DestroyReason};
use crate::cell::relay::begin::RelayBegin;
use crate::cell::relay::begin_dir::RelayBeginDir;
use crate::cell::relay::data::RelayData;
use crate::cell::relay::drop::RelayDrop;
use crate::cell::relay::end::{EndReason, RelayEnd};
use crate::cell::relay::sendme::{RelaySendme, SendmeData};
use crate::cell::relay::v0::RelayExt;
use crate::cell::relay::{IntoRelay, Relay, RelayEarly, RelayVersion, cast as cast_r};
use crate::cell::{Cell, FixedCell, cast};
use crate::circuit::controller::CircuitController;
use crate::circuit::{CircuitInput, CircuitOutput, NewStream};
use crate::crypto::onion::{CircuitDigest, OnionLayer, OnionLayer128, OnionLayerFast, RelayDigest};
use crate::errors;
use crate::runtime::{Runtime, TrySendError};
use crate::util::cell_map::{IDGeneratorExt as _, NewHandler, StreamIDGenerator};
use crate::util::sans_io::event::{
    ChannelClosed, ChildCellMsg, ControlMsg, ParentCellMsg, Timeout,
};
use crate::util::sans_io::{CellMsgPause, Handle};
use crate::util::{GenerationalData, InBuffer, OutBuffer, print_hex};

/// Trait for [`DirController`] configuration type.
pub trait DirConfig {
    /// Cell cache.
    type Cache: 'static + Send + Sync + Clone + CellCache;

    /// Get [`CellCache`].
    ///
    /// # Implementer's Note
    ///
    /// To maximize cache utilization, cache should be as global as possible.
    fn get_cache(&self) -> &Self::Cache;

    /// Gets which SENDME type should be used.
    ///
    /// By default it'll return [`SendmeType::Disabled`].
    ///
    /// NOTE: It's only called once during controller setup. It will not be called again.
    fn sendme(&self) -> SendmeType {
        SendmeType::Disabled
    }
}

#[derive(Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum SendmeType {
    /// Do not use SENDME at all.
    Disabled,
    /// Use version 0 unauthenticated SENDME.
    Unauth,
    /// Use version 1 authenticated SENDME.
    Auth,
}

struct CfgData<C: DirConfig> {
    cfg: C,
    circ_id: GenerationalData<NonZeroU32>,
    linkver: u16,
}

impl<Cfg: DirConfig> CellCache for CfgData<Cfg> {
    fn get_cached(&self) -> FixedCell {
        self.cfg.get_cache().get_cached()
    }

    fn cache_cell(&self, cell: FixedCell) {
        self.cfg.get_cache().cache_cell(cell);
    }
}

/// Directory circuit controller.
///
/// Creates a one-hop circuit, suitable for directory streams.
/// It cannot open remote-requested circuit, only user-initiated.
///
/// # Configuration
///
/// Controller's coniguration type must implement [`DirConfig`].
///
/// # User's Notes
///
/// - Controller **does not** automatically send RELAY_BEGIN_DIR cell.
///
///   It is the responsibility of stream controller to do so.
/// - Stream controllers **must not** send any cell with circuit ID other than their own.
/// - To gracefully shutdown circuit, do the following:
///
///   1. Send RELAY_END cell.
///   2. Receive and drop all cells until receiver is closed.
///
///   Controller will automatically intercept RELAY_END cells to properly clean up circuit on it's end.
/// - Non-graceful stream shutdown (AKA receiver gets dropped) will be detected in 5 seconds or upon any cell received.
pub struct DirController<R: Runtime, C: DirConfig> {
    cfg: CfgData<C>,
    state: State<R, C>,

    last_packet: Option<Instant>,
    is_timeout: bool,
}

#[allow(clippy::large_enum_variant)]
enum State<R: Runtime, C: DirConfig> {
    Init(InitState<R, C::Cache>),
    Steady(SteadyState<R, C::Cache>),
    Shutdown,
}

/// Sender for the resulting [`NewStream`].
pub type NewStreamSender<R, C> = Sender<
    Result<NewStream<GenerationalData<NonZeroU16>, R, RelayTy<C>>, errors::NoFreeCircIDError>,
>;
/// Receiver for the resulting [`NewStream`].
pub type NewStreamReceiver<R, C> = Receiver<
    Result<NewStream<GenerationalData<NonZeroU16>, R, RelayTy<C>>, errors::NoFreeCircIDError>,
>;

type PendingOpen<R, C> = VecDeque<NewStreamSender<R, C>>;
type CellTy<Cache, C = Cell> = Cached<GenerationalData<C>, Cache>;
type RelayTy<Cache> = CellTy<Cache, Relay>;
type CIn<'a, 'b, R, C> = CircuitInput<'a, 'b, R, RelayTy<C>, CellTy<C>, DirStreamMeta>;

pub enum DirControlMsg<R: Runtime, C: DirConfig> {
    Shutdown,
    /// Create new stream.
    NewStream(NewStreamSender<R, C::Cache>),
}

impl<R: Runtime, C: DirConfig> DirControlMsg<R, C> {
    pub fn new_stream() -> (NewStreamReceiver<R, C::Cache>, Self) {
        let (send, recv) = channel();
        (recv, Self::NewStream(send))
    }
}

/// [`DirController`] circuit metadata type.
///
/// It is marked public only for [`CircuitController`] purposes.
/// It cannot be created.
pub struct DirStreamMeta {
    /// Mark if peer is closing stream.
    peer_close: bool,

    /// Generation.
    generation: u64,
}

impl<R: Runtime, C: DirConfig> Drop for DirController<R, C> {
    fn drop(&mut self) {
        if let State::Steady(s) = replace(&mut self.state, State::Shutdown) {
            self.cfg
                .cfg
                .get_cache()
                .discard((s.in_buffer, s.out_buffer, s.cell_send));
        }
    }
}

impl<R: Runtime, C: DirConfig> DirController<R, C> {
    pub fn is_init(&self) -> bool {
        matches!(self.state, State::Init(_))
    }

    pub fn is_shutdown(&self) -> bool {
        matches!(self.state, State::Shutdown)
    }
}

impl<R: 'static + Runtime, C: 'static + Send + Sync + DirConfig> CircuitController
    for DirController<R, C>
{
    type Runtime = R;
    type Config = C;
    type Error = errors::DirControllerError;
    type CircID = GenerationalData<NonZeroU32>;
    type ControlMsg = DirControlMsg<R, C>;
    type Cell = CellTy<C::Cache>;
    type StreamCell = RelayTy<C::Cache>;
    type StreamMeta = DirStreamMeta;

    fn new(cfg: C, circ_id: GenerationalData<NonZeroU32>) -> Self {
        let sendme = cfg.sendme();
        let cfg = CfgData {
            circ_id,
            linkver: 0,
            cfg,
        };
        Self {
            state: State::Init(InitState::new(&cfg, sendme)),
            cfg,

            last_packet: None,
            is_timeout: false,
        }
    }

    fn set_linkver(&mut self, linkver: u16) {
        self.cfg.linkver = linkver;
    }

    fn error_reason(err: Self::Error) -> DestroyReason {
        match err {
            // TODO: Map error code
            errors::DirControllerError::CircuitProtocolError(_)
            | errors::DirControllerError::CircuitHandshakeError(_)
            | errors::DirControllerError::InvalidCellHeader(_)
            | errors::DirControllerError::CellFormatError(_) => DestroyReason::Protocol,
            errors::DirControllerError::CipherError(_)
            | errors::DirControllerError::CellDigestError(_) => DestroyReason::None,
            _ => DestroyReason::Internal,
        }
    }

    fn make_destroy_cell(&mut self, reason: DestroyReason) -> Self::Cell {
        self.cfg.cfg.get_cache().cache(GenerationalData::new(
            Destroy::new(self.cfg.get_cached(), self.cfg.circ_id.inner, reason).into(),
            self.cfg.circ_id.generation,
        ))
    }
}

impl<'a, 'b, R: Runtime, C: DirConfig> Handle<(&'a R, CIn<'a, 'b, R, C::Cache>)>
    for DirController<R, C>
{
    type Return = Result<CircuitOutput, errors::DirControllerError>;

    #[instrument(level = "trace", skip_all)]
    fn handle(
        &mut self,
        (rt, input): (&'a R, CIn<'a, 'b, R, C::Cache>),
    ) -> Result<CircuitOutput, errors::DirControllerError> {
        let last_packet = self
            .last_packet
            .get_or_insert_with(|| input.time() + CREATE_TIMEOUT);
        let is_timeout = take(&mut self.is_timeout);

        let (out, is_shutdown) = match self.state {
            State::Init(ref mut s) => s.handle(is_timeout, last_packet, &self.cfg, input),
            State::Steady(ref mut s) => s.handle(is_timeout, last_packet, &self.cfg, rt, input),
            State::Shutdown => {
                let mut output = CircuitOutput::new();
                output.shutdown(DestroyReason::default());
                return Ok(output);
            }
        }?;

        if is_shutdown {
            self.state = State::Shutdown;
        }
        Ok(out)
    }
}

impl<R: Runtime, C: DirConfig> Handle<Timeout> for DirController<R, C> {
    type Return = Result<(), errors::DirControllerError>;

    fn handle(&mut self, _: Timeout) -> Result<(), errors::DirControllerError> {
        self.is_timeout = true;
        Ok(())
    }
}

impl<R: Runtime, C: DirConfig> Handle<ControlMsg<DirControlMsg<R, C>>> for DirController<R, C> {
    type Return = Result<(), errors::DirControllerError>;

    #[instrument(level = "trace", name = "handle_control", skip_all)]
    fn handle(
        &mut self,
        msg: ControlMsg<DirControlMsg<R, C>>,
    ) -> Result<(), errors::DirControllerError> {
        match msg.0 {
            DirControlMsg::Shutdown => {
                self.state = State::Shutdown;
                Ok(())
            }
            DirControlMsg::NewStream(v) => {
                debug!("queueing new stream");
                match &mut self.state {
                    State::Init(v) => &mut v.pending_open,
                    State::Steady(v) => &mut v.pending_open,
                    State::Shutdown => return Ok(()),
                }
                .push_back(v);
                Ok(())
            }
        }
    }
}

impl<R: Runtime, C: DirConfig> Handle<ParentCellMsg<CellTy<C::Cache>>> for DirController<R, C> {
    type Return = Result<CellMsgPause, errors::DirControllerError>;

    #[instrument(level = "trace", name = "handle_parent", skip_all)]
    fn handle(
        &mut self,
        msg: ParentCellMsg<CellTy<C::Cache>>,
    ) -> Result<CellMsgPause, errors::DirControllerError> {
        let id = GenerationalData::new(msg.0.inner.circuit, msg.0.generation);
        if id != self.cfg.circ_id.map(u32::from) {
            warn!(%id, "discard invalid circuit ID cell");
            return Ok(CellMsgPause(false));
        }

        match self.state {
            State::Init(ref mut s) => {
                if let Some(s) = s.handle_cell(&self.cfg, msg.0)? {
                    self.state = State::Steady(s);
                }
                Ok(CellMsgPause(false))
            }
            State::Steady(ref mut s) => s.handle_cell(&self.cfg, msg.0),
            State::Shutdown => Ok(CellMsgPause(true)),
        }
    }
}

impl<R: Runtime, C: DirConfig> Handle<ChildCellMsg<RelayTy<C::Cache>>> for DirController<R, C> {
    type Return = Result<CellMsgPause, errors::DirControllerError>;

    #[instrument(level = "trace", name = "handle_child", skip_all)]
    fn handle(
        &mut self,
        msg: ChildCellMsg<RelayTy<C::Cache>>,
    ) -> Result<CellMsgPause, errors::DirControllerError> {
        debug_assert_eq!(msg.0.inner.circuit, self.cfg.circ_id.inner);

        match self.state {
            State::Init(_) => {
                panic!("state should not receive stream cell message")
            }
            State::Steady(ref mut s) => s.handle_stream_cell(&self.cfg, msg.0),
            State::Shutdown => Ok(CellMsgPause(true)),
        }
    }
}

impl<'a, R: Runtime, C: DirConfig>
    Handle<ChannelClosed<'a, NonZeroU16, RelayTy<C::Cache>, DirStreamMeta>>
    for DirController<R, C>
{
    type Return = Result<(), errors::DirControllerError>;

    #[instrument(level = "trace", name = "handle_close", skip_all, fields(id = msg.id))]
    fn handle(
        &mut self,
        msg: ChannelClosed<'a, NonZeroU16, RelayTy<C::Cache>, DirStreamMeta>,
    ) -> Result<(), errors::DirControllerError> {
        match self.state {
            State::Steady(ref mut s) => {
                s.scan_cells = true;
                if !msg.meta.peer_close {
                    let id = msg.id;
                    debug!(id, "stream is closing");
                    if s.closing.insert(id) {
                        s.pending_close.push_back((id, EndReason::Misc));
                    }
                }
            }
            State::Shutdown => (),
            State::Init(_) => unreachable!("state should not open any stream"),
        }
        Ok(())
    }
}

struct InitState<R: Runtime, C: 'static + Send + Sync + Clone + CellCache> {
    data: Option<(OnionLayerFast, SendmeType)>,
    cell: Option<Cell>,
    pending_open: PendingOpen<R, C>,
}

const CREATE_TIMEOUT: Duration = Duration::from_secs(10);

impl<R: Runtime, C: 'static + Send + Sync + Clone + CellCache> InitState<R, C> {
    fn new<CC: DirConfig<Cache = C>>(cfg: &CfgData<CC>, sendme: SendmeType) -> Self {
        let client = OnionLayerFast::new();

        Self {
            cell: Some(client.create_cell(cfg.circ_id.inner, cfg).into()),
            data: Some((client, sendme)),
            pending_open: PendingOpen::new(),
        }
    }

    #[instrument(level = "debug", skip_all)]
    fn handle<CC: DirConfig<Cache = C>>(
        &mut self,
        is_timeout: bool,
        last_packet: &mut Instant,
        cfg: &CfgData<CC>,
        mut input: CIn<'_, '_, R, C>,
    ) -> Result<(CircuitOutput, bool), errors::DirControllerError> {
        if is_timeout && *last_packet <= input.time() {
            let mut out = CircuitOutput::new();
            info!("circuit creation timed out, shutting down");
            out.shutdown(DestroyReason::Timeout);
            return Ok((out, true));
        }

        if self.cell.is_some() {
            input.try_send(|| {
                cfg.cfg.get_cache().cache(GenerationalData::new(
                    self.cell.take().expect("cell must be Some"),
                    cfg.circ_id.generation,
                ))
            });
        }

        let mut out = CircuitOutput::new();
        out.timeout(*last_packet)
            .parent_cell_msg_pause(CellMsgPause(false))
            .child_cell_msg_pause(CellMsgPause(true));
        Ok((out, false))
    }

    #[instrument(level = "debug", skip_all)]
    fn handle_cell<CC: DirConfig<Cache = C>>(
        &mut self,
        cfg: &CfgData<CC>,
        cell: CellTy<C>,
    ) -> Result<Option<SteadyState<R, C>>, errors::DirControllerError> {
        let mut cell = Cached::map(cell, |c| Some(c.inner));

        if let Some(cell) = cast::<CreatedFast>(&mut cell)? {
            let cell = cfg.cache_b(cell);
            let (client, sendme_ty) = self.data.take().expect("client params must exist");
            let layer = client.derive_client(&cell)?;

            debug!("initialization finished");

            return Ok(Some(SteadyState {
                encrypt: layer.encrypt,
                digest: layer.digest,
                early_cnt: 8,

                in_buffer: InBuffer::new(),
                out_buffer: OutBuffer::new(),
                cell_send: None,
                pause_out_buffer: false,
                scan_cells: false,
                has_new_cells: false,

                pending_close: VecDeque::new(),
                pending_open: take(&mut self.pending_open),
                closing: HashSet::new(),
                generation: 0,

                sendme_ty,
                forward_data_count: 1000,
                backward_data_count: 1000,
                forward_data_modulo: 0,
                backward_data_modulo: 0,
                forward_sendme_digest: VecDeque::new(),
                backward_sendme_digest: VecDeque::new(),
            }));
        } else if let Some(cell) = cast::<Destroy>(&mut cell)? {
            let cell = cfg.cache_b(cell);
            warn!(reason = %cell.display_reason(), "circuit destroyed");
            return Err(errors::ChannelClosedError.into());
        }

        if let Some(cell) = Cached::transpose(cell) {
            warn!(command = cell.command, "discarding unknown cell");
        }
        Ok(None)
    }
}

struct SteadyState<R: Runtime, C: 'static + Send + Sync + Clone + CellCache> {
    encrypt: OnionLayer128,
    digest: CircuitDigest,
    early_cnt: u8,

    in_buffer: InBuffer<Relay>,
    out_buffer: OutBuffer<GenerationalData<Relay>>,
    cell_send: Option<Cell>,
    pause_out_buffer: bool,
    scan_cells: bool,
    has_new_cells: bool,

    pending_close: VecDeque<(NonZeroU16, EndReason)>,
    pending_open: PendingOpen<R, C>,
    closing: HashSet<NonZeroU16>,
    generation: u64,

    sendme_ty: SendmeType,
    forward_data_count: usize,
    backward_data_count: usize,
    forward_data_modulo: u8,
    backward_data_modulo: u8,
    forward_sendme_digest: VecDeque<[u8; 20]>,
    backward_sendme_digest: VecDeque<[u8; 20]>,
}

const IDLE_TIMEOUT: Duration = Duration::from_secs(60);

#[inline]
fn update_last_packet<R: Runtime, C: 'static + Send + Sync + Clone + CellCache>(
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
    fn handle<CC: DirConfig<Cache = C>>(
        &mut self,
        is_timeout: bool,
        last_packet: &mut Instant,
        cfg: &CfgData<CC>,
        rt: &R,
        mut input: CIn<'_, '_, R, C>,
    ) -> Result<(CircuitOutput, bool), errors::DirControllerError> {
        if self.has_new_cells {
            update_last_packet(last_packet, &input);
        }

        if is_timeout && *last_packet <= input.time() {
            let mut out = CircuitOutput::new();
            info!("circuit idled for 1 minutes, gracefully shutting down");
            out.shutdown(DestroyReason::Finished);
            return Ok((out, true));
        }

        // Scan input buffer
        if take(&mut self.scan_cells) {
            self.in_buffer.scan_pop(|p| {
                let Some(cell) = p else {
                    return Ok(());
                };

                let id = cell.stream();
                if NonZeroU16::new(id).is_none_or(|id| !input.stream_map().has(&id)) {
                    // Discard all unmapped stream ID
                    trace!(
                        id,
                        command = cell.command(),
                        "discard unmapped stream ID in cell"
                    );
                    cfg.discard(p.take());
                    return Ok(());
                }

                Ok::<(), errors::DirControllerError>(())
            })?;
        }

        // Process pending open
        for send in self.pending_open.drain(..) {
            let r = input
                .stream_map()
                .open_with(
                    rt,
                    StreamIDGenerator::new().filter(|id| !self.closing.contains(id)),
                    64,
                    |_| DirStreamMeta {
                        peer_close: false,
                        generation: self.generation,
                    },
                )
                .map(|(v, mut h)| {
                    NewStream::new(
                        v.map_id(|id| GenerationalData::new(id, h.meta().generation)),
                        cfg.circ_id.inner,
                    )
                });
            if r.is_ok() {
                self.generation = self.generation.wrapping_add(1);
            }
            if let Err(Ok(NewStream {
                inner: NewHandler { id, .. },
                ..
            })) = send.send(r)
            {
                debug_assert_eq!(id.generation, self.generation);
                // Instantly discards newly created stream
                input.stream_map().remove(&id.inner);
                self.generation = self.generation.wrapping_sub(1);
            }
        }

        let mut flags = 0u8;
        loop {
            // Process read cells
            if flags & FLAG_READ == 0 {
                flags = self.read_handler(cfg, &mut input, flags)?;
            }

            // Process write cells
            if flags & (FLAG_WRITE | FLAG_WRITE_EMPTY) == 0 {
                flags = self.write_handler(last_packet, cfg, &mut input, flags)?;
            }

            trace!(flags, "processing");
            if flags & FLAG_READ != 0 && flags & (FLAG_WRITE | FLAG_WRITE_EMPTY) != 0 {
                break;
            }
        }

        let mut out = CircuitOutput::new();
        out.timeout(*last_packet)
            .parent_cell_msg_pause(CellMsgPause(self.in_buffer.is_full()))
            .child_cell_msg_pause(CellMsgPause(self.out_buffer.is_full()));

        Ok((out, false))
    }

    #[instrument(level = "debug", skip_all)]
    fn handle_cell<CC: DirConfig<Cache = C>>(
        &mut self,
        cfg: &CfgData<CC>,
        cell: CellTy<C>,
    ) -> Result<CellMsgPause, errors::DirControllerError> {
        let mut cell = cfg.cache_b({
            let mut cell = Cached::map(cell, |c| Some(c.inner));
            if let Some(cell) = cast::<Relay>(&mut cell)? {
                cell
            } else if let Some(cell) = cast::<RelayEarly>(&mut cell)? {
                cell.into()
            } else if let Some(cell) = cast::<Destroy>(&mut cell)? {
                let cell = cfg.cache_b(cell);
                warn!(reason = %cell.display_reason(), "circuit destroyed");
                return Err(errors::ChannelClosedError.into());
            } else {
                let cell = Cached::transpose(cell).unwrap();
                return Err(errors::InvalidCellHeader::with_cell(&cell).into());
            }
        });

        // Decrypt and check digest cell
        self.encrypt.decrypt_backward((*cell).as_mut())?;
        let digest = self.digest.unwrap_digest_backward((*cell).as_mut())?;

        let command = cell.command();
        let stream = cell.stream();

        if stream != 0 {
            // Stream cell, queue it for streams.
            if self.sendme_ty != SendmeType::Disabled && command == RelayData::ID {
                // Data-bearing cell, decrement backward data counter.
                self.backward_data_count = match self.backward_data_count.checked_sub(1) {
                    Some(v) => v,
                    None => {
                        return Err(errors::CircuitProtocolError(
                            errors::CircuitProtocolInner::BucketUnderflow,
                        )
                        .into());
                    }
                };

                self.backward_data_modulo += 1;
                debug_assert!(self.backward_data_modulo <= 100);
                if self.backward_data_modulo == 100 {
                    // Every 100 decrement, send a SENDME cell.
                    self.backward_data_modulo = 0;
                    self.backward_sendme_digest.push_back(digest);
                }
            }

            self.in_buffer.push(Cached::into_inner(cell));
            self.scan_cells = true;
            self.has_new_cells = true;
        } else {
            let mut cell = Cached::map(cell, Some);
            if let Some(cell) = cast_r::<RelayDrop>(&mut cell, RelayVersion::V0)? {
                // RELAY_DROP is for long-range padding
                cfg.discard(cell);
            } else if let Some(cell) = cast_r::<RelaySendme>(&mut cell, RelayVersion::V0)? {
                // RELAY_SENDME, check digest and increment forward data counter.
                let cell = cfg.cache_b(cell);

                // Only proceed only if sendme handling is enabled.
                if self.sendme_ty != SendmeType::Disabled {
                    let digest = match cell.data() {
                        None | Some(SendmeData::Unauth) => None,
                        Some(SendmeData::Auth(digest)) => Some(digest),
                    };
                    match (digest, self.backward_sendme_digest.pop_front()) {
                        (_, None) => {
                            return Err(errors::CircuitProtocolError(
                                errors::CircuitProtocolInner::UnexpectedSendme,
                            )
                            .into());
                        }
                        (None, _) => (),
                        (Some(a), Some(b)) if a == b => (),
                        (Some(a), Some(b)) => {
                            debug!(
                                expect = %print_hex(&b),
                                sent = %print_hex(&a),
                                "SENDME digest mismatch"
                            );
                            return Err(errors::CircuitProtocolError(
                                errors::CircuitProtocolInner::SendmeDigest,
                            )
                            .into());
                        }
                    }

                    self.forward_data_count = self
                        .forward_data_count
                        .checked_add(100)
                        .expect("token bucket overflow");
                }
            }

            if let Some(cell) = Cached::transpose(cell) {
                // NOTE: Potential protocol violation
                trace!("unhandled cell with command {} received", cell.command());
            }
        }

        Ok(CellMsgPause(self.in_buffer.is_full()))
    }

    #[instrument(level = "debug", skip_all)]
    fn handle_stream_cell<CC: DirConfig<Cache = C>>(
        &mut self,
        _: &CfgData<CC>,
        cell: RelayTy<C>,
    ) -> Result<CellMsgPause, errors::DirControllerError> {
        self.out_buffer.push_back(Cached::into_inner(cell));

        Ok(CellMsgPause(self.out_buffer.is_full()))
    }

    #[inline(always)]
    fn read_handler<CC: DirConfig<Cache = C>>(
        &mut self,
        cfg: &CfgData<CC>,
        input: &mut CIn<'_, '_, R, C>,
        mut flags: u8,
    ) -> Result<u8, errors::DirControllerError> {
        // Process in buffer.
        if take(&mut self.has_new_cells) || (input.has_ready() && flags & FLAG_TRY_SEND_CELLS == 0)
        {
            self.in_buffer.scan_pop(|p| {
                let is_begin = if let Some(cell) = cast_r::<RelayBegin>(p, RelayVersion::V0)? {
                    cfg.discard(cell);
                    true
                } else if let Some(cell) = cast_r::<RelayBeginDir>(p, RelayVersion::V0)? {
                    cfg.discard(cell);
                    true
                } else {
                    false
                };
                if is_begin {
                    return Err(errors::CircuitProtocolError(
                        errors::CircuitProtocolInner::RelayBegin,
                    )
                    .into());
                }

                let Some(cell) = p else {
                    return Ok(());
                };
                let id = NonZeroU16::new(cell.stream()).expect("stream ID should not be zero");
                let mut stream_map = input.stream_map();
                let Some(mut stream) = stream_map.get(&id) else {
                    // Discard all unmapped stream ID.
                    debug!(
                        id,
                        command = cell.command(),
                        "discard unmapped stream ID cell"
                    );
                    *p = None;
                    return Ok(());
                };
                if !stream.is_ready() {
                    // Circuit is not ready
                    return Ok(());
                }

                if let Some(cell) = cast_r::<RelayEnd>(p, RelayVersion::V0)? {
                    // RELAY_END cell received, closing stream.
                    let cell = cfg.cfg.get_cache().cache(cell);
                    let reason = cell.reason();
                    let cell = Cached::map(
                        <_>::try_into_relay_cached(cell, cfg.circ_id.inner, RelayVersion::V0)?,
                        |cell| GenerationalData::new(cell, stream.meta().generation),
                    );
                    match stream.try_send(cell) {
                        Ok(()) => {
                            debug!(id, %reason, "peer is closing stream");
                            stream.meta().peer_close = true;
                            stream.start_close();
                        }
                        Err(TrySendError::NotReady(cell)) => {
                            *p = Some(Cached::into_inner(cell).into_inner())
                        }
                        // Stream is closed while peer is closing.
                        Err(TrySendError::Disconnected(_)) => {
                            stream.meta().peer_close = true;
                            debug!(id, %reason, "discard DESTROY cell, stream is closed")
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
                    .cache(GenerationalData::new(cell, stream.meta().generation));

                match stream.try_send(cell) {
                    // Success
                    Ok(()) => {
                        trace!(id, "sending in cell to stream");
                    }
                    // Not ready, return cell
                    Err(TrySendError::NotReady(cell)) => {
                        *p = Some(Cached::into_inner(cell).into_inner());
                        trace!(id, "cannot send cell, stream is not ready");
                    }
                    // Stream is closed, drop cell
                    Err(TrySendError::Disconnected(_)) => {
                        trace!(id, "cannot send cell, stream is closed");
                    }
                }

                Ok::<(), errors::DirControllerError>(())
            })?;
            flags |= FLAG_TRY_SEND_CELLS;
        }

        flags |= FLAG_READ;

        Ok(flags)
    }

    #[inline(always)]
    fn write_handler<CC: DirConfig<Cache = C>>(
        &mut self,
        last_packet: &mut Instant,
        cfg: &CfgData<CC>,
        input: &mut CIn<'_, '_, R, C>,
        mut flags: u8,
    ) -> Result<u8, errors::DirControllerError> {
        if input.is_ready() && self.cell_send.is_some() {
            if input.try_send(|| {
                cfg.cfg.get_cache().cache(GenerationalData::new(
                    self.cell_send.take().expect("cell must be Some"),
                    cfg.circ_id.generation,
                ))
            }) {
                update_last_packet(last_packet, input);
            } else {
                flags |= FLAG_WRITE;
                return Ok(flags);
            }
        }

        let mut found: Option<Cached<Relay, _>> = None;
        let mut is_data = false;

        while found.is_none() {
            let Some((id, reason)) = self.pending_close.pop_front() else {
                break;
            };

            self.closing.remove(&id);

            // Prepend RELAY_END cell
            found = Some(
                cfg.cache_b(
                    RelayEnd::new(cfg.get_cached(), id, reason)
                        .try_into_relay(cfg.circ_id.inner, RelayVersion::V0)?,
                ),
            );
        }

        while found.is_none() {
            let Some(digest) = self.forward_sendme_digest.pop_front() else {
                break;
            };
            let data = match self.sendme_ty {
                SendmeType::Disabled => continue,
                SendmeType::Unauth => SendmeData::Unauth,
                SendmeType::Auth => SendmeData::Auth(digest),
            };

            // Prepend RELAY_SENDME cell
            found = Some(<_>::try_into_relay_cached(
                cfg.cache_b(RelaySendme::from_data(cfg.get_cached(), data)),
                cfg.circ_id.inner,
                RelayVersion::V0,
            )?);

            self.backward_data_count = self
                .backward_data_count
                .checked_add(100)
                .expect("token bucket overflow");
            self.pause_out_buffer = false;
        }

        while found.is_none() && !self.pause_out_buffer {
            let Some(GenerationalData {
                inner: cell,
                generation,
            }) = self.out_buffer.pop_front()
            else {
                break;
            };
            let cell = cfg.cache_b(cell);

            let mut stream_map = input.stream_map();
            let id = cell.stream();
            let Some(mut handle) = NonZeroU16::new(id)
                .and_then(|id| stream_map.get(&id))
                .and_then(|mut handle| {
                    let meta = handle.meta();
                    if meta.peer_close || meta.generation != generation {
                        return None;
                    }
                    Some(handle)
                })
            else {
                // Unmapped stream ID. Probably non-graceful shutdown.
                trace!(
                    id,
                    command = cell.command(),
                    "discard unmapped stream ID out cell"
                );
                continue;
            };
            let mut cell = Cached::map(cell, Some);

            found = if let Some(cell) = cast_r::<RelayEnd>(&mut cell, RelayVersion::V0)? {
                let cell = cfg.cache_b(cell);
                trace!(id = cell.stream, "sending RELAY_END cell, closing stream");
                handle.meta().peer_close = true;
                handle.start_close();

                Some(<_>::try_into_relay_cached(
                    cell,
                    cfg.circ_id.inner,
                    RelayVersion::V0,
                )?)
            } else if let Some(cell) = Cached::transpose(cell) {
                is_data = self.sendme_ty != SendmeType::Disabled && cell.command() == RelayData::ID;

                if is_data {
                    // Data-bearing cell, decrement forward data counter.
                    self.forward_data_count = match self.forward_data_count.checked_sub(1) {
                        Some(v) => v,
                        None => {
                            // Token bucket is empty, repush cell and pause out buffer.
                            self.out_buffer.push_front(GenerationalData::new(
                                Cached::into_inner(cell),
                                generation,
                            ));
                            self.pause_out_buffer = true;
                            return Ok(flags);
                        }
                    };

                    self.forward_data_modulo += 1;
                    debug_assert!(self.forward_data_modulo <= 100);
                    if self.forward_data_modulo == 100 {
                        self.forward_data_modulo = 0;
                    }
                }

                trace!(id = cell.stream(), "sending output cell");
                Some(cell)
            } else {
                None
            };
        }

        let Some(mut cell) = found else {
            // Nothing to write
            flags |= FLAG_WRITE_EMPTY;
            return Ok(flags);
        };

        // Set circuit ID.
        cell.circuit = cfg.circ_id.inner;

        // Encrypt and set digest,
        let digest = self.digest.wrap_digest_forward((*cell).as_mut());
        self.encrypt.encrypt_forward((*cell).as_mut())?;

        if is_data && self.forward_data_modulo == 0 {
            // Every 100 decrement, send a SENDME cell.
            self.forward_sendme_digest.push_back(digest);
        }

        let cell = Cached::into_inner(cell);
        self.cell_send = Some(match self.early_cnt {
            1.. => RelayEarly::from(cell).into(),
            0 => cell.into(),
        });
        self.early_cnt = self.early_cnt.saturating_sub(1);

        Ok(flags)
    }
}
