use std::collections::vec_deque::VecDeque;
use std::marker::PhantomData;
use std::mem::take;
use std::num::{NonZeroU16, NonZeroU32};
use std::sync::Arc;
use std::time::{Duration, Instant};

use flume::TrySendError;
use futures_channel::oneshot::{Receiver, Sender, channel};
use tracing::{debug, info, instrument, trace, warn};

use crate::cache::{Cached, CellCache, CellCacheExt};
use crate::cell::create::CreatedFast;
use crate::cell::destroy::{Destroy, DestroyReason};
use crate::cell::relay::begin::RelayBegin;
use crate::cell::relay::begin_dir::RelayBeginDir;
use crate::cell::relay::connected::RelayConnected;
use crate::cell::relay::data::RelayData;
use crate::cell::relay::drop::RelayDrop;
use crate::cell::relay::end::{EndReason, RelayEnd};
use crate::cell::relay::sendme::{RelaySendme, SendmeData};
use crate::cell::relay::{IntoRelay, Relay, RelayEarly, RelayLike, cast as cast_r};
use crate::cell::{Cell, cast};
use crate::circuit::controller::CircuitController;
use crate::circuit::{CircuitInput, CircuitOutput, NewStream};
use crate::crypto::onion::{CircuitDigest, OnionLayer, OnionLayer128, OnionLayerFast, RelayDigest};
use crate::errors;
use crate::util::cell_map::{CellMap, StreamIDGenerator};
use crate::util::sans_io::event::{ChildCellMsg, ControlMsg, ParentCellMsg, Timeout};
use crate::util::sans_io::{CellMsgPause, Handle};
use crate::util::{InBuffer, OutBuffer, option_ord_min, print_hex};

type CacheTy = Arc<dyn Send + Sync + CellCache>;
type CachedCell<C = Cell> = Cached<C, CacheTy>;
type PendingOpen =
    VecDeque<Sender<Result<NewStream<CachedCell<Relay>>, errors::NoFreeCircIDError>>>;
type StreamMap = CellMap<CachedCell<Relay>, DirStreamMeta>;
type NewStreamSender = Sender<Result<NewStream<CachedCell<Relay>>, errors::NoFreeCircIDError>>;

/// Trait for [`DirController`] configuration type.
pub trait DirConfig {
    /// Get [`CellCache`].
    ///
    /// # Implementer's Note
    ///
    /// To maximize cache utilization, cache should be as global as possible.
    fn get_cache(&self) -> Arc<dyn Send + Sync + CellCache>;

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

struct CfgData {
    cache: CacheTy,
    circ_id: NonZeroU32,
    linkver: u16,
}

pub struct DirController<Cfg> {
    cfg: CfgData,

    state: State,

    _p: PhantomData<Cfg>,
}

#[allow(clippy::large_enum_variant)]
enum State {
    Init(InitState),
    Steady(SteadyState),
    Shutdown,
}

#[derive(Debug)]
pub enum DirControlMsg {
    Shutdown,
    /// Create new stream.
    NewStream(NewStreamSender),
}

impl DirControlMsg {
    #[allow(clippy::type_complexity)]
    pub fn new_stream() -> (
        Receiver<Result<NewStream<CachedCell<Relay>>, errors::NoFreeCircIDError>>,
        Self,
    ) {
        let (send, recv) = channel();
        (recv, Self::NewStream(send))
    }
}

/// [`DirController`] circuit metadata type.
///
/// It is marked public only for [`CircuitController`] purposes.
/// It cannot be created.
pub struct DirStreamMeta {
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

    /// New stream data, will be resolved after receiving RELAY_CONNECTED.
    connect_resolve: Option<(NewStreamSender, NewStream<CachedCell<Relay>>)>,
}

impl<Cfg> Drop for DirController<Cfg> {
    fn drop(&mut self) {
        if let State::Steady(s) = &mut self.state {
            s.in_buffer.discard_all(&self.cfg.cache);
            s.out_buffer.discard_all(&self.cfg.cache);
            self.cfg.cache.discard(s.cell_send.take());
        }
    }
}

impl<Cfg> DirController<Cfg> {
    pub fn is_init(&self) -> bool {
        matches!(self.state, State::Init(_))
    }

    pub fn is_shutdown(&self) -> bool {
        matches!(self.state, State::Shutdown)
    }
}

impl<Cfg: 'static + Send + Sync + DirConfig> CircuitController for DirController<Cfg> {
    type Config = Cfg;
    type Error = errors::DirControllerError;
    type ControlMsg = DirControlMsg;
    type Cell = CachedCell;
    type StreamCell = CachedCell<Relay>;
    type StreamMeta = DirStreamMeta;

    fn new(cfg: Arc<dyn Send + Sync + AsRef<Self::Config>>, circ_id: NonZeroU32) -> Self {
        let cfg = (*cfg).as_ref();
        let sendme = cfg.sendme();
        let cfg = CfgData {
            circ_id,
            cache: cfg.get_cache(),
            linkver: 0,
        };
        Self {
            state: State::Init(InitState::new(&cfg, circ_id, sendme)),

            cfg,

            _p: PhantomData,
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
        self.cfg
            .cache
            .cache(Destroy::new(self.cfg.cache.get_cached(), self.cfg.circ_id, reason).into())
    }
}

impl<'a, Cfg>
    Handle<(
        CircuitInput<'a, CachedCell>,
        &'a mut CellMap<CachedCell<Relay>, DirStreamMeta>,
    )> for DirController<Cfg>
{
    type Return = Result<CircuitOutput, errors::DirControllerError>;

    #[instrument(level = "trace", skip_all)]
    fn handle(
        &mut self,
        (input, stream_map): (
            CircuitInput<'a, CachedCell>,
            &'a mut CellMap<CachedCell<Relay>, DirStreamMeta>,
        ),
    ) -> Result<CircuitOutput, errors::DirControllerError> {
        match self.state {
            State::Init(ref mut s) => s.handle(&self.cfg, input),
            State::Steady(ref mut s) => {
                let (out, is_shutdowun) = s.handle(&self.cfg, input, stream_map)?;
                if is_shutdowun {
                    self.state = State::Shutdown;
                }
                Ok(out)
            }
            State::Shutdown => {
                let mut output = CircuitOutput::new();
                output.shutdown(DestroyReason::default());
                Ok(output)
            }
        }
    }
}

impl<Cfg> Handle<Timeout> for DirController<Cfg> {
    type Return = Result<(), errors::DirControllerError>;

    fn handle(&mut self, _: Timeout) -> Result<(), errors::DirControllerError> {
        match self.state {
            State::Init(_) | State::Shutdown => (),
            State::Steady(ref mut s) => s.is_timeout = true,
        }

        Ok(())
    }
}

impl<Cfg> Handle<ControlMsg<DirControlMsg>> for DirController<Cfg> {
    type Return = Result<(), errors::DirControllerError>;

    #[instrument(level = "trace", skip_all, fields(msg))]
    fn handle(&mut self, msg: ControlMsg<DirControlMsg>) -> Result<(), errors::DirControllerError> {
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

impl<Cfg> Handle<ParentCellMsg<CachedCell>> for DirController<Cfg> {
    type Return = Result<CellMsgPause, errors::DirControllerError>;

    fn handle(
        &mut self,
        msg: ParentCellMsg<CachedCell>,
    ) -> Result<CellMsgPause, errors::DirControllerError> {
        match self.state {
            State::Init(ref mut s) => {
                self.state = State::Steady(s.handle_cell(&self.cfg, msg.0)?);
                Ok(CellMsgPause(false))
            }
            State::Steady(ref mut s) => s.handle_cell(&self.cfg, msg.0),
            State::Shutdown => Ok(CellMsgPause(true)),
        }
    }
}

impl<Cfg> Handle<ChildCellMsg<CachedCell<Relay>>> for DirController<Cfg> {
    type Return = Result<CellMsgPause, errors::DirControllerError>;

    fn handle(
        &mut self,
        msg: ChildCellMsg<CachedCell<Relay>>,
    ) -> Result<CellMsgPause, errors::DirControllerError> {
        match self.state {
            State::Init(_) => {
                panic!("state should not receive stream cell message")
            }
            State::Steady(ref mut s) => s.handle_stream_cell(&self.cfg, msg.0),
            State::Shutdown => Ok(CellMsgPause(true)),
        }
    }
}

struct InitState {
    data: Option<(OnionLayerFast, SendmeType)>,
    cell: Option<CachedCell>,
    timeout: Option<Instant>,
    pending_open: PendingOpen,
}

const CREATE_TIMEOUT: Duration = Duration::from_secs(10);

impl InitState {
    fn new(cfg: &CfgData, circ_id: NonZeroU32, sendme: SendmeType) -> Self {
        let client = OnionLayerFast::new();

        Self {
            cell: Some(Cached::map_into(client.create_cell(circ_id, &cfg.cache))),
            data: Some((client, sendme)),
            timeout: None,
            pending_open: PendingOpen::new(),
        }
    }

    #[instrument(level = "debug", skip_all, err)]
    fn handle<'a>(
        &mut self,
        _cfg: &CfgData,
        mut input: CircuitInput<'a, CachedCell>,
    ) -> Result<CircuitOutput, errors::DirControllerError> {
        let mut output = CircuitOutput::new();

        output
            .parent_cell_msg_pause(CellMsgPause(false))
            .child_cell_msg_pause(CellMsgPause(true));

        let timeout = *self
            .timeout
            .get_or_insert_with(|| input.time() + CREATE_TIMEOUT);
        output.timeout(timeout);

        if timeout <= input.time() {
            output.shutdown(DestroyReason::Timeout);
            return Ok(output);
        }

        if let Some(cell) = self.cell.take() {
            match input.try_send(cell) {
                Ok(()) => (),
                Err(TrySendError::Full(cell)) => self.cell = Some(cell),
                Err(TrySendError::Disconnected(_)) => return Err(errors::ChannelClosedError.into()),
            }
        }

        Ok(output)
    }

    #[instrument(level = "debug", skip_all, err)]
    fn handle_cell(
        &mut self,
        cfg: &CfgData,
        cell: CachedCell,
    ) -> Result<SteadyState, errors::DirControllerError> {
        let mut cell = Cached::map(cell, Some);

        if let Some(cell) = cast::<CreatedFast>(&mut cell)? {
            let (client, sendme_ty) = self.data.take().expect("client params must exist");
            let layer = client.derive_client(&(*cfg.cache).cache_b(cell))?;

            debug!("initialization finished");

            return Ok(SteadyState {
                encrypt: layer.encrypt,
                digest: layer.digest,
                early_cnt: 8,

                in_buffer: InBuffer::new(),
                out_buffer: OutBuffer::new(),
                cell_send: None,
                pause_out_buffer: false,

                pending_close: VecDeque::new(),
                pending_open: take(&mut self.pending_open),

                is_timeout: false,
                has_new_cell: false,
                sendme_ty,
                forward_data_count: 1000,
                backward_data_count: 1000,
                forward_data_modulo: 0,
                backward_data_modulo: 0,
                forward_sendme_digest: VecDeque::new(),
                backward_sendme_digest: VecDeque::new(),

                time_data: None,
            });
        } else if let Some(cell) = cast::<Destroy>(&mut cell)? {
            warn!(reason = display(cell.display_reason()), "circuit destroyed");
            return Err(errors::ChannelClosedError.into());
        }

        let cell = Cached::transpose(cell).unwrap();
        Err(errors::InvalidCellHeader::with_cell(&cell).into())
    }
}

struct SteadyState {
    encrypt: OnionLayer128,
    digest: CircuitDigest,
    early_cnt: u8,

    in_buffer: InBuffer<Relay>,
    out_buffer: OutBuffer<Relay>,
    cell_send: Option<Cell>,
    pause_out_buffer: bool,

    pending_close: VecDeque<(NonZeroU16, EndReason)>,
    pending_open: PendingOpen,

    is_timeout: bool,
    has_new_cell: bool,
    sendme_ty: SendmeType,
    forward_data_count: usize,
    backward_data_count: usize,
    forward_data_modulo: u8,
    backward_data_modulo: u8,
    forward_sendme_digest: VecDeque<[u8; 20]>,
    backward_sendme_digest: VecDeque<[u8; 20]>,

    time_data: Option<TimeData>,
}

struct TimeData {
    last_packet: Instant,
    close_scan: Instant,
}

const IDLE_TIMEOUT: Duration = Duration::from_secs(60);
const FULL_TIMEOUT: Duration = Duration::from_millis(100);
const CLOSE_SCAN_TIMEOUT: Duration = Duration::from_secs(10);
const MAX_BACKOFF: u8 = 20;

fn update_last_packet(ptr: &mut Instant, input: &CircuitInput<'_, CachedCell>) {
    *ptr = input.time() + IDLE_TIMEOUT;
}

const FLAG_READ: u8 = 1 << 0;
const FLAG_WRITE: u8 = 1 << 1;
const FLAG_WRITE_EMPTY: u8 = 1 << 2;

impl SteadyState {
    #[instrument(level = "debug", skip_all, err)]
    fn handle<'a>(
        &mut self,
        cfg: &CfgData,
        mut input: CircuitInput<'a, CachedCell>,
        stream_map: &'a mut StreamMap,
    ) -> Result<(CircuitOutput, bool), errors::DirControllerError> {
        let TimeData {
            last_packet,
            close_scan,
        } = self.time_data.get_or_insert_with(|| {
            let time = input.time();
            TimeData {
                last_packet: time + IDLE_TIMEOUT,
                close_scan: time + CLOSE_SCAN_TIMEOUT,
            }
        });

        if self.is_timeout && *last_packet <= input.time() {
            info!("circuit idled for 1 minutes, gracefully shutting down");
            let mut out = CircuitOutput::new();
            out.shutdown(DestroyReason::Finished);
            return Ok((out, true));
        }

        if self.has_new_cell {
            update_last_packet(last_packet, &input);
        }

        // Scan for close circuits
        if self.is_timeout && *close_scan <= input.time() {
            for (&id, stream) in stream_map.items() {
                if !stream.meta.closing && stream.is_closed() {
                    debug!(id, "stream is closing");
                    stream.meta.closing = true;
                    self.pending_close
                        .push_back((id.try_into().unwrap(), EndReason::Internal));
                }
            }

            *close_scan = input.time() + CLOSE_SCAN_TIMEOUT;
        }

        let mut timeout = (*last_packet).min(*close_scan);

        let mut flags = 0u8;
        let mut full_timeout = None;

        loop {
            // Process read cells
            if flags & FLAG_READ == 0 {
                let t;
                (flags, t) = read_handler(self, cfg, &mut input, stream_map, flags)?;
                full_timeout = option_ord_min(full_timeout, t);
            }

            // Process write cells
            if flags & (FLAG_WRITE | FLAG_WRITE_EMPTY) == 0 {
                flags = write_handler(self, cfg, &mut input, stream_map, flags)?;
            }

            trace!(flags, "processing");
            if flags & FLAG_READ != 0 && flags & (FLAG_WRITE | FLAG_WRITE_EMPTY) != 0 {
                break;
            }
        }

        if let Some(t) = full_timeout {
            // Full timeout
            timeout = timeout.min(t);
        }

        let mut out = CircuitOutput::new();
        out.timeout(timeout);
        out.parent_cell_msg_pause(CellMsgPause(self.in_buffer.is_full()));
        out.child_cell_msg_pause(CellMsgPause(self.out_buffer.is_full()));
        Ok((out, false))
    }

    #[instrument(level = "debug", skip_all, err)]
    fn handle_cell(
        &mut self,
        cfg: &CfgData,
        cell: CachedCell,
    ) -> Result<CellMsgPause, errors::DirControllerError> {
        let mut cell = (*cfg.cache).cache_b({
            let mut cell = Cached::map(cell, Some);
            if let Some(cell) = cast::<Relay>(&mut cell)? {
                cell
            } else if let Some(cell) = cast::<RelayEarly>(&mut cell)? {
                cell.into()
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
            self.has_new_cell = true;
        } else {
            let mut cell = Cached::map(cell, Some);
            if let Some(cell) = cast_r::<RelayDrop>(&mut cell)? {
                // RELAY_DROP is for long-range padding
                cfg.cache.discard(cell);
            } else if let Some(cell) = cast_r::<RelaySendme>(&mut cell)? {
                // RELAY_SENDME, check digest and increment forward data counter.
                let cell = (*cfg.cache).cache_b(cell);

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
                                expect = display(print_hex(&b)),
                                sent = display(print_hex(&a)),
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

    #[instrument(level = "debug", skip_all, err)]
    fn handle_stream_cell(
        &mut self,
        cfg: &CfgData,
        mut cell: CachedCell<Relay>,
    ) -> Result<CellMsgPause, errors::DirControllerError> {
        cell.circuit = cfg.circ_id;
        self.out_buffer.push_back(Cached::into_inner(cell));

        Ok(CellMsgPause(self.out_buffer.is_full()))
    }
}

#[inline(always)]
fn read_handler(
    this: &mut SteadyState,
    cfg: &CfgData,
    input: &mut CircuitInput<'_, CachedCell>,
    stream_map: &mut StreamMap,
    mut flags: u8,
) -> Result<(u8, Option<Instant>), errors::DirControllerError> {
    let mut full_timeout = None;

    // Process in buffer.
    // Should only be done if timeout or in buffer has new data.
    if take(&mut this.is_timeout) | take(&mut this.has_new_cell) {
        this.in_buffer.scan_pop(|p| {
            let is_begin = if let Some(cell) = cast_r::<RelayBegin>(p)? {
                cfg.cache.discard(cell);
                true
            } else if let Some(cell) = cast_r::<RelayBeginDir>(p)? {
                cfg.cache.discard(cell);
                true
            } else {
                false
            };
            if is_begin {
                return Err(
                    errors::CircuitProtocolError(errors::CircuitProtocolInner::RelayBegin).into(),
                );
            }

            let Some(cell) = p else {
                return Ok(());
            };
            let id = NonZeroU16::new(cell.stream()).expect("stream ID should not be zero");
            let Some(stream) = stream_map.get(id.into()) else {
                // Discard all unmapped stream ID.
                debug!(
                    id,
                    command = cell.command(),
                    "discard unmapped stream ID cell"
                );
                *p = None;
                return Ok(());
            };
            if stream.meta.closing {
                // Stream closing, discard cell
                debug!(id, command = cell.command(), "discard closing stream cell");
                *p = None;
                return Ok(());
            }

            if let Some(cell) = cast_r::<RelayEnd>(p)? {
                // RELAY_END cell received, force closing stream.
                let cell = cfg.cache.cache(cell);
                let reason = cell.reason();
                debug!(id, reason = display(&reason), "peer is closing stream");
                match stream.send(Cached::map(cell, |c| c.into_relay(cfg.circ_id))) {
                    Ok(()) => (),
                    Err(TrySendError::Full(_)) => warn!(
                        id,
                        reason = display(&reason),
                        "cannot send RELAY_END cell to handler because channel is full"
                    ),
                    // Stream is closing while peer is closing.
                    Err(TrySendError::Disconnected(_)) => (),
                }

                stream_map.remove(id.into());

                // Scan pending close to ensure we don't double close.
                this.pending_close.retain(|(id_, _)| *id_ != id);

                return Ok(());
            }
            if let Some(cell) = cast_r::<RelayConnected>(p)? {
                cfg.cache.discard(cell);
                trace!(id, "directory stream connected");

                if let Some((s, m)) = stream.meta.connect_resolve.take()
                    && s.send(Ok(m)).is_err()
                {
                    stream.meta.closing = true;

                    this.pending_close.push_back((id, EndReason::Internal));
                    // Pending RELAY_END cell, clear flag
                    flags &= !FLAG_WRITE_EMPTY;
                }
                return Ok(());
            }

            if stream.meta.last_full > input.time() {
                // Sender recently full
                return Ok(());
            }

            let Some(cell) = p.take() else {
                return Ok(());
            };

            match stream.send(cfg.cache.cache(cell)) {
                // Success, decrease backoff
                Ok(()) => stream.meta.backoff_mult = stream.meta.backoff_mult.saturating_sub(1),
                // Full, return cell and set last full
                Err(TrySendError::Full(cell)) => {
                    *p = Some(Cached::into_inner(cell));

                    let mut mult = stream.meta.backoff_mult;
                    // Multiply backoff
                    mult = mult
                        .checked_mul(2)
                        .map_or(MAX_BACKOFF, |v| v.clamp(1, MAX_BACKOFF));

                    let t = input.time() + FULL_TIMEOUT * u32::from(mult);
                    stream.meta.backoff_mult = mult;
                    stream.meta.last_full = t;
                    full_timeout = option_ord_min(full_timeout, Some(t));

                    debug!(
                        id,
                        mult,
                        time = debug(t),
                        "cannot send cell, stream is full"
                    );
                }
                // Stream is closing, drop cell and close it for real
                Err(TrySendError::Disconnected(_)) => {
                    debug!(id, "cannot send cell, stream is closing");
                    stream.meta.closing = true;

                    this.pending_close.push_back((id, EndReason::Internal));
                    // Pending RELAY_END cell, clear flag
                    flags &= !FLAG_WRITE_EMPTY;
                }
            }

            Ok::<(), errors::DirControllerError>(())
        })?;
    }

    flags |= FLAG_READ;

    Ok((flags, full_timeout))
}

#[inline(always)]
fn write_handler(
    this: &mut SteadyState,
    cfg: &CfgData,
    input: &mut CircuitInput<'_, CachedCell>,
    stream_map: &mut StreamMap,
    flags: u8,
) -> Result<u8, errors::DirControllerError> {
    if let Some(cell) = this.cell_send.take() {
        match input.try_send(cfg.cache.cache(cell)) {
            Ok(()) => update_last_packet(&mut this.time_data.as_mut().unwrap().last_packet, input),
            Err(TrySendError::Full(cell)) => {
                this.cell_send = Some(Cached::into_inner(cell));
                return Ok(flags | FLAG_WRITE);
            }
            Err(TrySendError::Disconnected(_)) => {
                debug!("circuit closed");
                return Err(errors::ChannelClosedError.into());
            }
        }
    }

    let mut found: Option<Relay> = None;

    while found.is_none()
        && let Some((id, reason)) = this.pending_close.pop_front()
    {
        let Some(meta) = stream_map.remove(id.into()) else {
            continue;
        };
        debug_assert!(meta.closing);

        // Prepend RELAY_END cell
        found = Some(RelayEnd::new(cfg.cache.get_cached(), id, reason).into_relay(cfg.circ_id));
        break;
    }

    while found.is_none()
        && let Some(send) = this.pending_open.pop_front()
    {
        // Open stream and prepend RELAY_BEGIN_DIR cell
        match stream_map.open_with(&StreamIDGenerator::new(), 64, |_| DirStreamMeta {
            closing: false,

            last_full: input.time(),
            backoff_mult: 0,

            connect_resolve: None,
        }) {
            Ok((m, v)) => {
                info!(stream_id = m.id, "opening new directory stream");

                found = Some(
                    RelayBeginDir::new(cfg.cache.get_cached(), m.id.try_into().unwrap())
                        .into_relay(cfg.circ_id),
                );

                // Store handle to be resolved later.
                v.meta.connect_resolve = Some((send, NewStream::new(m, input)));
            }
            Err(e) => {
                // Failed to create stream.
                let _ = send.send(Err(e));
            }
        }
    }

    while found.is_none()
        && let Some(digest) = this.forward_sendme_digest.pop_front()
        && let Some(data) = match this.sendme_ty {
            SendmeType::Disabled => None,
            SendmeType::Unauth => Some(SendmeData::Unauth),
            SendmeType::Auth => Some(SendmeData::Auth(digest)),
        }
    {
        // Prepend RELAY_SENDME cell
        found = Some(RelaySendme::from_data(cfg.cache.get_cached(), data).into_relay(cfg.circ_id));

        this.backward_data_count = this
            .backward_data_count
            .checked_add(100)
            .expect("token bucket overflow");
        this.pause_out_buffer = false;
    }

    while found.is_none() && !this.pause_out_buffer {
        let Some(cell) = this.out_buffer.pop_front() else {
            break;
        };

        let Some(id) = NonZeroU16::new(cell.stream()) else {
            continue;
        };
        if !stream_map.has(id.into()) {
            // Unmapped stream ID. Probably non-graceful shutdown.
            continue;
        }
        let mut cell = Some(cell);

        found = if let Some(cell) = cast_r::<RelayEnd>(&mut cell)? {
            if stream_map.remove(id.into()).is_none() {
                // No need to scan pending close because it should be empty by now.
                continue;
            }

            Some(cell.into_relay(cfg.circ_id))
        } else {
            cell
        };
    }

    let Some(cell) = found else {
        // Nothing to write
        return Ok(flags | FLAG_WRITE_EMPTY);
    };
    let mut cell = (*cfg.cache).cache_b(cell);
    let command = cell.command();
    let is_data = this.sendme_ty != SendmeType::Disabled && command == RelayData::ID;

    if is_data {
        // Data-bearing cell, decrement forward data counter.
        this.forward_data_count = match this.forward_data_count.checked_sub(1) {
            Some(v) => v,
            None => {
                // Token bucket is empty, repush cell and pause out buffer.
                this.out_buffer.push_front(Cached::into_inner(cell));
                this.pause_out_buffer = true;
                return Ok(flags);
            }
        };

        this.forward_data_modulo += 1;
        debug_assert!(this.forward_data_modulo <= 100);
        if this.forward_data_modulo == 100 {
            this.forward_data_modulo = 0;
        }
    }

    // Set circuit ID.
    cell.circuit = cfg.circ_id;

    // Encrypt and set digest,
    let digest = this.digest.wrap_digest_forward((*cell).as_mut());
    this.encrypt.encrypt_forward((*cell).as_mut())?;

    if is_data && this.forward_data_modulo == 0 {
        // Every 100 decrement, send a SENDME cell.
        this.forward_sendme_digest.push_back(digest);
    }

    let cell = Cached::into_inner(cell);
    this.cell_send = Some(match this.early_cnt {
        1.. => RelayEarly::from(cell).into(),
        0 => cell.into(),
    });
    this.early_cnt = this.early_cnt.saturating_sub(1);

    Ok(flags)
}
