use std::collections::vec_deque::VecDeque;
use std::fmt::Display;
use std::marker::PhantomData;
use std::mem::take;
use std::num::{NonZeroU16, NonZeroU32};
use std::sync::Arc;
use std::time::{Duration, Instant};

use flume::TrySendError;
use futures_channel::oneshot::{Receiver, Sender, channel};
use scopeguard::guard;
use tracing::{debug, info, instrument, trace, warn};

use crate::cache::{Cached, CellCache, CellCacheExt, cast};
use crate::cell::Cell;
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
use crate::circuit::controller::CircuitController;
use crate::circuit::{
    CellMsg, CellMsgPause, CircuitInput, CircuitOutput, ControlMsg, NewStream, StreamCellMsg,
    Timeout,
};
use crate::crypto::onion::{CircuitDigest, OnionLayer, OnionLayer128, OnionLayerFast, RelayDigest};
use crate::errors;
use crate::util::cell_map::{CellMap, StreamIDGenerator};
use crate::util::sans_io::Handle;
use crate::util::{InBuffer, OutBuffer, option_ord_min, print_hex};

type CacheTy = Arc<dyn Send + Sync + CellCache>;
type CachedCell<C = Cell> = Cached<C, CacheTy>;
type PendingOpen = VecDeque<Sender<Result<NewStream<CachedCell>, errors::NoFreeCircIDError>>>;
type StreamMap = CellMap<CachedCell<Cell>, DirStreamMeta>;
type NewStreamSender = Sender<Result<NewStream<CachedCell>, errors::NoFreeCircIDError>>;

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

pub enum DirControlMsg {
    Shutdown,
    /// Create new stream.
    NewStream(NewStreamSender),
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
    connect_resolve: Option<(NewStreamSender, NewStream<CachedCell>)>,
}

impl<Cfg: 'static + Send + Sync + Display + DirConfig> CircuitController for DirController<Cfg> {
    type Config = Cfg;
    type Error = errors::DirControllerError;
    type ControlMsg = DirControlMsg;
    type Cell = CachedCell;
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
        &'a mut CellMap<CachedCell, DirStreamMeta>,
    )> for DirController<Cfg>
{
    type Return = Result<CircuitOutput, errors::DirControllerError>;

    fn handle(
        &mut self,
        (input, stream_map): (
            CircuitInput<'a, CachedCell>,
            &'a mut CellMap<CachedCell, DirStreamMeta>,
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

    fn handle(&mut self, msg: ControlMsg<DirControlMsg>) -> Result<(), errors::DirControllerError> {
        match msg.0 {
            DirControlMsg::Shutdown => {
                self.state = State::Shutdown;
                Ok(())
            }
            DirControlMsg::NewStream(v) => {
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

impl<Cfg> Handle<CellMsg<CachedCell>> for DirController<Cfg> {
    type Return = Result<CellMsgPause, errors::DirControllerError>;

    fn handle(
        &mut self,
        msg: CellMsg<CachedCell>,
    ) -> Result<CellMsgPause, errors::DirControllerError> {
        match self.state {
            State::Init(ref mut s) => {
                self.state = State::Steady(s.handle_cell(&self.cfg, msg.0)?);
                Ok(false.into())
            }
            State::Steady(ref mut s) => s.handle_cell(&self.cfg, msg.0),
            State::Shutdown => Ok(true.into()),
        }
    }
}

impl<Cfg> Handle<StreamCellMsg<CachedCell>> for DirController<Cfg> {
    type Return = Result<CellMsgPause, errors::DirControllerError>;

    fn handle(
        &mut self,
        msg: StreamCellMsg<CachedCell>,
    ) -> Result<CellMsgPause, errors::DirControllerError> {
        match self.state {
            State::Init(_) => {
                panic!("state should not receive stream cell message")
            }
            State::Steady(ref mut s) => s.handle_stream_cell(&self.cfg, msg.0),
            State::Shutdown => Ok(true.into()),
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

    #[instrument(level = "debug", skip_all)]
    fn handle<'a>(
        &mut self,
        _cfg: &CfgData,
        mut input: CircuitInput<'a, CachedCell>,
    ) -> Result<CircuitOutput, errors::DirControllerError> {
        let mut output = CircuitOutput::new();

        output
            .cell_msg_pause(true.into())
            .stream_cell_msg_pause(true.into());

        let timeout = *self
            .timeout
            .get_or_insert_with(|| input.time() + CREATE_TIMEOUT);
        output.timeout(timeout);

        if timeout >= input.time() {
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

    #[instrument(level = "debug", skip_all)]
    fn handle_cell(
        &mut self,
        cfg: &CfgData,
        cell: CachedCell,
    ) -> Result<SteadyState, errors::DirControllerError> {
        let mut cell = Cached::map(cell, Some);

        if let Some(cell) = cast::<CreatedFast>(&mut cell)? {
            let (client, sendme_ty) = self.data.take().expect("client params must exist");
            let layer = client.derive_client(&cfg.cache.cache(cell))?;

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

                last_packet: None,
            });
        }

        let cell = Cached::transpose(cell).unwrap();
        Err(errors::InvalidCellHeader::with_cell(&cell).into())
    }
}

struct SteadyState {
    encrypt: OnionLayer128,
    digest: CircuitDigest,
    early_cnt: u8,

    in_buffer: InBuffer<CachedCell<Option<Relay>>>,
    out_buffer: OutBuffer<CachedCell<Relay>>,
    cell_send: Option<CachedCell>,
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

    last_packet: Option<Instant>,
}

const IDLE_TIMEOUT: Duration = Duration::from_secs(60);
const FULL_TIMEOUT: Duration = Duration::from_millis(100);
const CLOSE_SCAN_TIMEOUT: Duration = Duration::from_secs(5);
const MAX_BACKOFF: u8 = 20;

fn update_last_packet(ptr: &mut Instant, input: &CircuitInput<'_, CachedCell>) {
    *ptr = input.time() + IDLE_TIMEOUT;
}

const FLAG_READ: u8 = 1 << 0;
const FLAG_WRITE: u8 = 1 << 1;
const FLAG_WRITE_EMPTY: u8 = 1 << 2;

impl SteadyState {
    #[instrument(level = "debug", skip_all)]
    fn handle<'a>(
        &mut self,
        cfg: &CfgData,
        mut input: CircuitInput<'a, CachedCell>,
        stream_map: &'a mut StreamMap,
    ) -> Result<(CircuitOutput, bool), errors::DirControllerError> {
        let last_packet = self
            .last_packet
            .get_or_insert_with(|| input.time() + IDLE_TIMEOUT);
        if self.is_timeout && *last_packet <= input.time() {
            info!("circuit idled for 1 minutes, gracefully shutting down");
            let mut out = CircuitOutput::new();
            out.shutdown(DestroyReason::default());
            return Ok((out, true));
        }

        if self.has_new_cell {
            update_last_packet(last_packet, &input);
        }

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

        let mut timeout = self.last_packet.unwrap();
        //timeout = timeout.min(self.close_scan);
        if let Some(t) = full_timeout {
            // Full timeout
            timeout = timeout.min(t);
        }

        let mut out = CircuitOutput::new();
        Ok((out, false))
    }

    #[instrument(level = "debug", skip_all)]
    fn handle_cell(
        &mut self,
        cfg: &CfgData,
        cell: CachedCell,
    ) -> Result<CellMsgPause, errors::DirControllerError> {
        let mut cell = Cached::map(cell, Some);

        let cell = if let Some(cell) = cast::<Relay>(&mut cell)? {
            cell
        } else if let Some(cell) = cast::<RelayEarly>(&mut cell)? {
            cell.into()
        } else {
            let cell = Cached::transpose(cell).unwrap();
            return Err(errors::InvalidCellHeader::with_cell(&cell).into());
        };
        let mut cell = cfg.cache.cache(cell);

        // Decrypt and check digest cell
        self.encrypt.decrypt_backward((*cell).as_mut())?;
        let digest = self.digest.unwrap_digest_backward(&mut *cell)?;

        let command = cell.command();
        let stream = cell.stream();
        let mut cell = Cached::map(cell, Some);

        if stream != 0 {
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

            self.in_buffer.push(cfg.cache.cache(cell.take()));
            self.has_new_cell = true;
        } else if let Some(cell) = cast_r::<RelayDrop>(&mut cell)? {
            // RELAY_DROP is for long-range padding
            cfg.cache.discard(cell);
        } else if let Some(cell) = cast_r::<RelaySendme>(&mut cell)? {
            // RELAY_SENDME, check digest and increment forward data counter.
            let cell = cfg.cache.cache(cell);

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

        if let Some(cell) = Cached::transpose(cell) {
            // NOTE: Potential protocol violation
            trace!("unhandled cell with command {} received", cell.command());
        }

        Ok(self.in_buffer.is_full().into())
    }

    #[instrument(level = "debug", skip_all)]
    fn handle_stream_cell(
        &mut self,
        cfg: &CfgData,
        cell: CachedCell,
    ) -> Result<CellMsgPause, errors::DirControllerError> {
        let mut cell = Cached::map(cell, Some);

        let mut cell = if let Some(cell) = cast::<Relay>(&mut cell)? {
            cell
        } else if let Some(cell) = cast::<RelayEarly>(&mut cell)? {
            cell.into()
        } else {
            let cell = Cached::transpose(cell).unwrap();
            return Err(errors::InvalidCellHeader::with_cell(&cell).into());
        };
        cell.circuit = cfg.circ_id;
        self.out_buffer.push_back(cfg.cache.cache(cell));

        Ok(self.out_buffer.is_full().into())
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
            let mut p = guard(p, |p| match p {
                Some(v) if v.is_none() => *p = None,
                _ => (),
            });
            let Some(cell) = p.as_mut() else {
                return Ok(());
            };

            let is_begin = if let Some(cell) = cast_r::<RelayBegin>(cell)? {
                cfg.cache.discard(cell);
                true
            } else if let Some(cell) = cast_r::<RelayBeginDir>(cell)? {
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

            let Some(c) = cell.as_ref() else {
                return Ok(());
            };
            let id = NonZeroU16::new(c.stream()).expect("stream ID should not be zero");
            let Some(stream) = stream_map.get(id.into()) else {
                // Discard all unmapped stream ID.
                debug!(id, command = c.command(), "discard unmapped stream ID cell");
                **p = None;
                return Ok(());
            };
            if stream.meta.closing {
                // Stream closing, discard cell
                debug!(id, command = c.command(), "discard closing stream cell");
                **p = None;
                return Ok(());
            }

            if let Some(cell) = cast_r::<RelayEnd>(cell)? {
                let reason = cell.reason();
                debug!(id, reason = display(&reason), "peer is closing stream");
                match stream.send(cfg.cache.cache(cell.into_relay(cfg.circ_id).into())) {
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
                return Ok(());
            }
            if let Some(cell) = cast_r::<RelayConnected>(cell)? {
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
            }

            if stream.meta.last_full > input.time() {
                // Sender recently full
                return Ok(());
            }

            let Some(Some(cell)) = p.take().map(Cached::transpose) else {
                return Ok(());
            };

            match stream.send(Cached::map_into(cell)) {
                // Success, decrease backoff
                Ok(()) => stream.meta.backoff_mult = stream.meta.backoff_mult.saturating_sub(1),
                // Full, return cell and set last full
                Err(TrySendError::Full(cell)) => {
                    **p = Some(Cached::map(cell, |c| {
                        Some(Relay::from_cell(cfg.circ_id, c.into_fixed().unwrap()))
                    }));

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
        match input.try_send(cell) {
            Ok(()) => update_last_packet(this.last_packet.as_mut().unwrap(), input),
            Err(TrySendError::Full(cell)) => {
                this.cell_send = Some(cell);
                return Ok(flags | FLAG_WRITE);
            }
            Err(TrySendError::Disconnected(_)) => {
                debug!("circuit closed");
                return Err(errors::ChannelClosedError.into());
            }
        }
    }

    let mut found: Option<CachedCell<Relay>> = None;

    if let Some((id, reason)) = this.pending_close.pop_front()
        && let Some(meta) = stream_map.remove(id.into())
    {
        debug_assert!(meta.closing);

        // Prepend RELAY_END cell
        found = Some(
            cfg.cache
                .cache(RelayEnd::new(cfg.cache.get_cached(), id, reason).into_relay(cfg.circ_id)),
        );
    }

    if found.is_none()
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
                found = Some(
                    cfg.cache.cache(
                        RelayBeginDir::new(cfg.cache.get_cached(), m.id.try_into().unwrap())
                            .into_relay(cfg.circ_id),
                    ),
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

    if found.is_none()
        && let Some(digest) = this.forward_sendme_digest.pop_front()
        && let Some(data) = match this.sendme_ty {
            SendmeType::Disabled => None,
            SendmeType::Unauth => Some(SendmeData::Unauth),
            SendmeType::Auth => Some(SendmeData::Auth(digest)),
        }
    {
        // Prepend RELAY_SENDME cell
        found =
            Some(cfg.cache.cache(
                RelaySendme::from_data(cfg.cache.get_cached(), data).into_relay(cfg.circ_id),
            ));

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
        let mut cell = Cached::map(cell, Some);

        found = if let Some(cell) = cast_r::<RelayEnd>(&mut cell)? {
            let cell = cfg.cache.cache(cell);
            if stream_map.remove(id.into()).is_none() {
                continue;
            }

            Some(Cached::map(cell, |cell| cell.into_relay(cfg.circ_id)))
        } else {
            Cached::transpose(cell)
        };
    }

    let Some(mut cell) = found else {
        return Ok(flags | FLAG_WRITE_EMPTY);
    };
    let command = cell.command();
    let is_data = this.sendme_ty != SendmeType::Disabled && command == RelayData::ID;

    if is_data {
        // Data-bearing cell, decrement forward data counter.
        this.forward_data_count = match this.forward_data_count.checked_sub(1) {
            Some(v) => v,
            None => {
                // Token bucket is empty, repush cell and pause out buffer.
                this.out_buffer.push_front(cell);
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
    cell.circuit = cfg.circ_id.into();

    // Encrypt and set digest,
    let digest = this.digest.wrap_digest_forward(&mut *cell);
    this.encrypt.encrypt_forward((*cell).as_mut())?;

    if is_data && this.forward_data_modulo == 0 {
        // Every 100 decrement, send a SENDME cell.
        this.forward_sendme_digest.push_back(digest);
    }

    this.cell_send = Some(if let Some(v) = this.early_cnt.checked_sub(1) {
        this.early_cnt = v;
        Cached::map_into(Cached::map_into::<RelayEarly>(cell))
    } else {
        Cached::map_into(cell)
    });

    Ok(flags)
}
