use std::collections::vec_deque::VecDeque;
use std::io::{ErrorKind, Result as IoResult};
use std::num::NonZeroU32;
use std::ops::ControlFlow;
use std::ops::ControlFlow::*;
use std::sync::Arc;
use std::time::{Duration, Instant};

use flume::TrySendError;
use futures_channel::oneshot::Sender;
use tracing::{debug, error, info, instrument, trace, warn};

use crate::cache::{Cached, CellCache, cast};
use crate::cell::auth::AuthChallenge;
use crate::cell::certs::Certs;
use crate::cell::create::{Create2, Created2};
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
use crate::crypto::relay::{RelayId, RelayIdEd};
use crate::errors;
use crate::linkver::StandardLinkver;
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

type Reader = CellReader<LinkCfg>;
type CachedCell<C = Cell> = Cached<C, Arc<dyn Send + Sync + CellCache>>;
type CachedCellWriter<C = Cell> = CellWriter<CachedCell<C>>;

enum State<Cfg> {
    Init {
        state: InitState,
        cfg: Arc<dyn Send + Sync + AsRef<Cfg>>,
    },
    Steady(Box<SteadyState>),
    Shutdown,
}

enum InitState {
    Init,
    VersionsWrite(CellWriter<Versions>),
    ConfigRead(Reader, ConfigReadState),
    NetinfoWrite(CachedCellWriter<Netinfo>),
}

enum ConfigReadState {
    NeedVersions,
    NeedCerts,
    NeedAuthChallenge,
    NeedNetinfo,
}

struct SteadyState {
    cell_read: Reader,
    cell_write: CellWriter<CachedCell>,

    in_buffer: InBuffer<CachedCell>,
    out_buffer: OutBuffer<CachedCell>,

    pending_open: VecDeque<Sender<Result<NewCircuit<CachedCell>, errors::NoFreeCircIDError>>>,
    pending_close: VecDeque<(NonZeroU32, DestroyReason)>,
}

pub struct CircuitMeta {
    last_full: Instant,
    closing: bool,
}

impl<Cfg: 'static + UserConfig + Send + Sync> ChannelController for UserController<Cfg> {
    type Error = errors::UserControllerError;
    type Config = Cfg;
    type ControlMsg = ();
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
        let last_packet = self.last_packet.get_or_insert_with(|| input.time());

        loop {
            match self.state {
                State::Init {
                    ref mut state,
                    ref cfg,
                } => match state.handle(&self.link_cfg, last_packet, cfg, &mut input)? {
                    Break(()) => break,
                    Continue(false) => (),
                    Continue(true) => todo!(),
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
        *self = match self {
            Self::Init => {
                let peer_addr = input.peer_addr();
                let addrs = (**cfg).as_ref().peer_addrs();
                if !addrs.contains(peer_addr) {
                    return Err(
                        errors::PeerMismatchError::new(*peer_addr, addrs.iter().copied()).into(),
                    );
                }

                Self::VersionsWrite(CellWriter::with_cell_config(
                    (*link_cfg.linkver).as_ref().versions_cell(),
                    &link_cfg,
                )?)
            }
            Self::VersionsWrite(w) => match write_cell(w, input)? {
                false => return Ok(Break(())),
                true => {
                    Self::ConfigRead(Reader::new(link_cfg.clone()), ConfigReadState::NeedVersions)
                }
            },
            _ => todo!(),
        };

        Ok(Continue(false))
    }
}

impl<Cfg: 'static + UserConfig + Send + Sync> Handle<Timeout> for UserController<Cfg> {
    type Return = Result<(), errors::UserControllerError>;

    #[instrument(name = "handle_timeout", skip_all)]
    fn handle(&mut self, _: Timeout) -> Self::Return {
        self.is_timeout = true;
        Ok(())
    }
}

impl<Cfg: 'static + UserConfig + Send + Sync> Handle<ControlMsg<()>> for UserController<Cfg> {
    type Return = Result<(), errors::UserControllerError>;

    #[instrument(name = "handle_control", skip_all)]
    fn handle(&mut self, _: ControlMsg<()>) -> Self::Return {
        todo!()
    }
}

impl<Cfg: 'static + UserConfig + Send + Sync> Handle<CellMsg<CachedCell>> for UserController<Cfg> {
    type Return = Result<CellMsgPause, errors::UserControllerError>;

    #[instrument(name = "handle_cell", skip_all)]
    fn handle(&mut self, _: CellMsg<CachedCell>) -> Self::Return {
        todo!()
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
        Ok(()) => {
            debug!("writing cell finished");
            Ok(true)
        }
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

const IDLE_TIMEOUT: Duration = Duration::from_secs(60 * 5);
const FULL_TIMEOUT: Duration = Duration::from_millis(100);

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

                    if let Some(_) = cast::<Create2>(&mut cell)? {
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

    use proptest::collection::vec;
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
