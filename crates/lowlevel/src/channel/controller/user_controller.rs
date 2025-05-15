use std::collections::vec_deque::VecDeque;
use std::io::{ErrorKind, Result as IoResult};
use std::num::NonZeroU32;
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
use crate::channel::{ChannelConfig, ChannelInput, ChannelOutput};
use crate::crypto::relay::{RelayId, RelayIdEd};
use crate::errors;
use crate::linkver::StandardLinkver;
use crate::util::sans_io::Handle;

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

    last_packet: Instant,
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

#[derive(Default)]
enum InitState {
    #[default]
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

    in_buffer: InBuffer,
    out_buffer: OutBuffer,

    pending_open: VecDeque<Sender<Result<NewCircuit<CachedCell>, errors::NoFreeCircIDError>>>,
    pending_close: VecDeque<(NonZeroU32, DestroyReason)>,
}

struct CircuitMeta {
    // TODO: Circuit metadata
}

struct InBuffer {
    buffer: [Option<CachedCell>; 64],
    index: [u8; 64],
    head: u8,
    free: u8,
}

impl InBuffer {
    const fn new() -> Self {
        Self {
            head: 64,
            free: 64,
            index: [64; 64],
            buffer: [const { None }; 64],
        }
    }

    fn is_full(&self) -> bool {
        self.free == 64
    }

    fn push(&mut self, cell: CachedCell) {
        assert!(self.head <= 64);
        assert!(self.free < 64);

        let i = self.free;
        let ix = usize::from(i);
        debug_assert!(self.buffer[ix].is_none());
        self.buffer[ix] = Some(cell);
        (self.free, self.index[ix], self.head) = (self.index[ix], self.head, i);

        debug_assert!(self.head < 64);
        debug_assert!(self.free <= 64);
    }

    fn scan_pop<E>(
        &mut self,
        mut f: impl FnMut(&mut Option<CachedCell>) -> Result<(), E>,
    ) -> Result<(), E> {
        assert!(self.head < 64);
        assert!(self.free < 64);

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
            (self.head, self.index[ix], self.free) = (self.index[ix], self.free, i);
            debug_assert!(self.head <= 64);
            debug_assert!(self.free < 64);
            i = self.head;
            ret?;
        }

        let mut j = self.index[usize::from(i)];
        debug_assert!(j <= 64);
        while j != 64 {
            let ix = usize::from(j);
            let data = &mut self.buffer[ix];

            debug_assert!(data.is_some());
            let ret = f(data);

            let k = self.index[ix];
            debug_assert!(k <= 64);
            if data.is_some() {
                (i, j) = (j, k);
            } else {
                self.index[usize::from(i)] = k;
                (self.index[ix], self.free, j) = (self.free, j, k);
            }
            ret?;
        }

        Ok(())
    }
}

struct OutBuffer {
    buffer: [Option<CachedCell>; 64],
    head: u8,
    len: u8,
}

impl OutBuffer {
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

    fn push(&mut self, cell: CachedCell) {
        assert!(self.head < 64);
        assert!(self.len < 64);

        let ix = usize::from(self.head);
        debug_assert!(self.buffer[ix].is_none());
        self.buffer[ix] = Some(cell);
        self.head = (self.head + 1) % 64;
        self.len += 1;
    }

    fn pop(&mut self) -> Option<CachedCell> {
        assert!(self.head < 64);
        assert!(self.len < 64);

        if self.len == 0 {
            return None;
        }
        let ix = usize::from((self.head + self.len) % 64);
        let ret = self.buffer[ix].take();
        debug_assert!(ret.is_some());
        self.len -= 1;
        if self.len == 0 {
            self.head = 0;
        }
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

fn update_last_packet(ptr: &mut Instant, input: &mut ChannelInput<'_>) {
    *ptr = input.time() + IDLE_TIMEOUT;
}

impl SteadyState {
    fn handle(
        &mut self,
        cfg: &LinkCfg,
        last_packet: &mut Instant,
        input: &mut ChannelInput<'_>,
        circ_map: &mut CircuitMap<CachedCell, CircuitMeta>,
    ) -> Result<(), errors::UserControllerError> {
        loop {
            // Read data from stream
            while !self.in_buffer.is_full() {
                let Some(cell) = read_cell(&mut self.cell_read, input)? else {
                    break;
                };
                if cell.circuit != 0 {
                    update_last_packet(last_packet, input);
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
                break;
            }

            // Process in buffer
            self.in_buffer
                .scan_pop(|p| -> Result<(), errors::UserControllerError> {
                    let Some(cell) = p.take() else { return Ok(()) };
                    let id = NonZeroU32::new(cell.circuit).unwrap();
                    let mut cell = Cached::map(cell, Some);

                    if let Some(_) = cast::<Create2>(&mut cell)? {
                        // User controller cannot create circuit by peer
                        self.pending_close.push_back((id, DestroyReason::Protocol));
                        return Ok(());
                    }

                    let Some(circ) = circ_map.get(id) else {
                        // Ignore all unmapped circuit ID.
                        return Ok(());
                    };
                    if let Some(cell) = cast::<Destroy>(&mut cell)? {
                        debug!(id, "peer is closing circuit");
                        match circ.send(cfg.cache.cache(cell.into())) {
                            Ok(()) => (),
                            Err(TrySendError::Full(_)) => warn!(
                                id,
                                "cannot send DESTROY cell to handler because channel is full"
                            ),
                            // Circuit is closing while peer is closing.
                            Err(TrySendError::Disconnected(_)) => (),
                        }
                        circ_map.remove(id);
                    } else if let Ok(cell) = Cached::try_map(cell, |v, _| v.ok_or(())) {
                        match circ.send(cell) {
                            Ok(()) => (),
                            // Full, return cell to buffer
                            Err(TrySendError::Full(cell)) => *p = Some(cell),
                            // Circuit is closing, drop cell and close it for real
                            Err(TrySendError::Disconnected(_)) => {
                                debug!(id, "cannot send cell, circuit is closing");
                                circ_map.remove(id);
                                self.pending_close.push_back((id, DestroyReason::Internal));
                            }
                        }
                    }

                    Ok(())
                })?;

            // Process drop messages
        }
    }
}
