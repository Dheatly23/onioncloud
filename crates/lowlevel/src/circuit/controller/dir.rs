use std::fmt::Display;
use std::marker::PhantomData;
use std::num::NonZeroU32;
use std::sync::Arc;
use std::time::{Duration, Instant};

use flume::TrySendError;
use futures_channel::oneshot::{Receiver, Sender, channel};
use tracing::instrument;

use crate::cache::{Cached, CellCache, cast};
use crate::cell::create::CreatedFast;
use crate::cell::destroy::DestroyReason;
use crate::cell::{Cell, CellHeader};
use crate::circuit::controller::CircuitController;
use crate::circuit::{
    CellMsg, CellMsgPause, CircuitInput, CircuitOutput, ControlMsg, NewStream, StreamCellMsg,
    Timeout,
};
use crate::crypto::onion::{CircuitDigest, OnionLayer128, OnionLayerFast};
use crate::errors;
use crate::util::cell_map::CellMap;
use crate::util::sans_io::Handle;

type CacheTy = Arc<dyn Send + Sync + CellCache>;
type CachedCell<C = Cell> = Cached<C, CacheTy>;

/// Trait for [`DirController`] configuration type.
pub trait DirConfig {
    /// Get [`CellCache`].
    ///
    /// # Implementer's Note
    ///
    /// To maximize cache utilization, cache should be as global as possible.
    fn get_cache(&self) -> Arc<dyn Send + Sync + CellCache>;
}

pub struct DirController<Cfg> {
    cache: CacheTy,
    linkver: u16,

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
    NewStream(Sender<Result<NewStream<CachedCell>, errors::NoFreeCircIDError>>),
}

pub struct DirStreamMeta {}

impl<Cfg: 'static + Send + Sync + Display + DirConfig> CircuitController for DirController<Cfg> {
    type Config = Cfg;
    type Error = errors::DirControllerError;
    type ControlMsg = DirControlMsg;
    type Cell = CachedCell;
    type StreamMeta = DirStreamMeta;

    fn new(cfg: Arc<dyn Send + Sync + AsRef<Self::Config>>, circ_id: NonZeroU32) -> Self {
        let cache = (*cfg).as_ref().get_cache();
        Self {
            state: State::Init(InitState::new(&cache, circ_id)),
            cache,
            linkver: 0,
            _p: PhantomData,
        }
    }

    fn set_linkver(&mut self, linkver: u16) {
        self.linkver = linkver;
    }
}

impl<'a, Cfg>
    Handle<(
        CircuitInput<'a, CachedCell>,
        &'a mut CellMap<CachedCell, DirStreamMeta>,
    )> for DirController<Cfg>
{
    type Return = Result<CircuitOutput<'a, CachedCell>, errors::DirControllerError>;

    fn handle(
        &mut self,
        (input, stream_map): (
            CircuitInput<'a, CachedCell>,
            &'a mut CellMap<CachedCell, DirStreamMeta>,
        ),
    ) -> Result<CircuitOutput<'a, CachedCell>, errors::DirControllerError> {
        match self.state {
            State::Init(ref mut s) => s.handle(&self.cache, input),
            State::Steady(ref mut s) => s.handle(&self.cache, input, stream_map),
            State::Shutdown => {
                let mut output = input.output();
                output.shutdown(self.cache.clone(), DestroyReason::Internal);
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
            DirControlMsg::NewStream(_) => todo!(),
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
                self.state = State::Steady(s.handle_cell(&self.cache, msg.0)?);
                Ok(false.into())
            }
            State::Steady(ref mut s) => s.handle_cell(&self.cache, msg.0),
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
            State::Steady(ref mut s) => s.handle_stream_cell(&self.cache, msg.0),
            State::Shutdown => Ok(true.into()),
        }
    }
}

struct InitState {
    client: Option<OnionLayerFast>,
    cell: Option<CachedCell>,
    timeout: Option<Instant>,
}

const CREATE_TIMEOUT: Duration = Duration::from_secs(10);

impl InitState {
    fn new(cache: &CacheTy, circ_id: NonZeroU32) -> Self {
        let client = OnionLayerFast::new();

        Self {
            cell: Some(Cached::map_into(client.create_cell(circ_id, cache))),
            client: Some(client),
            timeout: None,
        }
    }

    #[instrument(level = "debug", skip_all)]
    fn handle<'a>(
        &mut self,
        cache: &CacheTy,
        input: CircuitInput<'a, CachedCell>,
    ) -> Result<CircuitOutput<'a, CachedCell>, errors::DirControllerError> {
        let mut output = input.output();

        output
            .cell_msg_pause(true.into())
            .stream_cell_msg_pause(true.into());

        let timeout = *self
            .timeout
            .get_or_insert_with(|| output.time() + CREATE_TIMEOUT);
        output.timeout(timeout);

        if timeout >= output.time() {
            output.shutdown(cache.clone(), DestroyReason::Timeout);
            return Ok(output);
        }

        if let Some(cell) = self.cell.take() {
            match output.try_send(cell) {
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
        cache: &CacheTy,
        cell: CachedCell,
    ) -> Result<SteadyState, errors::DirControllerError> {
        let mut cell = Cached::map(cell, Some);

        if let Some(cell) = cast::<CreatedFast>(&mut cell)? {
            let layer = self
                .client
                .take()
                .expect("client params must exist")
                .derive_client(&cache.cache(cell))?;

            return Ok(SteadyState {
                encrypt: layer.encrypt,
                digest: layer.digest,

                is_timeout: false,
                forward_data_count: 0,
                backward_data_count: 0,
            });
        }

        let cell = Cached::transpose(cell).expect("cell must be returned if not match");
        Err(
            errors::InvalidCellHeader::with_header(&CellHeader::new(cell.circuit, cell.command))
                .into(),
        )
    }
}

struct SteadyState {
    encrypt: OnionLayer128,
    digest: CircuitDigest,

    is_timeout: bool,
    forward_data_count: usize,
    backward_data_count: usize,
}

impl SteadyState {
    #[instrument(level = "debug", skip_all)]
    fn handle<'a>(
        &mut self,
        cache: &CacheTy,
        input: CircuitInput<'a, CachedCell>,
        stream_map: &'a mut CellMap<CachedCell, DirStreamMeta>,
    ) -> Result<CircuitOutput<'a, CachedCell>, errors::DirControllerError> {
        todo!()
    }

    #[instrument(level = "debug", skip_all)]
    fn handle_cell(
        &mut self,
        cache: &CacheTy,
        cell: CachedCell,
    ) -> Result<CellMsgPause, errors::DirControllerError> {
        todo!()
    }

    #[instrument(level = "debug", skip_all)]
    fn handle_stream_cell(
        &mut self,
        cache: &CacheTy,
        cell: CachedCell,
    ) -> Result<CellMsgPause, errors::DirControllerError> {
        todo!()
    }
}
