use std::collections::hash_map::{Entry, HashMap};
use std::future::Future;
use std::io::{Error as IoError, ErrorKind, IoSlice, IoSliceMut, Read, Result as IoResult, Write};
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::task::Poll::*;
use std::task::{Context, Poll};
use std::time::Instant;

use flume::r#async::RecvStream;
use flume::{Receiver, Sender, bounded};
use futures_core::Stream as _;
use futures_util::select_biased;
use pin_project::pin_project;
use rustls::Error as RustlsError;
use rustls::client::ClientConnection;
use scopeguard::guard;
use tracing::{Span, debug, debug_span, error, info, instrument, trace, warn};

use super::controller::ChannelController;
use super::{CellMsg, ChannelConfig, ChannelInput, ControlMsg, Stream, Timeout};
use crate::crypto::relay::RelayId;
use crate::crypto::tls::setup_client;
use crate::errors;
use crate::runtime::{Runtime, Stream as RTStream, Timer};
use crate::util::cell_map::CellMap;
use crate::util::{AsyncReadWrapper, AsyncWriteWrapper, FutureRepollable, print_hex, print_list};

struct ChannelInner<C: ChannelController> {
    sender: Sender<C::ControlMsg>,
    receiver: Receiver<C::ControlMsg>,
    config: C::Config,
}

impl<C: ChannelController> AsRef<C::Config> for ChannelInner<C> {
    fn as_ref(&self) -> &C::Config {
        &self.config
    }
}

#[pin_project]
struct Channel<R: Runtime, C: ChannelController, M> {
    #[pin]
    handle: FutureRepollable<R::Task<bool>>,
    inner: Arc<ChannelInner<C>>,
    #[pin]
    meta: M,
}

/// A reference to channel.
///
/// Use [`ChannelManager::get`] to create it.
pub struct ChannelRef<'a, R: Runtime, C: ChannelController, M> {
    inner: Pin<&'a mut Channel<R, C, M>>,
    runtime: &'a R,
}

/// A removed channel.
///
/// Typically created by [`ChannelManager::remove`],
/// it can be used to do finalization outside channel manager.
pub struct ChannelRemoved<R: Runtime, C: ChannelController, M>(Pin<Box<Channel<R, C, M>>>);

/// Channel manager.
///
/// Manages multiple channels, each running in separate task.
/// It is recommended to create dedicated task to manage [`ChannelManager`]
/// and communicate to it via channels.
pub struct ChannelManager<R: Runtime, C: ChannelController, M = ()> {
    runtime: R,
    #[allow(clippy::type_complexity)]
    channels: HashMap<RelayId, Pin<Box<Channel<R, C, M>>>>,
}

impl<R: Runtime, C: ChannelController, M> ChannelManager<R, C, M> {
    /// Create new [`ChannelManager`].
    pub fn new(runtime: R) -> Self {
        Self {
            runtime,
            channels: HashMap::new(),
        }
    }

    /// Get reference to channel.
    pub fn get<'a>(&'a mut self, peer: &RelayId) -> Option<ChannelRef<'a, R, C, M>> {
        self.channels.get_mut(peer).map(|v| ChannelRef {
            inner: v.as_mut(),
            runtime: &self.runtime,
        })
    }

    /// Checks if channel with peer ID exists.
    ///
    /// Note that it doesn't check if channel is running.
    pub fn has(&self, peer: &RelayId) -> bool {
        self.channels.contains_key(peer)
    }

    /// Open new channel if it doesn't exist.
    ///
    /// # Parameters
    /// - `cfg` : Channel configuration.
    /// - `meta` : Metadata associated with channel.
    pub fn create(&mut self, cfg: C::Config, meta: M) -> ChannelRef<'_, R, C, M>
    where
        R: 'static + Clone,
        C: 'static,
    {
        let v = self.channels.entry(*cfg.peer_id()).or_insert_with(|| {
            let (sender, receiver) = bounded(0);
            let inner = Arc::new(ChannelInner {
                config: cfg,
                sender,
                receiver,
            });

            Box::pin(Channel {
                handle: self
                    .runtime
                    .spawn(handle_channel(self.runtime.clone(), inner.clone()))
                    .into(),
                inner,
                meta,
            })
        });

        ChannelRef {
            inner: v.as_mut(),
            runtime: &self.runtime,
        }
    }

    /// Remove channel from manager.
    ///
    /// Make sure channel has stopped running before removing (use [`ChannelRef::completion`] or [`ChannelRemoved::completion`] to wait).
    pub fn remove(&mut self, peer: &RelayId) -> Option<ChannelRemoved<R, C, M>> {
        self.channels.remove(peer).map(ChannelRemoved)
    }

    /// Insert existing stream to manager if it doesn't exist.
    ///
    /// Useful for relays where connection comes from outside.
    ///
    /// # Parameters
    /// - `stream` : Network stream.
    /// - `cfg` : Channel configuration.
    /// - `meta` : Metadata associated with channel.
    pub fn insert(
        &mut self,
        stream: R::Stream,
        cfg: C::Config,
        meta: M,
    ) -> IoResult<ChannelRef<'_, R, C, M>>
    where
        R: 'static + Clone,
        C: 'static,
    {
        let v = match self.channels.entry(*cfg.peer_id()) {
            Entry::Occupied(e) => {
                drop((stream, cfg, meta));
                e.into_mut()
            }
            Entry::Vacant(e) => {
                let (sender, receiver) = bounded(0);
                let inner = Arc::new(ChannelInner {
                    config: cfg,
                    sender,
                    receiver,
                });
                let peer_addr = stream.peer_addr()?;

                e.insert(Box::pin(Channel {
                    handle: self
                        .runtime
                        .spawn(handle_stream(
                            self.runtime.clone(),
                            inner.clone(),
                            stream,
                            peer_addr,
                        ))
                        .into(),
                    inner,
                    meta,
                }))
            }
        };

        Ok(ChannelRef {
            inner: v.as_mut(),
            runtime: &self.runtime,
        })
    }
}

impl<R: Runtime, C: ChannelController, M> Channel<R, C, M> {
    /// Gets reference to channel metadata.
    fn meta(self: Pin<&mut Self>) -> Pin<&mut M> {
        self.project().meta
    }

    /// Gets reference to channel configuration.
    fn config(&self) -> &C::Config {
        &self.inner.config
    }

    /// Send a control message.
    async fn send_control(
        self: Pin<&mut Self>,
        msg: C::ControlMsg,
    ) -> Result<(), errors::SendControlMsgError> {
        let this = self.project();

        select_biased! {
            res = this.handle => Err(if res {
                errors::SendControlMsgError::HandleFinalized
            } else {
                errors::HandleError.into()
            }),
            res = this.inner.sender.send_async(msg) => {
                assert!(res.is_ok(), "receiver somehow got closed");
                Ok(())
            },
        }
    }

    /// Send a control message and wait for completion.
    ///
    /// Useful for sending shutdown message.
    async fn send_and_completion(
        mut self: Pin<&mut Self>,
        msg: C::ControlMsg,
    ) -> Result<(), errors::HandleError> {
        match self.as_mut().send_control(msg).await {
            Ok(()) => self.completion().await,
            Err(errors::SendControlMsgError::HandleFinalized) => Ok(()),
            Err(errors::SendControlMsgError::HandleError(e)) => Err(e),
        }
    }

    /// Waits controller for completion.
    async fn completion(self: Pin<&mut Self>) -> Result<(), errors::HandleError> {
        if self.project().handle.as_mut().await {
            Ok(())
        } else {
            Err(errors::HandleError)
        }
    }

    /// Restarts controller if stopped.
    ///
    /// Sometimes it's useful to reuse state.
    pub fn restart(self: Pin<&mut Self>, r: &R) -> bool
    where
        R: 'static + Clone,
        C: 'static,
    {
        let mut this = self.project();

        if !this.handle.is_finished() {
            return false;
        }

        this.handle.as_mut().set(
            r.spawn(handle_channel(r.clone(), this.inner.clone()))
                .into(),
        );
        true
    }

    /// Restarts controller if stopped (with attached stream).
    pub fn restart_with(self: Pin<&mut Self>, r: &R, stream: R::Stream) -> bool
    where
        R: 'static + Clone,
        C: 'static,
    {
        let mut this = self.project();

        if !this.handle.is_finished() {
            return false;
        }

        let peer_addr = match stream.peer_addr() {
            Ok(v) => v,
            Err(e) => {
                error!(error = display(e), "cannot get peer address");
                return false;
            }
        };

        this.handle.as_mut().set(
            r.spawn(handle_stream(
                r.clone(),
                this.inner.clone(),
                stream,
                peer_addr,
            ))
            .into(),
        );
        true
    }
}

impl<R: Runtime, C: ChannelController, M> ChannelRef<'_, R, C, M> {
    /// Gets reference to channel metadata.
    #[inline(always)]
    pub fn meta(&mut self) -> Pin<&mut M> {
        self.inner.as_mut().meta()
    }

    /// Gets reference to channel configuration.
    #[inline(always)]
    pub fn config(&self) -> &C::Config {
        self.inner.config()
    }

    /// Send a control message.
    #[inline(always)]
    pub async fn send_control(
        &mut self,
        msg: C::ControlMsg,
    ) -> Result<(), errors::SendControlMsgError> {
        self.inner.as_mut().send_control(msg).await
    }

    /// Send a control message and wait for completion.
    ///
    /// Useful for sending shutdown message.
    #[inline(always)]
    pub async fn send_and_completion(
        &mut self,
        msg: C::ControlMsg,
    ) -> Result<(), errors::HandleError> {
        self.inner.as_mut().send_and_completion(msg).await
    }

    /// Waits controller for completion.
    #[inline(always)]
    pub async fn completion(&mut self) -> Result<(), errors::HandleError> {
        self.inner.as_mut().completion().await
    }

    /// Restarts controller if stopped.
    ///
    /// Sometimes it's useful to reuse state.
    #[inline(always)]
    pub fn restart(&mut self) -> bool
    where
        R: 'static + Clone,
        C: 'static,
    {
        self.inner.as_mut().restart(self.runtime)
    }

    /// Restarts controller if stopped (with attached stream).
    #[inline(always)]
    pub fn restart_with(&mut self, stream: R::Stream) -> bool
    where
        R: 'static + Clone,
        C: 'static,
    {
        self.inner.as_mut().restart_with(self.runtime, stream)
    }
}

impl<R: Runtime, C: ChannelController, M> ChannelRemoved<R, C, M> {
    /// Gets reference to channel metadata.
    #[inline(always)]
    pub fn meta(&mut self) -> Pin<&mut M> {
        self.0.as_mut().meta()
    }

    /// Gets reference to channel configuration.
    #[inline(always)]
    pub fn config(&self) -> &C::Config {
        self.0.config()
    }

    /// Send a control message.
    #[inline(always)]
    pub async fn send_control(
        &mut self,
        msg: C::ControlMsg,
    ) -> Result<(), errors::SendControlMsgError> {
        self.0.as_mut().send_control(msg).await
    }

    /// Send a control message and wait for completion.
    ///
    /// Useful for sending shutdown message.
    #[inline(always)]
    pub async fn send_and_completion(
        mut self,
        msg: C::ControlMsg,
    ) -> Result<(), errors::HandleError> {
        self.0.as_mut().send_and_completion(msg).await
    }

    /// Waits controller for completion.
    #[inline(always)]
    pub async fn completion(mut self) -> Result<(), errors::HandleError> {
        self.0.as_mut().completion().await
    }
}

/// Channel manager that only manages one channel.
///
/// Useful if you want to manage channels yourself.
pub struct SingleManager<R: Runtime, C: ChannelController, M> {
    inner: Pin<Box<Channel<R, C, M>>>,
    runtime: R,
}

impl<R: Runtime, C: ChannelController, M> SingleManager<R, C, M> {
    /// Create new channel.
    ///
    /// # Parameters
    /// - `runtime` : Runtime used. Must be [`Clone`]-able.
    /// - `config` : Channel configuration.
    /// - `meta` : Channel metadata.
    pub fn new(runtime: R, config: C::Config, meta: M) -> Self
    where
        R: 'static + Clone,
        C: 'static,
    {
        let (sender, receiver) = bounded(0);
        let inner = Arc::new(ChannelInner {
            config,
            sender,
            receiver,
        });

        Self {
            inner: Box::pin(Channel {
                handle: runtime
                    .spawn(handle_channel(runtime.clone(), inner.clone()))
                    .into(),
                inner,
                meta,
            }),
            runtime,
        }
    }

    /// Bind stream into channel.
    ///
    /// # Parameters
    /// - `runtime` : Runtime used. Must be [`Clone`]-able.
    /// - `stream` : Stream to be bound.
    /// - `config` : Channel configuration.
    /// - `meta` : Channel metadata.
    pub fn with_stream(runtime: R, stream: R::Stream, config: C::Config, meta: M) -> IoResult<Self>
    where
        R: 'static + Clone,
        C: 'static,
    {
        let (sender, receiver) = bounded(0);
        let inner = Arc::new(ChannelInner {
            config,
            sender,
            receiver,
        });
        let peer_addr = stream.peer_addr()?;

        Ok(Self {
            inner: Box::pin(Channel {
                handle: runtime
                    .spawn(handle_stream(
                        runtime.clone(),
                        inner.clone(),
                        stream,
                        peer_addr,
                    ))
                    .into(),
                inner,
                meta,
            }),
            runtime,
        })
    }

    /// Create new channel with default metadata.
    ///
    /// # Parameters
    /// - `runtime` : Runtime used. Must be [`Clone`]-able.
    /// - `config` : Channel configuration.
    pub fn with_default_meta(runtime: R, config: C::Config) -> Self
    where
        R: 'static + Clone,
        C: 'static,
        M: Default,
    {
        Self::new(runtime, config, M::default())
    }

    /// Bind stream into channel with default metadata.
    ///
    /// # Parameters
    /// - `runtime` : Runtime used. Must be [`Clone`]-able.
    /// - `stream` : Stream to be bound.
    /// - `config` : Channel configuration.
    pub fn with_stream_default_meta(
        runtime: R,
        stream: R::Stream,
        config: C::Config,
    ) -> IoResult<Self>
    where
        R: 'static + Clone,
        C: 'static,
        M: Default,
    {
        Self::with_stream(runtime, stream, config, M::default())
    }

    /// Gets [`ChannelRef`] to self.
    pub fn as_ref(&mut self) -> ChannelRef<'_, R, C, M> {
        ChannelRef {
            inner: self.inner.as_mut(),
            runtime: &self.runtime,
        }
    }

    /// Gets reference to channel metadata.
    #[inline(always)]
    pub fn meta(&mut self) -> Pin<&mut M> {
        self.inner.as_mut().meta()
    }

    /// Gets reference to channel configuration.
    #[inline(always)]
    pub fn config(&self) -> &C::Config {
        self.inner.config()
    }

    /// Send a control message.
    #[inline(always)]
    pub async fn send_control(
        &mut self,
        msg: C::ControlMsg,
    ) -> Result<(), errors::SendControlMsgError> {
        self.inner.as_mut().send_control(msg).await
    }

    /// Send a control message and wait for completion.
    ///
    /// Useful for sending shutdown message.
    #[inline(always)]
    pub async fn send_and_completion(
        &mut self,
        msg: C::ControlMsg,
    ) -> Result<(), errors::HandleError> {
        self.inner.as_mut().send_and_completion(msg).await
    }

    /// Waits controller for completion.
    #[inline(always)]
    pub async fn completion(&mut self) -> Result<(), errors::HandleError> {
        self.inner.as_mut().completion().await
    }

    /// Restarts controller if stopped.
    ///
    /// Sometimes it's useful to reuse state.
    pub fn restart(&mut self) -> bool
    where
        R: 'static + Clone,
        C: 'static,
    {
        self.inner.as_mut().restart(&self.runtime)
    }

    /// Restarts controller if stopped (with attached stream).
    pub fn restart_with(&mut self, stream: R::Stream) -> bool
    where
        R: 'static + Clone,
        C: 'static,
    {
        self.inner.as_mut().restart_with(&self.runtime, stream)
    }
}

#[instrument(skip_all, fields(peer_id = %print_hex(cfg.config.peer_id())))]
async fn handle_channel<R: Runtime, C: ChannelController + 'static>(
    runtime: R,
    cfg: Arc<ChannelInner<C>>,
) -> bool {
    let stream = {
        let peer_addrs = cfg.config.peer_addrs();
        debug!(
            "connecting to peer at addresses: {}",
            print_list(&peer_addrs)
        );
        runtime.connect(&peer_addrs[..]).await
    };
    let stream = match stream {
        Ok(v) => v,
        Err(e) => {
            error!(error = display(e), "cannot connect to peer");
            return false;
        }
    };

    let peer_addr = match stream.peer_addr() {
        Ok(v) => v,
        Err(e) => {
            error!(error = display(e), "cannot get peer address");
            return false;
        }
    };
    debug!("connected to peer at {peer_addr}");

    handle_stream(runtime, cfg, stream, peer_addr).await
}

#[instrument(skip_all, fields(peer_id = %print_hex(cfg.config.peer_id())))]
async fn handle_stream<R: Runtime, C: ChannelController + 'static>(
    runtime: R,
    cfg: Arc<ChannelInner<C>>,
    stream: R::Stream,
    peer_addr: SocketAddr,
) -> bool {
    let tls = match setup_client(peer_addr.ip()) {
        Ok(v) => v,
        Err(e) => {
            error!(error = display(e), "rustls setup");
            return false;
        }
    };

    let fut = ChannelFut {
        runtime,
        stream: StreamWrapper {
            stream,
            tls,
            addr: peer_addr,
        },
        timer: None,
        timer_finished: true,
        ctrl_recv: Some(cfg.receiver.clone().into_stream()),
        circ_map: Some(CellMap::new(
            C::channel_cap(&cfg.config),
            C::channel_aggregate_cap(&cfg.config),
        )),
        cell_msg_pause: false,
        state: State::Normal,
        cont: C::new(cfg),
        span: debug_span!("ChannelFut"),
    };

    match fut.await {
        Ok(()) => true,
        Err(e) => {
            error!(error = display(e), "channel error");
            false
        }
    }
}

#[derive(PartialEq, Eq)]
enum State {
    Normal,
    ReqShutdown,
    TlsShutdown,
    Shutdown,
}

#[pin_project]
struct ChannelFut<R: Runtime, C: ChannelController> {
    runtime: R,
    #[pin]
    stream: StreamWrapper<R::Stream>,
    #[pin]
    timer: Option<R::Timer>,
    timer_finished: bool,
    #[pin]
    ctrl_recv: Option<RecvStream<'static, C::ControlMsg>>,
    circ_map: Option<CellMap<C::Cell, C::CircMeta>>,
    cell_msg_pause: bool,
    cont: C,
    state: State,
    span: Span,
}

const FLAG_READ: u8 = 1 << 0;
const FLAG_WRITE: u8 = 1 << 1;
const FLAG_TIMEOUT: u8 = 1 << 2;
const FLAG_CTRLMSG: u8 = 1 << 3;
const FLAG_FLUSH: u8 = 1 << 4;
const FLAG_CELLMSG: u8 = 1 << 5;
const FLAG_EMPTY_HANDLE: u8 = 1 << 7;

impl<R: Runtime, C: ChannelController> Future for ChannelFut<R, C> {
    type Output = Result<(), C::Error>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let mut this = self.project();
        let mut pending = 0u8;

        'main: loop {
            let _guard = this.span.enter();

            // Process shutdown
            match this.state {
                State::Shutdown => {
                    this.timer.set(None);
                    *this.circ_map = None;
                    this.ctrl_recv.set(None);
                    return this.stream.poll_close(cx).map_err(|e| e.into());
                }
                State::ReqShutdown => {
                    debug!("graceful shutdown request received");
                    this.stream.as_mut().tls().send_close_notify();
                    this.timer.set(None);
                    *this.state = State::TlsShutdown;
                    *this.circ_map = None;
                    this.ctrl_recv.set(None);
                    continue;
                }
                _ => (),
            }

            // Process TLS
            match this
                .stream
                .as_mut()
                .process(cx, *this.state == State::TlsShutdown, pending)
            {
                Ok(Pending) => return Pending,
                Ok(Ready(None)) => {
                    *this.state = State::Shutdown;
                    continue;
                }
                Ok(Ready(Some(v))) => pending = v,
                Err(e) => {
                    *this.state = State::Shutdown;
                    return Ready(Err(match e {
                        ErrorType::Io(e) => e.into(),
                        ErrorType::Tls(e) => e.into(),
                    }));
                }
            }

            // Process controller
            let mut has_event = false;
            let mut ctrl_recv = this
                .ctrl_recv
                .as_mut()
                .as_pin_mut()
                .expect("control receiver should not be dropped");
            let circ_map = this
                .circ_map
                .as_mut()
                .expect("circuit map should not be dropped");

            if !*this.timer_finished && pending & FLAG_TIMEOUT == 0 {
                pending |= FLAG_TIMEOUT;

                if this
                    .timer
                    .as_mut()
                    .as_pin_mut()
                    .is_some_and(|t| t.poll(cx).is_ready())
                {
                    *this.timer_finished = true;
                    // Event: timeout
                    this.cont
                        .handle(Timeout)
                        .inspect_err(|_| *this.state = State::Shutdown)?;
                    has_event = true;
                }
            }

            if pending & FLAG_CTRLMSG == 0 {
                while let Ready(msg) = ctrl_recv.as_mut().poll_next(cx) {
                    let Some(msg) = msg else {
                        error!(
                            "shutting down: control channel disconnected (this might be a bug in channel manager)"
                        );
                        *this.state = State::Shutdown;
                        continue 'main;
                    };

                    // Event: control message
                    this.cont
                        .handle(ControlMsg(msg))
                        .inspect_err(|_| *this.state = State::Shutdown)?;
                    has_event = true;
                }

                pending |= FLAG_CTRLMSG;
            }

            if pending & FLAG_CELLMSG == 0 {
                while !*this.cell_msg_pause {
                    let Ready(msg) = circ_map.poll_recv(cx) else {
                        pending |= FLAG_CELLMSG;
                        break;
                    };

                    // Event: cell message
                    *this.cell_msg_pause = this
                        .cont
                        .handle(CellMsg(
                            msg.expect("circuit map aggregate receiver should never close"),
                        ))
                        .inspect_err(|_| *this.state = State::Shutdown)?
                        .0;
                    has_event = true;
                    if *this.cell_msg_pause {
                        debug!("pausing cell message receiving");
                    }
                }
            }

            if has_event || pending & FLAG_EMPTY_HANDLE == 0 {
                // Handle channel
                let ret = this
                    .cont
                    .handle((
                        ChannelInput::new(this.stream.as_mut().as_stream(), Instant::now()),
                        circ_map,
                    ))
                    .inspect_err(|_| *this.state = State::Shutdown)?;

                if ret.shutdown {
                    info!("controller requesting graceful shutdown");
                    *this.state = State::ReqShutdown;
                    continue;
                }
                if let Some(t) = ret.timeout {
                    debug!(timeout = debug(t), "resetting timer");
                    match this.timer.as_mut().as_pin_mut() {
                        Some(f) => f.reset(t),
                        None => this.timer.set(Some(this.runtime.timer(t))),
                    }

                    *this.timer_finished = false;
                    pending &= !FLAG_TIMEOUT;
                } else {
                    debug!("clearing timer");
                    // Regardless, mark timer as "finished"
                    *this.timer_finished = true;
                }
                match (*this.cell_msg_pause, ret.cell_msg_pause) {
                    (true, false) => debug!("resuming cell message receiving"),
                    (false, true) => debug!("pausing cell message receiving"),
                    _ => (),
                }
                *this.cell_msg_pause = ret.cell_msg_pause;
            }
            // Mark empty handle as true, because either timeout already fires or it has been handled previously.
            pending |= FLAG_EMPTY_HANDLE;

            let mut retry = false;
            if pending & FLAG_READ == 0 && this.stream.as_mut().tls().wants_read() {
                trace!("repolling: TLS wants to read");
                pending &= !FLAG_EMPTY_HANDLE; // Make sure controller will handle
                retry = true;
            }
            if pending & FLAG_WRITE == 0 && this.stream.as_mut().tls().wants_write() {
                trace!("repolling: TLS wants to write");
                pending &= !FLAG_EMPTY_HANDLE; // Make sure controller will handle
                retry = true;
            }
            if pending & FLAG_TIMEOUT == 0 && !*this.timer_finished && this.timer.is_some() {
                trace!("repolling: timer wants to be polled");
                retry = true;
            }
            if pending & FLAG_CELLMSG == 0 && !*this.cell_msg_pause {
                trace!("repolling: cell aggregate channel wants to be polled");
                retry = true;
            }

            if !retry {
                trace!("all futures are pending");
                // All futures are pending.
                return Pending;
            }
        }
    }
}

enum ErrorType {
    Io(IoError),
    Tls(RustlsError),
}

impl From<IoError> for ErrorType {
    fn from(e: IoError) -> Self {
        Self::Io(e)
    }
}

impl From<RustlsError> for ErrorType {
    fn from(e: RustlsError) -> Self {
        Self::Tls(e)
    }
}

#[pin_project]
struct StreamWrapper<S> {
    #[pin]
    stream: S,
    tls: ClientConnection,
    addr: SocketAddr,
}

impl<S: RTStream> StreamWrapper<S> {
    #[instrument(level = "debug", skip(self, cx))]
    fn process(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        is_shutdown: bool,
        mut pending: u8,
    ) -> Result<Poll<Option<u8>>, ErrorType> {
        let mut this = self.project();

        loop {
            this.tls.process_new_packets()?;

            if pending & FLAG_FLUSH == 0 && this.stream.as_mut().poll_flush(cx)?.is_pending() {
                pending |= FLAG_FLUSH;
            }

            let wants_write = pending & FLAG_WRITE == 0 && this.tls.wants_write();
            let wants_read = pending & FLAG_READ == 0 && this.tls.wants_read();
            if !(wants_write || wants_read) {
                break;
            }

            if wants_write {
                let mut wrapper = guard(AsyncWriteWrapper::new(cx, this.stream.as_mut()), |w| {
                    if w.finish() {
                        pending |= FLAG_WRITE;
                    }
                });

                while this.tls.wants_write() {
                    match this.tls.write_tls(&mut *wrapper) {
                        Ok(0) => {
                            info!("shutting down: write end connection closed");
                            return Ok(Ready(None));
                        }
                        Ok(_) => (),
                        Err(e) => match e.kind() {
                            ErrorKind::Interrupted | ErrorKind::WouldBlock => break,
                            _ => return Err(e.into()),
                        },
                    }
                }
            }

            if wants_read {
                let mut wrapper = guard(AsyncReadWrapper::new(cx, this.stream.as_mut()), |w| {
                    if w.finish() {
                        pending |= FLAG_READ;
                    }
                });

                while this.tls.wants_read() {
                    match this.tls.read_tls(&mut *wrapper) {
                        Ok(0) => {
                            // XXX: Read end is closed.
                            // We might have pending data to be written, but trying to handle it leads to infinite loop/pending.
                            // In the future, fix it?
                            info!("shutting down: read end connection closed");
                            return Ok(Ready(None));
                        }
                        Ok(_) => (),
                        Err(e) => match e.kind() {
                            ErrorKind::Interrupted | ErrorKind::WouldBlock => break,
                            _ => return Err(e.into()),
                        },
                    }
                }
            }
        }

        Ok(if is_shutdown && pending & (FLAG_READ | FLAG_WRITE) == 0 {
            info!("TLS shutdown finished");
            Ready(None)
        } else if this.tls.is_handshaking() || is_shutdown {
            if this.tls.is_handshaking() {
                debug!("pending: TLS handshaking");
            } else {
                debug!("pending: TLS shutdown");
            }
            assert_ne!(
                pending & (FLAG_READ | FLAG_WRITE),
                0,
                "TLS handshake pending but IO is not"
            );
            Pending
        } else {
            Ready(Some(pending))
        })
    }

    fn poll_close(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<IoResult<()>> {
        self.project().stream.poll_close(cx)
    }
}

impl<S> StreamWrapper<S> {
    fn tls(self: Pin<&mut Self>) -> &mut ClientConnection {
        self.project().tls
    }

    fn as_stream(self: Pin<&mut Self>) -> &mut dyn Stream {
        // SAFETY: Stream trait cannot access stream.
        unsafe { Pin::into_inner_unchecked(self) }
    }
}

impl<S> Read for StreamWrapper<S> {
    fn read(&mut self, buf: &mut [u8]) -> IoResult<usize> {
        self.tls.reader().read(buf)
    }

    fn read_vectored(&mut self, bufs: &mut [IoSliceMut<'_>]) -> IoResult<usize> {
        self.tls.reader().read_vectored(bufs)
    }
}

impl<S> Write for StreamWrapper<S> {
    fn write(&mut self, buf: &[u8]) -> IoResult<usize> {
        self.tls.writer().write(buf)
    }

    fn flush(&mut self) -> IoResult<()> {
        self.tls.writer().flush()
    }

    fn write_vectored(&mut self, bufs: &[IoSlice<'_>]) -> IoResult<usize> {
        self.tls.writer().write_vectored(bufs)
    }
}

impl<S> Stream for StreamWrapper<S> {
    fn link_cert(&self) -> Option<&[u8]> {
        self.tls.peer_certificates()?.first().map(|v| &v[..])
    }

    fn peer_addr(&self) -> &SocketAddr {
        &self.addr
    }
}
