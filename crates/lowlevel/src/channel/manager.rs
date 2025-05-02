use std::collections::hash_map::{Entry, HashMap};
use std::future::Future;
use std::io::{ErrorKind, IoSlice, IoSliceMut, Read, Result as IoResult, Write};
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Instant;

use flume::r#async::RecvStream;
use flume::{Receiver, Sender, bounded};
use futures_core::future::FusedFuture;
use futures_core::{Stream as _, ready};
use futures_io::AsyncWrite;
use futures_util::select_biased;
use pin_project::pin_project;
use rustls::client::ClientConnection;
use scopeguard::guard;
use tracing::{Span, debug, debug_span, error, info, instrument, trace, warn};

use super::controller::{ChannelController, ControlMsg, Timeout};
use super::{ChannelConfig, ChannelInput, ChannelOutput, CircuitMap, Stream};
use crate::crypto::relay::RelayId;
use crate::crypto::tls::setup_client;
use crate::errors;
use crate::runtime::{Runtime, Stream as _, Timer};
use crate::util::{AsyncReadWrapper, AsyncWriteWrapper, print_hex, print_list};

struct ChannelInner<C: ChannelController> {
    config: C::Config,
    sender: Sender<C::ControlMsg>,
    receiver: Receiver<C::ControlMsg>,
}

#[pin_project]
struct Channel<R: Runtime, C: ChannelController, M> {
    #[pin]
    handle: HandleWrapper<R::Task<bool>>,
    inner: Arc<ChannelInner<C>>,
    #[pin]
    meta: M,
}

/// A reference to channel.
///
/// Use [`ChannelManager::get`] to create it.
pub struct ChannelRef<'a, R: Runtime, C: ChannelController, M> {
    inner: Pin<&'a mut Channel<R, C, M>>,
    runtime: &'a mut R,
}

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
            runtime: &mut self.runtime,
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
                handle: HandleWrapper::Fut(
                    self.runtime
                        .spawn(handle_channel(self.runtime.clone(), inner.clone())),
                ),
                inner,
                meta,
            })
        });

        ChannelRef {
            inner: v.as_mut(),
            runtime: &mut self.runtime,
        }
    }

    /// Remove channel from manager.
    ///
    /// Make sure channel has stopped running before removing (use [`ChannelRef::completion`] to wait).
    pub fn remove(&mut self, peer: &RelayId) -> bool {
        self.channels.remove(peer).is_some()
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
                    handle: HandleWrapper::Fut(self.runtime.spawn(handle_stream(
                        self.runtime.clone(),
                        inner.clone(),
                        stream,
                        peer_addr,
                    ))),
                    inner,
                    meta,
                }))
            }
        };

        Ok(ChannelRef {
            inner: v.as_mut(),
            runtime: &mut self.runtime,
        })
    }
}

impl<R: Runtime, C: ChannelController, M> ChannelRef<'_, R, C, M> {
    /// Gets reference to channel metadata.
    pub fn meta(&mut self) -> Pin<&mut M> {
        self.inner.as_mut().project().meta
    }

    /// Send a control message.
    pub async fn send_control(
        &mut self,
        msg: C::ControlMsg,
    ) -> Result<(), errors::SendControlMsgError> {
        let this = self.inner.as_mut().project();

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
    pub async fn send_and_completion(
        &mut self,
        msg: C::ControlMsg,
    ) -> Result<(), errors::HandleError> {
        match self.send_control(msg).await {
            Ok(()) => self.completion().await,
            Err(errors::SendControlMsgError::HandleFinalized) => Ok(()),
            Err(errors::SendControlMsgError::HandleError(e)) => Err(e),
        }
    }

    /// Waits controller for completion.
    pub async fn completion(&mut self) -> Result<(), errors::HandleError> {
        if self.inner.as_mut().project().handle.as_mut().await {
            Ok(())
        } else {
            Err(errors::HandleError)
        }
    }

    /// Restarts controller if stopped.
    ///
    /// Sometimes it's useful to reuse state.
    pub fn restart(&mut self) -> bool
    where
        R: 'static + Clone,
        C: 'static,
    {
        let mut this = self.inner.as_mut().project();

        if !matches!(&*this.handle, HandleWrapper::Res(_)) {
            return false;
        }

        this.handle.as_mut().set(HandleWrapper::Fut(
            self.runtime
                .spawn(handle_channel(self.runtime.clone(), this.inner.clone())),
        ));
        true
    }

    /// Restarts controller if stopped (with attached stream).
    pub fn restart_with(&mut self, stream: R::Stream) -> bool
    where
        R: 'static + Clone,
        C: 'static,
    {
        let mut this = self.inner.as_mut().project();

        if !matches!(&*this.handle, HandleWrapper::Res(_)) {
            return false;
        }

        let peer_addr = match stream.peer_addr() {
            Ok(v) => v,
            Err(e) => {
                error!(error = format_args!("{}", e), "cannot get peer address");
                return false;
            }
        };

        this.handle
            .as_mut()
            .set(HandleWrapper::Fut(self.runtime.spawn(handle_stream(
                self.runtime.clone(),
                this.inner.clone(),
                stream,
                peer_addr,
            ))));
        true
    }
}

#[pin_project(project = HandleWrapperProj)]
enum HandleWrapper<F: Future> {
    Fut(#[pin] F),
    Res(F::Output),
}

impl<F> Future for HandleWrapper<F>
where
    F: Future,
    F::Output: Copy,
{
    type Output = F::Output;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        match self.as_mut().project() {
            HandleWrapperProj::Fut(f) => {
                let r = ready!(f.poll(cx));
                self.set(Self::Res(r));
                Poll::Ready(r)
            }
            HandleWrapperProj::Res(r) => Poll::Ready(*r),
        }
    }
}

impl<F> FusedFuture for HandleWrapper<F>
where
    F: Future,
    F::Output: Copy,
{
    fn is_terminated(&self) -> bool {
        // Always can be polled
        false
    }
}

#[instrument(skip_all, fields(peer_id = %print_hex(cfg.config.peer_id())))]
async fn handle_channel<R: Runtime, C: ChannelController>(
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
            error!(error = format_args!("{}", e), "cannot connect to peer");
            return false;
        }
    };

    let peer_addr = match stream.peer_addr() {
        Ok(v) => v,
        Err(e) => {
            error!(error = format_args!("{}", e), "cannot get peer address");
            return false;
        }
    };
    debug!("connected to peer at {peer_addr}");

    handle_stream(runtime, cfg, stream, peer_addr).await
}

#[instrument(skip_all, fields(peer_id = %print_hex(cfg.config.peer_id())))]
async fn handle_stream<R: Runtime, C: ChannelController>(
    runtime: R,
    cfg: Arc<ChannelInner<C>>,
    stream: R::Stream,
    peer_addr: SocketAddr,
) -> bool {
    let tls = match setup_client(peer_addr.ip()) {
        Ok(v) => v,
        Err(e) => {
            error!(error = format_args!("{}", e), "rustls setup");
            return false;
        }
    };

    let fut = ChannelFut {
        runtime,
        stream,
        timer: None,
        timer_finished: true,
        tls: TlsWrapper(tls, peer_addr),
        cont: C::new(&cfg.config),
        ctrl_recv: Some(cfg.receiver.clone().into_stream()),
        circ_map: Some(CircuitMap::new()),
        state: State::Normal,
        span: debug_span!("ChannelFut"),
    };
    drop(cfg);

    match fut.await {
        Ok(()) => true,
        Err(e) => {
            error!(error = format_args!("{}", e), "channel error");
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
    stream: R::Stream,
    #[pin]
    timer: Option<R::Timer>,
    timer_finished: bool,
    tls: TlsWrapper,
    #[pin]
    ctrl_recv: Option<RecvStream<'static, C::ControlMsg>>,
    circ_map: Option<CircuitMap<C::Cell, C::CircMeta>>,
    cont: C,
    state: State,
    span: Span,
}

impl<R: Runtime, C: ChannelController> Future for ChannelFut<R, C> {
    type Output = Result<(), C::Error>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let mut this = self.project();
        let mut pending = 0u8;

        const FLAG_READ: u8 = 1 << 0;
        const FLAG_WRITE: u8 = 1 << 1;
        const FLAG_TIMEOUT: u8 = 1 << 2;
        const FLAG_CTRLMSG: u8 = 1 << 3;
        const FLAG_FLUSH: u8 = 1 << 4;
        const FLAG_EMPTY_HANDLE: u8 = 1 << 7;

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
                    this.tls.0.send_close_notify();
                    *this.state = State::TlsShutdown;
                    *this.circ_map = None;
                    this.ctrl_recv.set(None);
                    continue;
                }
                _ => (),
            }

            // Process TLS
            loop {
                if let Err(e) = this.tls.0.process_new_packets() {
                    warn!("shutting down: TLS error");
                    *this.state = State::Shutdown;
                    return Poll::Ready(Err(e.into()));
                }

                if pending & FLAG_FLUSH == 0 {
                    match this.stream.as_mut().poll_flush(cx) {
                        Poll::Pending => pending |= FLAG_FLUSH,
                        Poll::Ready(Ok(())) => (),
                        Poll::Ready(Err(e)) => {
                            warn!("shutting down: IO error");
                            *this.state = State::Shutdown;
                            return Poll::Ready(Err(e.into()));
                        }
                    }
                }

                let wants_write = pending & FLAG_WRITE == 0 && this.tls.0.wants_write();
                let wants_read = pending & FLAG_READ == 0 && this.tls.0.wants_read();
                if !(wants_write || wants_read) {
                    break;
                }

                if wants_write {
                    let mut wrapper =
                        guard(AsyncWriteWrapper::new(cx, this.stream.as_mut()), |w| {
                            if w.finish() {
                                pending |= FLAG_WRITE;
                            }
                        });

                    while this.tls.0.wants_write() {
                        match this.tls.0.write_tls(&mut *wrapper) {
                            Ok(0) => {
                                debug_assert!(
                                    !this.tls.0.wants_write(),
                                    "TLS writes EOF yet wants to write more"
                                );
                                info!("shutting down: TLS write finished");
                                *this.state = State::Shutdown;
                                continue 'main;
                            }
                            Ok(_) => (),
                            Err(e)
                                if matches!(
                                    e.kind(),
                                    ErrorKind::Interrupted | ErrorKind::WouldBlock
                                ) =>
                            {
                                break;
                            }
                            Err(e) => {
                                warn!("shutting down: IO error");
                                *this.state = State::Shutdown;
                                return Poll::Ready(Err(e.into()));
                            }
                        }
                    }
                }

                if wants_read {
                    let mut wrapper = guard(AsyncReadWrapper::new(cx, this.stream.as_mut()), |w| {
                        if w.finish() {
                            pending |= FLAG_READ;
                        }
                    });

                    while this.tls.0.wants_read() {
                        match this.tls.0.read_tls(&mut *wrapper) {
                            Ok(0) => {
                                debug_assert!(
                                    !this.tls.0.wants_read(),
                                    "TLS reads EOF yet wants to read more"
                                );
                                break;
                            }
                            Ok(_) => (),
                            Err(e)
                                if matches!(
                                    e.kind(),
                                    ErrorKind::Interrupted | ErrorKind::WouldBlock
                                ) =>
                            {
                                break;
                            }
                            Err(e) => {
                                warn!("shutting down: IO error");
                                *this.state = State::Shutdown;
                                return Poll::Ready(Err(e.into()));
                            }
                        }
                    }
                }
            }

            if *this.state == State::TlsShutdown && pending & (FLAG_READ | FLAG_WRITE) == 0 {
                info!("shutting down: TLS shutdown finished");
                *this.state = State::Shutdown;
                continue 'main;
            }

            if this.tls.0.is_handshaking() || *this.state == State::TlsShutdown {
                if this.tls.0.is_handshaking() {
                    debug!("pending: TLS handshaking");
                } else {
                    debug!("pending: TLS shutdown");
                }
                assert_ne!(
                    pending & (FLAG_READ | FLAG_WRITE),
                    0,
                    "TLS handshake pending but IO is not"
                );
                return Poll::Pending;
            }

            const fn match_out<E>(v: &Option<Result<ChannelOutput, E>>) -> bool {
                matches!(
                    v,
                    None | Some(Ok(ChannelOutput {
                        shutdown: false,
                        ..
                    }))
                )
            }

            // Process controller
            let mut ctrl_recv = this
                .ctrl_recv
                .as_mut()
                .as_pin_mut()
                .expect("control receiver should not be dropped");
            let circ_map = this
                .circ_map
                .as_mut()
                .expect("circuit map should not be dropped");

            let mut time = None;
            let mut time = move || *time.get_or_insert_with(Instant::now);
            let mut ret = None;
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
                    ret = Some(this.cont.handle((
                        Timeout,
                        ChannelInput::new(this.tls, Some(cx), circ_map, time()),
                    )));
                }
            }

            if pending & FLAG_CTRLMSG == 0 {
                while match_out(&ret) {
                    let msg = match ctrl_recv.as_mut().poll_next(cx) {
                        Poll::Pending => {
                            pending |= FLAG_CTRLMSG;
                            break;
                        }
                        Poll::Ready(Some(v)) => v,
                        Poll::Ready(None) => {
                            error!(
                                "shutting down: control channel disconnected (this might be a bug in channel manager)"
                            );
                            *this.state = State::Shutdown;
                            continue 'main;
                        }
                    };

                    // Event: control message
                    ret = Some(this.cont.handle((
                        ControlMsg(msg),
                        ChannelInput::new(this.tls, Some(cx), circ_map, time()),
                    )));
                }
            }

            if ret.is_none() && pending & FLAG_EMPTY_HANDLE == 0 {
                // No event
                ret =
                    Some(
                        this.cont
                            .handle(ChannelInput::new(this.tls, Some(cx), circ_map, time())),
                    );
            }
            // Mark empty handle as true, because either timeout already fires or it has been handled previously.
            pending |= FLAG_EMPTY_HANDLE;

            let ret = match ret.transpose() {
                Ok(v) => v,
                Err(e) => {
                    warn!("shutting down: controller error");
                    *this.state = State::Shutdown;
                    return Poll::Ready(Err(e));
                }
            };

            match ret {
                Some(ChannelOutput { shutdown: true, .. }) => {
                    info!("controller requesting graceful shutdown");
                    *this.state = State::ReqShutdown;
                    continue;
                }
                Some(ChannelOutput {
                    timeout: Some(t), ..
                }) => {
                    debug!(timeout = format!("{:?}", t), "resetting timer");
                    let f = loop {
                        if let Some(f) = this.timer.as_mut().as_pin_mut() {
                            break f;
                        }
                        this.timer.set(Some(this.runtime.timer(t)));
                    };

                    f.reset(t);
                    *this.timer_finished = false;
                    pending &= !FLAG_TIMEOUT;
                }
                Some(ChannelOutput { timeout: None, .. }) => {
                    debug!("clearing timer");
                    // Regardless, mark timer as "finished"
                    *this.timer_finished = true;
                }
                _ => (),
            }

            let mut retry = false;
            if pending & FLAG_READ == 0 && this.tls.0.wants_read() {
                trace!("repolling: TLS wants to read");
                pending &= !FLAG_EMPTY_HANDLE; // Make sure controller will handle
                retry = true;
            }
            if pending & FLAG_WRITE == 0 && this.tls.0.wants_write() {
                trace!("repolling: TLS wants to write");
                pending &= !FLAG_EMPTY_HANDLE; // Make sure controller will handle
                retry = true;
            }
            if pending & FLAG_TIMEOUT == 0 && !*this.timer_finished && this.timer.is_some() {
                trace!("repolling: timer wants to be polled");
                retry = true;
            }

            if !retry {
                trace!("all futures are pending");
                // All futures are pending.
                return Poll::Pending;
            }
        }
    }
}

struct TlsWrapper(ClientConnection, SocketAddr);

impl Read for TlsWrapper {
    fn read(&mut self, buf: &mut [u8]) -> IoResult<usize> {
        self.0.reader().read(buf)
    }

    fn read_vectored(&mut self, bufs: &mut [IoSliceMut<'_>]) -> IoResult<usize> {
        self.0.reader().read_vectored(bufs)
    }
}

impl Write for TlsWrapper {
    fn write(&mut self, buf: &[u8]) -> IoResult<usize> {
        self.0.writer().write(buf)
    }

    fn flush(&mut self) -> IoResult<()> {
        self.0.writer().flush()
    }

    fn write_vectored(&mut self, bufs: &[IoSlice<'_>]) -> IoResult<usize> {
        self.0.writer().write_vectored(bufs)
    }
}

impl Stream for TlsWrapper {
    fn link_cert(&self) -> Option<&[u8]> {
        self.0.peer_certificates()?.first().map(|v| &v[..])
    }

    fn peer_addr(&self) -> &SocketAddr {
        &self.1
    }
}
