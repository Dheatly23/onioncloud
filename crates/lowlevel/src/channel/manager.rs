use std::future::Future;
use std::io::{Error as IoError, ErrorKind, IoSlice, IoSliceMut, Read, Result as IoResult, Write};
use std::net::SocketAddr;
use std::pin::Pin;
use std::task::Poll::*;
use std::task::{Context, Poll};

use futures_core::Stream as _;
use futures_sink::Sink;
use futures_util::{FutureExt as _, SinkExt as _, select_biased};
use pin_project::pin_project;
use rustls::Error as RustlsError;
use rustls::client::ClientConnection;
use scopeguard::guard;
use tracing::{Span, debug, debug_span, error, info, info_span, instrument, trace, warn};

use super::controller::ChannelController;
use super::{ChannelConfig, ChannelInput, CircMap, Stream};
use crate::crypto::tls::setup_client;
use crate::errors;
use crate::runtime::{Runtime, SendError, Stream as RTStream};
use crate::util::sans_io::event::{ChannelClosed, ChildCellMsg, ControlMsg, Timeout};
use crate::util::{
    AsyncReadWrapper, AsyncWriteWrapper, BytesBuffer, FutureRepollable, TimerManager, print_hex,
    print_list,
};

#[pin_project(!Unpin)]
struct Channel<C: ChannelController> {
    #[pin]
    handle: FutureRepollable<<C::Runtime as Runtime>::Task<bool>>,
    #[pin]
    send_ctrl: <C::Runtime as Runtime>::SPSCSender<C::ControlMsg>,
}

/// A reference to channel.
pub struct ChannelRef<'a, C: ChannelController> {
    inner: Pin<&'a mut Channel<C>>,
}

impl<C: ChannelController> Channel<C> {
    /// Send a control message.
    async fn send_control(
        self: Pin<&mut Self>,
        msg: C::ControlMsg,
    ) -> Result<(), errors::SendControlMsgError> {
        let mut this = self.project();

        select_biased! {
            res = this.handle.as_mut() => Err(if res {
                errors::SendControlMsgError::HandleFinalized
            } else {
                errors::HandleError.into()
            }),
            res = this.send_ctrl.send(msg).fuse() => match res {
                Err(_) => Err(if this.handle.await {
                    errors::SendControlMsgError::HandleFinalized
                } else {
                    errors::HandleError.into()
                }),
                Ok(_) => Ok(()),
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
        if self.project().handle.await {
            Ok(())
        } else {
            Err(errors::HandleError)
        }
    }
}

impl<C: ChannelController> ChannelRef<'_, C> {
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

    /// Poll for control message to be ready to send.
    ///
    /// See: [`Self::start_send_control`].
    pub fn poll_ready_control(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), SendError<C::ControlMsg>>> {
        self.inner.as_mut().project().send_ctrl.poll_flush(cx)
    }

    /// Queue control message for sending.
    ///
    /// Both this and [`Self::poll_ready_control`] can be used to manually implement [`Self::send_control`].
    ///
    /// **NOTE: Ensure [`Self::poll_ready_control`] return `Ready(Ok(()))` before calling this method.
    /// Failure to do so might cause panic or infinite loop.**
    ///
    /// After calling this, call [`Self::poll_ready_control`] to drive queue to completion and ensure message is sent.
    ///
    /// # Example
    ///
    /// ```
    /// # use std::future::poll_fn;
    /// # use onioncloud_lowlevel::channel::manager::ChannelRef;
    /// # use onioncloud_lowlevel::channel::controller::ChannelController;
    /// # use onioncloud_lowlevel::runtime::SendError;
    ///
    /// async fn manual_send<C: ChannelController>(mut channel: ChannelRef<'_, C>, msg: C::ControlMsg) -> Result<(), SendError<C::ControlMsg>> {
    ///     poll_fn(|cx| channel.poll_ready_control(cx)).await?;
    ///     channel.start_send_control(msg)?;
    ///     poll_fn(|cx| channel.poll_ready_control(cx)).await
    /// }
    /// ```
    pub fn start_send_control(
        &mut self,
        item: C::ControlMsg,
    ) -> Result<(), SendError<C::ControlMsg>> {
        self.inner.as_mut().project().send_ctrl.start_send(item)
    }

    /// Poll for controller completion.
    ///
    /// Basically the manual version of [`Self::completion`].
    pub fn poll_completion(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), errors::HandleError>> {
        match self.inner.as_mut().project().handle.poll(cx) {
            Pending => Pending,
            Ready(true) => Ready(Ok(())),
            Ready(false) => Ready(Err(errors::HandleError)),
        }
    }
}

/// Channel manager that only manages one channel.
///
/// Useful if you want to manage channels yourself.
#[pin_project(!Unpin)]
pub struct SingleManager<C: ChannelController> {
    #[pin]
    inner: Channel<C>,
}

impl<C: ChannelController> SingleManager<C> {
    /// Create new channel.
    ///
    /// # Parameters
    /// - `runtime` : Runtime used. Must be [`Clone`]-able.
    /// - `config` : Channel configuration.
    pub fn new(runtime: &C::Runtime, config: C::Config) -> Self
    where
        C: 'static,
        C::Runtime: Clone,
    {
        let (sender, receiver) = runtime.spsc_make(1);
        Self {
            inner: Channel {
                handle: runtime
                    .spawn(handle_channel::<
                        C,
                        StreamWrapper<<C::Runtime as Runtime>::Stream>,
                    >(runtime.clone(), config, receiver))
                    .into(),
                send_ctrl: sender,
            },
        }
    }

    /// Bind stream into channel.
    ///
    /// # Parameters
    /// - `runtime` : Runtime used. Must be [`Clone`]-able.
    /// - `stream` : Stream to be bound.
    /// - `config` : Channel configuration.
    pub fn with_stream(
        runtime: &C::Runtime,
        stream: <C::Runtime as Runtime>::Stream,
        config: C::Config,
    ) -> IoResult<Self>
    where
        C: 'static,
        C::Runtime: Clone,
    {
        let (sender, receiver) = runtime.spsc_make(0);
        let peer_addr = stream.peer_addr()?;

        Ok(Self {
            inner: Channel {
                handle: runtime
                    .spawn(handle_stream_outer::<
                        C,
                        StreamWrapper<<C::Runtime as Runtime>::Stream>,
                    >(
                        runtime.clone(), config, receiver, stream, peer_addr
                    ))
                    .into(),
                send_ctrl: sender,
            },
        })
    }

    /// Create new channel without TLS.
    ///
    /// Useful for testing.
    ///
    /// # Safety
    ///
    /// Even though there is nothing memory unsafe about it,
    /// nonetheless it's marked unsafe because it **bypass** essential cryptographic operation.
    /// Ensure that it's **only** used for local testing only.
    pub unsafe fn new_test(
        runtime: &C::Runtime,
        config: C::Config,
        link_cert: impl 'static + Send + FnOnce(&SocketAddr) -> Option<Box<[u8]>>,
    ) -> Self
    where
        C: 'static,
        C::Runtime: Clone,
    {
        let (sender, receiver) = runtime.spsc_make(1);
        Self {
            inner: Channel {
                handle: runtime
                    .spawn(handle_test_stream::<C>(
                        runtime.clone(),
                        config,
                        receiver,
                        link_cert,
                    ))
                    .into(),
                send_ctrl: sender,
            },
        }
    }

    /// Gets [`ChannelRef`] to self.
    pub fn as_ref(self: Pin<&mut Self>) -> ChannelRef<'_, C> {
        ChannelRef {
            inner: self.project().inner,
        }
    }

    /// Send a control message.
    #[inline(always)]
    pub async fn send_control(
        self: Pin<&mut Self>,
        msg: C::ControlMsg,
    ) -> Result<(), errors::SendControlMsgError> {
        self.project().inner.as_mut().send_control(msg).await
    }

    /// Send a control message and wait for completion.
    ///
    /// Useful for sending shutdown message.
    #[inline(always)]
    pub async fn send_and_completion(
        self: Pin<&mut Self>,
        msg: C::ControlMsg,
    ) -> Result<(), errors::HandleError> {
        self.project().inner.as_mut().send_and_completion(msg).await
    }

    /// Waits controller for completion.
    #[inline(always)]
    pub async fn completion(self: Pin<&mut Self>) -> Result<(), errors::HandleError> {
        self.project().inner.as_mut().completion().await
    }
}

#[instrument(skip_all, fields(peer_id = %print_hex(cfg.peer_id())))]
async fn handle_channel<
    C: ChannelController + 'static,
    S: StreamLike<Stream = <C::Runtime as Runtime>::Stream> + 'static,
>(
    rt: C::Runtime,
    cfg: C::Config,
    recv: <C::Runtime as Runtime>::SPSCReceiver<C::ControlMsg>,
) -> bool {
    let Some((stream, peer_addr)) = open_socket(&rt, &cfg).await else {
        return false;
    };

    let Some(stream) = S::new(stream, peer_addr) else {
        return false;
    };

    handle_stream::<C, S>(rt, cfg, recv, stream).await
}

#[instrument(skip_all, fields(peer_id = %print_hex(cfg.peer_id())))]
async fn handle_test_stream<C: ChannelController + 'static>(
    rt: C::Runtime,
    cfg: C::Config,
    recv: <C::Runtime as Runtime>::SPSCReceiver<C::ControlMsg>,
    link_cert: impl Send + FnOnce(&SocketAddr) -> Option<Box<[u8]>>,
) -> bool {
    let Some((stream, peer_addr)) = open_socket(&rt, &cfg).await else {
        return false;
    };

    let stream = TestStreamWrapper::new(stream, peer_addr, link_cert(&peer_addr));

    handle_stream::<C, _>(rt, cfg, recv, stream).await
}

#[instrument(skip_all)]
async fn open_socket<R: Runtime>(
    rt: &R,
    cfg: &impl ChannelConfig,
) -> Option<(R::Stream, SocketAddr)> {
    let stream = {
        let peer_addrs = cfg.peer_addrs();
        debug!(
            "connecting to peer at addresses: {}",
            print_list(&peer_addrs)
        );
        rt.connect(&peer_addrs[..]).await
    };
    let stream = match stream {
        Ok(v) => v,
        Err(e) => {
            error!(error = %e, "cannot connect to peer");
            return None;
        }
    };

    let peer_addr = match stream.peer_addr() {
        Ok(v) => v,
        Err(e) => {
            error!(error = %e, "cannot get peer address");
            return None;
        }
    };
    debug!("connected to peer at {peer_addr}");

    Some((stream, peer_addr))
}

async fn handle_stream_outer<
    C: ChannelController + 'static,
    S: StreamLike<Stream = <C::Runtime as Runtime>::Stream> + 'static,
>(
    rt: C::Runtime,
    cfg: C::Config,
    recv: <C::Runtime as Runtime>::SPSCReceiver<C::ControlMsg>,
    stream: <C::Runtime as Runtime>::Stream,
    peer_addr: SocketAddr,
) -> bool {
    let stream = {
        let _g = info_span!("handle_stream_outer", peer_id = %print_hex(cfg.peer_id())).entered();
        let Some(stream) = S::new(stream, peer_addr) else {
            return false;
        };
        stream
    };

    handle_stream::<C, S>(rt, cfg, recv, stream).await
}

#[instrument(skip_all)]
async fn handle_stream<
    C: ChannelController + 'static,
    S: StreamLike<Stream = <C::Runtime as Runtime>::Stream> + 'static,
>(
    rt: C::Runtime,
    cfg: C::Config,
    recv: <C::Runtime as Runtime>::SPSCReceiver<C::ControlMsg>,
    stream: S,
) -> bool {
    let fut = ChannelFut {
        state: State::Normal {
            timer: TimerManager::new(),
            ctrl_recv: recv,
            circ_map: CircMap::new(&rt, C::channel_cap(&cfg), C::channel_aggregate_cap(&cfg)),
            cell_msg_pause: true,
            controller: C::new(&rt, cfg),
        },
        rt,
        stream,
        span: debug_span!("ChannelFut"),
    };

    match fut.await {
        Ok(()) => true,
        Err(e) => {
            error!(error = %e, "channel error");
            false
        }
    }
}

#[pin_project(!Unpin, project = StateProj)]
enum State<C: ChannelController> {
    Normal {
        controller: C,
        #[pin]
        timer: TimerManager<C::Runtime>,
        #[pin]
        ctrl_recv: <C::Runtime as Runtime>::SPSCReceiver<C::ControlMsg>,
        #[pin]
        circ_map: CircMap<C::Runtime, C::Cell, C::CircMeta>,
        cell_msg_pause: bool,
    },
    ReqShutdown,
    TlsShutdown,
    Shutdown,
}

#[pin_project(!Unpin)]
struct ChannelFut<C: ChannelController, S: StreamLike> {
    rt: C::Runtime,
    #[pin]
    stream: S,
    #[pin]
    state: State<C>,
    span: Span,
}

const FLAG_READ: u8 = 1 << 0;
const FLAG_WRITE: u8 = 1 << 1;
const FLAG_TIMEOUT: u8 = 1 << 2;
const FLAG_CTRLMSG: u8 = 1 << 3;
const FLAG_FLUSH: u8 = 1 << 4;
const FLAG_CELLMSG: u8 = 1 << 5;
const FLAG_CELLMAP: u8 = 1 << 6;
const FLAG_EMPTY_HANDLE: u8 = 1 << 7;

impl<C: ChannelController, S: StreamLike> Future for ChannelFut<C, S> {
    type Output = Result<(), C::Error>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let mut this = self.project();
        let mut pending = 0u8;

        'main: loop {
            let _guard = this.span.enter();
            let state = this.state.as_mut().project();

            // Process shutdown
            match state {
                StateProj::Shutdown => return this.stream.poll_close(cx).map_err(|e| e.into()),
                StateProj::ReqShutdown => {
                    debug!("graceful shutdown request received");
                    this.stream.as_mut().send_close_notify();
                    this.state.set(State::TlsShutdown);
                    continue;
                }
                _ => (),
            }

            // Process TLS
            match this
                .stream
                .as_mut()
                .process(cx, matches!(state, StateProj::TlsShutdown), pending)
            {
                Ok(Pending) => return Pending,
                Ok(Ready(None)) => {
                    this.state.set(State::Shutdown);
                    continue;
                }
                Ok(Ready(Some(v))) => pending = v,
                Err(e) => {
                    this.state.set(State::Shutdown);
                    return Ready(Err(match e {
                        ErrorType::Io(e) => e.into(),
                        ErrorType::Tls(e) => e.into(),
                    }));
                }
            }

            // Process controller
            let StateProj::Normal {
                controller,
                mut timer,
                mut ctrl_recv,
                mut circ_map,
                cell_msg_pause,
            } = state
            else {
                unreachable!("all states should be handled")
            };
            let mut has_event = false;

            if pending & FLAG_TIMEOUT == 0 && timer.wants_poll() {
                pending |= FLAG_TIMEOUT;

                if timer.as_mut().poll(cx).is_ready() {
                    // Event: timeout
                    if let Err(e) = controller.handle(Timeout) {
                        this.state.set(State::Shutdown);
                        return Ready(Err(e));
                    }
                    has_event = true;
                }
            }

            if pending & FLAG_CTRLMSG == 0 {
                while let Ready(msg) = ctrl_recv.as_mut().poll_next(cx) {
                    let Some(msg) = msg else {
                        error!(
                            "shutting down: control channel disconnected (this might be a bug in channel manager)"
                        );
                        this.state.set(State::ReqShutdown);
                        continue 'main;
                    };

                    // Event: control message
                    if let Err(e) = controller.handle(ControlMsg(msg)) {
                        this.state.set(State::Shutdown);
                        return Ready(Err(e));
                    }
                    has_event = true;
                }

                pending |= FLAG_CTRLMSG;
            }

            let mut has_ready = false;
            if pending & FLAG_CELLMAP == 0 {
                let mut err = None;
                circ_map.as_mut().retain(|&id, mut v| {
                    if err.is_some() {
                        return true;
                    }

                    let cell = match v.as_mut().poll_ready(cx) {
                        Ready(Err(SendError(v))) => Some(v),
                        Ready(Ok(())) if !v.is_pollable() => None,
                        Ready(Ok(())) => {
                            has_ready = true;
                            return true;
                        }
                        Pending => return true,
                    };

                    // Event: channel closed
                    if let Err(e) = controller.handle(ChannelClosed {
                        id,
                        cell,
                        meta: v.meta(),
                    }) {
                        err = Some(e);
                    }
                    has_event = true;

                    false
                });

                if let Some(e) = err {
                    this.state.set(State::Shutdown);
                    return Ready(Err(e));
                }

                pending |= FLAG_CELLMAP;
            }

            if pending & FLAG_CELLMSG == 0 {
                while !*cell_msg_pause {
                    let msg = match circ_map.as_mut().poll_recv(cx) {
                        Pending => {
                            pending |= FLAG_CELLMSG;
                            break;
                        }
                        Ready(Some(v)) => v,
                        Ready(None) => {
                            error!(
                                "shutting down: circuit map aggregate receiver disconnected (this might be a bug in runtime)"
                            );
                            this.state.set(State::ReqShutdown);
                            continue 'main;
                        }
                    };

                    // Event: cell message
                    *cell_msg_pause = match controller.handle(ChildCellMsg(msg)) {
                        Ok(v) => v.0,
                        Err(e) => {
                            this.state.set(State::Shutdown);
                            return Ready(Err(e));
                        }
                    };
                    has_event = true;
                    if *cell_msg_pause {
                        debug!("pausing cell message receiving");
                    }
                }
            }

            if has_event || pending & FLAG_EMPTY_HANDLE == 0 {
                // Handle channel
                let mut is_any_close = false;
                let ret = match controller.handle((
                    &*this.rt,
                    ChannelInput::new(
                        this.stream.as_mut().as_stream(),
                        this.rt.get_time(),
                        has_ready,
                        cx,
                        circ_map.as_mut(),
                        &mut is_any_close,
                    ),
                )) {
                    Ok(v) => v,
                    Err(e) => {
                        this.state.set(State::Shutdown);
                        return Ready(Err(e));
                    }
                };

                if ret.shutdown {
                    info!("controller requesting graceful shutdown");
                    this.state.set(State::ReqShutdown);
                    continue;
                }

                if let Some(time) = ret.timeout {
                    debug!(timeout = ?time, "resetting timer");
                    timer.as_mut().set(this.rt, time);
                    pending &= !FLAG_TIMEOUT;
                } else {
                    debug!("clearing timer");
                    timer.as_mut().unset();
                }

                match (*cell_msg_pause, ret.cell_msg_pause) {
                    (true, false) => debug!("resuming cell message receiving"),
                    (false, true) => debug!("pausing cell message receiving"),
                    _ => (),
                }
                *cell_msg_pause = ret.cell_msg_pause;

                if is_any_close {
                    // Rescan close circuit
                    pending &= !FLAG_CELLMAP;
                }
            }
            // Mark empty handle as true, because either timeout already fires or it has been handled previously.
            pending |= FLAG_EMPTY_HANDLE;

            let mut retry = false;
            if pending & FLAG_READ == 0 && this.stream.wants_read() {
                trace!("repolling: TLS wants to read");
                pending &= !FLAG_EMPTY_HANDLE; // Make sure controller will handle
                retry = true;
            }
            if pending & FLAG_WRITE == 0 && this.stream.wants_write() {
                trace!("repolling: TLS wants to write");
                pending &= !FLAG_EMPTY_HANDLE; // Make sure controller will handle
                retry = true;
            }
            if pending & FLAG_TIMEOUT == 0 && timer.wants_poll() {
                trace!("repolling: timer wants to be polled");
                retry = true;
            }
            if pending & FLAG_CELLMSG == 0 && !*cell_msg_pause {
                trace!("repolling: cell aggregate channel wants to be polled");
                retry = true;
            }
            if pending & FLAG_CELLMAP == 0 {
                trace!("repolling: some circuit(s) are closed");
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

trait StreamLike: Sized {
    type Stream;

    fn new(stream: Self::Stream, addr: SocketAddr) -> Option<Self>;

    fn poll_close(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), IoError>>;

    fn send_close_notify(self: Pin<&mut Self>);

    fn process(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        is_shutdown: bool,
        pending: u8,
    ) -> Result<Poll<Option<u8>>, ErrorType>;

    fn as_stream(self: Pin<&mut Self>) -> &mut dyn Stream;

    fn wants_read(&self) -> bool;

    fn wants_write(&self) -> bool;
}

#[pin_project(!Unpin, project = StreamWrapperProj)]
struct StreamWrapper<S> {
    #[pin]
    stream: S,
    inner: InnerStreamWrapper,
}

struct InnerStreamWrapper {
    tls: ClientConnection,
    addr: SocketAddr,
}

impl<S: RTStream> StreamLike for StreamWrapper<S> {
    type Stream = S;

    fn new(stream: S, addr: SocketAddr) -> Option<Self> {
        match setup_client(addr.ip()) {
            Ok(tls) => Some(Self {
                stream,
                inner: InnerStreamWrapper { tls, addr },
            }),
            Err(e) => {
                error!(error = %e, "rustls setup");
                None
            }
        }
    }

    #[instrument(level = "debug", skip(self, cx))]
    fn poll_close(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), IoError>> {
        self.project().stream.poll_close(cx)
    }

    fn send_close_notify(self: Pin<&mut Self>) {
        self.project().inner.tls.send_close_notify();
    }

    #[instrument(level = "debug", skip(self, cx))]
    fn process(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        is_shutdown: bool,
        mut pending: u8,
    ) -> Result<Poll<Option<u8>>, ErrorType> {
        let StreamWrapperProj {
            mut stream,
            inner: InnerStreamWrapper { tls, .. },
        } = self.project();

        loop {
            if pending & FLAG_FLUSH == 0 && stream.as_mut().poll_flush(cx)?.is_pending() {
                pending |= FLAG_FLUSH;
            }

            let wants_write = pending & FLAG_WRITE == 0 && tls.wants_write();
            let wants_read = pending & FLAG_READ == 0 && tls.wants_read();
            if !(wants_write || wants_read) {
                break;
            }

            if wants_write {
                let mut wrapper = guard(AsyncWriteWrapper::new(cx, stream.as_mut()), |w| {
                    if w.finish() {
                        pending |= FLAG_WRITE;
                    }
                });

                while tls.wants_write() {
                    match tls.write_tls(&mut *wrapper) {
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
                let mut wrapper = guard(AsyncReadWrapper::new(cx, stream.as_mut()), |w| {
                    if w.finish() {
                        pending |= FLAG_READ;
                    }
                });

                while tls.wants_read() {
                    match tls.read_tls(&mut *wrapper) {
                        Ok(0) => {
                            // XXX: Read end is closed.
                            // We might have pending data to be written, but trying to handle it leads to infinite loop/pending.
                            // In the future, fix it?
                            info!("shutting down: read end connection closed");
                            return Ok(Ready(None));
                        }
                        Ok(_) => {
                            tls.process_new_packets()?;
                        }
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
        } else if tls.is_handshaking() || is_shutdown {
            if tls.is_handshaking() {
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

    fn as_stream(self: Pin<&mut Self>) -> &mut dyn Stream {
        self.project().inner
    }

    fn wants_read(&self) -> bool {
        self.inner.tls.wants_read()
    }

    fn wants_write(&self) -> bool {
        self.inner.tls.wants_write()
    }
}

impl Read for InnerStreamWrapper {
    fn read(&mut self, buf: &mut [u8]) -> IoResult<usize> {
        self.tls.reader().read(buf)
    }

    fn read_vectored(&mut self, bufs: &mut [IoSliceMut<'_>]) -> IoResult<usize> {
        self.tls.reader().read_vectored(bufs)
    }
}

impl Write for InnerStreamWrapper {
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

impl Stream for InnerStreamWrapper {
    fn link_cert(&self) -> Option<&[u8]> {
        self.tls.peer_certificates()?.first().map(|v| &v[..])
    }

    fn peer_addr(&self) -> &SocketAddr {
        &self.addr
    }
}

#[pin_project(!Unpin, project = TestStreamWrapperProj)]
struct TestStreamWrapper<S> {
    #[pin]
    stream: S,
    inner: Box<InnerTestStreamWrapper>,
}

impl<S> TestStreamWrapper<S> {
    fn new(stream: S, addr: SocketAddr, link_cert: Option<Box<[u8]>>) -> Self {
        Self {
            stream,
            inner: Box::new(InnerTestStreamWrapper {
                read_buf: Default::default(),
                write_buf: Default::default(),

                addr,
                link_cert,
            }),
        }
    }
}

impl<S: RTStream> StreamLike for TestStreamWrapper<S> {
    type Stream = S;

    fn new(_: S, _: SocketAddr) -> Option<Self> {
        error!("cannot create test stream with given parameters");
        None
    }

    #[instrument(level = "debug", skip(self, cx))]
    fn poll_close(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), IoError>> {
        self.project().stream.poll_close(cx)
    }

    fn send_close_notify(self: Pin<&mut Self>) {}

    #[instrument(level = "debug", skip(self, cx))]
    fn process(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        is_shutdown: bool,
        mut pending: u8,
    ) -> Result<Poll<Option<u8>>, ErrorType> {
        let TestStreamWrapperProj {
            mut stream, inner, ..
        } = self.project();

        if is_shutdown {
            loop {
                match inner.write_buf.socket_write(stream.as_mut(), cx)? {
                    Pending => return Ok(Pending),
                    Ready(0) => return Ok(Ready(None)),
                    Ready(_) => (),
                }
            }
        }

        while pending & FLAG_READ == 0 {
            if matches!(
                inner.read_buf.socket_read(stream.as_mut(), cx)?,
                Pending | Ready(0)
            ) {
                pending |= FLAG_READ;
            }
        }

        while pending & FLAG_WRITE == 0 {
            if matches!(
                inner.write_buf.socket_write(stream.as_mut(), cx)?,
                Pending | Ready(0)
            ) {
                pending |= FLAG_WRITE;
            }
        }

        Ok(Ready(Some(pending)))
    }

    fn as_stream(self: Pin<&mut Self>) -> &mut dyn Stream {
        &mut **self.project().inner
    }

    fn wants_read(&self) -> bool {
        !self.inner.read_buf.is_empty()
    }

    fn wants_write(&self) -> bool {
        !self.inner.write_buf.is_full() && !self.inner.write_buf.is_eof()
    }
}

struct InnerTestStreamWrapper {
    read_buf: BytesBuffer<1024>,
    write_buf: BytesBuffer<1024>,

    addr: SocketAddr,
    link_cert: Option<Box<[u8]>>,
}

impl Read for InnerTestStreamWrapper {
    fn read(&mut self, buf: &mut [u8]) -> IoResult<usize> {
        self.read_buf.read(buf)
    }

    fn read_vectored(&mut self, bufs: &mut [IoSliceMut<'_>]) -> IoResult<usize> {
        self.read_buf.read_vectored(bufs)
    }
}

impl Write for InnerTestStreamWrapper {
    fn write(&mut self, buf: &[u8]) -> IoResult<usize> {
        self.write_buf.write(buf)
    }

    fn flush(&mut self) -> IoResult<()> {
        self.write_buf.flush()
    }

    fn write_vectored(&mut self, bufs: &[IoSlice<'_>]) -> IoResult<usize> {
        self.write_buf.write_vectored(bufs)
    }
}

impl Stream for InnerTestStreamWrapper {
    fn link_cert(&self) -> Option<&[u8]> {
        self.link_cert.as_deref()
    }

    fn peer_addr(&self) -> &SocketAddr {
        &self.addr
    }
}
