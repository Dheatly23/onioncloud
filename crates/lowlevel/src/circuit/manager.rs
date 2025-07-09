use std::fmt::{Debug, Display};
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::task::Poll::*;
use std::task::{Context, Poll};
use std::time::Instant;

use flume::r#async::{RecvStream, SendFut};
use flume::{Receiver, SendError, Sender, bounded};
use futures_channel::oneshot::{Receiver as OneshotReceiver, Sender as OneshotSender, channel};
use futures_core::ready;
use futures_core::stream::Stream;
use futures_util::select_biased;
use pin_project::pin_project;
use tracing::{Instrument, Span, debug, debug_span, error, info, instrument, trace, warn};

use super::controller::CircuitController;
use super::{
    CellMsg, CheckedSender, CircuitInput, CircuitOutput, ControlMsg, StreamCellMsg, Timeout,
};
use crate::cell::destroy::DestroyReason;
use crate::channel::NewCircuit;
use crate::errors;
use crate::runtime::{Runtime, Timer};
use crate::util::FutureRepollable;
use crate::util::cell_map::{CellMap, NewHandler};

pub type NewCircuitSender<C, E> = OneshotSender<Result<NewCircuit<C>, E>>;
type NewCircuitReceiver<C, E> = OneshotReceiver<Result<NewCircuit<C>, E>>;

struct CircuitInner<C: CircuitController> {
    config: C::Config,
    sender: Sender<C::ControlMsg>,
    receiver: Receiver<C::ControlMsg>,
}

impl<C: CircuitController> AsRef<C::Config> for CircuitInner<C> {
    fn as_ref(&self) -> &C::Config {
        &self.config
    }
}

#[pin_project]
struct Circuit<R: Runtime, C: CircuitController, M> {
    #[pin]
    handle: FutureRepollable<R::Task<bool>>,
    inner: Arc<CircuitInner<C>>,
    #[pin]
    meta: M,
}

pub struct SingleManager<R: Runtime, C: CircuitController, M = ()> {
    runtime: R,
    inner: Pin<Box<Circuit<R, C, M>>>,
}

pub struct CircuitRef<'a, R: Runtime, C: CircuitController, M> {
    runtime: &'a mut R,
    inner: Pin<&'a mut Circuit<R, C, M>>,
}

impl<R: Runtime, C: CircuitController, M> SingleManager<R, C, M> {
    pub fn new<E>(runtime: R, config: C::Config, meta: M) -> (NewCircuitSender<C::Cell, E>, Self)
    where
        E: 'static + Send + Debug + Display,
        R: 'static + Clone,
        C: 'static,
    {
        let (sender, receiver) = bounded(0);
        let inner = Arc::new(CircuitInner {
            config,
            sender,
            receiver,
        });
        let (send, recv) = channel();

        (
            send,
            Self {
                inner: Box::pin(Circuit {
                    handle: spawn(&runtime, inner.clone(), recv).into(),
                    inner,
                    meta,
                }),
                runtime,
            },
        )
    }

    pub fn into_ref(&mut self) -> CircuitRef<'_, R, C, M> {
        CircuitRef {
            runtime: &mut self.runtime,
            inner: self.inner.as_mut(),
        }
    }
}

impl<R: Runtime, C: CircuitController, M> Circuit<R, C, M> {
    /// Gets reference to circuit metadata.
    fn meta(self: Pin<&mut Self>) -> Pin<&mut M> {
        self.project().meta
    }

    /// Gets reference to circuit configuration.
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
    pub fn restart<E>(self: Pin<&mut Self>, r: &R) -> Option<NewCircuitSender<C::Cell, E>>
    where
        E: 'static + Send + Debug + Display,
        R: 'static + Clone,
        C: 'static,
    {
        let mut this = self.project();

        if !this.handle.is_finished() {
            return None;
        }

        let (send, recv) = channel();
        this.handle
            .as_mut()
            .set(spawn(r, this.inner.clone(), recv).into());
        Some(send)
    }

    /// Restarts controller if stopped (with attached cell sender/receiver).
    pub fn restart_with(
        self: Pin<&mut Self>,
        r: &R,
        linkver: u16,
        send: CheckedSender<C::Cell>,
        recv: Receiver<C::Cell>,
    ) -> bool
    where
        R: 'static + Clone,
        C: 'static,
    {
        let mut this = self.project();

        if !this.handle.is_finished() {
            return false;
        }

        this.handle
            .as_mut()
            .set(spawn_with(r, this.inner.clone(), linkver, send, recv).into());
        true
    }
}

impl<R: Runtime, C: CircuitController, M> CircuitRef<'_, R, C, M> {
    /// Gets reference to circuit metadata.
    #[inline(always)]
    pub fn meta(&mut self) -> Pin<&mut M> {
        self.inner.as_mut().meta()
    }

    /// Gets reference to circuit configuration.
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
    pub fn restart<E>(&mut self) -> Option<NewCircuitSender<C::Cell, E>>
    where
        E: 'static + Send + Debug + Display,
        R: 'static + Clone,
        C: 'static,
    {
        self.inner.as_mut().restart(self.runtime)
    }

    /// Restarts controller if stopped (with attached cell sender/receiver).
    #[inline(always)]
    pub fn restart_with(
        &mut self,
        linkver: u16,
        send: CheckedSender<C::Cell>,
        recv: Receiver<C::Cell>,
    ) -> bool
    where
        R: 'static + Clone,
        C: 'static,
    {
        self.inner
            .as_mut()
            .restart_with(self.runtime, linkver, send, recv)
    }
}

fn spawn<
    R: 'static + Runtime + Clone,
    C: 'static + CircuitController,
    E: 'static + Send + Debug + Display,
>(
    runtime: &R,
    config: Arc<CircuitInner<C>>,
    recv: NewCircuitReceiver<C::Cell, E>,
) -> R::Task<bool> {
    runtime.spawn(handle_create_circuit(runtime.clone(), config, recv))
}

fn spawn_with<R: 'static + Runtime + Clone, C: 'static + CircuitController>(
    runtime: &R,
    config: Arc<CircuitInner<C>>,
    linkver: u16,
    send: CheckedSender<C::Cell>,
    recv: Receiver<C::Cell>,
) -> R::Task<bool> {
    runtime.spawn(handle_circuit(runtime.clone(), config, linkver, send, recv))
}

#[instrument(skip_all, fields(config = %cfg.config))]
async fn handle_create_circuit<
    R: Runtime,
    C: 'static + CircuitController,
    E: 'static + Send + Debug + Display,
>(
    rt: R,
    cfg: Arc<CircuitInner<C>>,
    recv: NewCircuitReceiver<C::Cell, E>,
) -> bool {
    let NewCircuit {
        inner: NewHandler {
            id,
            sender,
            receiver,
        },
        linkver,
    } = match recv.await {
        Ok(Ok(v)) => v,
        Err(_) => {
            error!("circuit creation cancelled");
            return false;
        }
        Ok(Err(e)) => {
            error!(error = display(e), "error in circuit creation");
            return false;
        }
    };

    handle_circuit(rt, cfg, linkver, CheckedSender::new(id, sender), receiver).await
}

#[instrument(skip_all, fields(circ_id = send.id()))]
async fn handle_circuit<R: Runtime, C: 'static + CircuitController>(
    rt: R,
    cfg: Arc<CircuitInner<C>>,
    linkver: u16,
    send: CheckedSender<C::Cell>,
    recv: Receiver<C::Cell>,
) -> bool {
    // SAFETY: Destroy cell has been checked
    let sender = unsafe { send.inner_sender().clone() };

    let ctrl_recv = cfg.receiver.clone().into_stream();
    let stream_map = CellMap::new(
        C::channel_cap(&cfg.config),
        C::channel_aggregate_cap(&cfg.config),
    );
    let mut controller = C::new(cfg, send.id());
    controller.set_linkver(linkver);

    let fut = CircuitFutSteady {
        runtime: rt,
        ctrl_recv,
        stream_map,
        controller: &mut controller,
        send,
        recv: recv.stream(),
        timer: None,
        timer_finished: false,
        cell_msg_pause: true,
        stream_cell_msg_pause: true,
        span: debug_span!("CircuitFutSteady"),
    };

    let (reason, ret) = match fut.await {
        Ok(Some(reason)) => (reason, true),
        Ok(None) => return false,
        Err(e) => {
            error!(error = display(&e), "circuit error");
            (C::error_reason(e), false)
        }
    };
    // Hopefully fut is dropped at this point

    let cell = controller.make_destroy_cell(reason);
    drop(controller);

    CircuitFutDestroy {
        recv: recv.into_stream(),
        fut: Some(sender.into_send_async(cell)),
    }
    .instrument(debug_span!("CircuitFutDestroy"))
    .await;
    ret
}

#[pin_project]
struct CircuitFutSteady<'a, R: Runtime, C: CircuitController> {
    runtime: R,
    controller: &'a mut C,
    #[pin]
    ctrl_recv: RecvStream<'a, C::ControlMsg>,
    stream_map: CellMap<C::Cell, C::StreamMeta>,
    send: CheckedSender<C::Cell>,
    #[pin]
    recv: RecvStream<'a, C::Cell>,
    #[pin]
    timer: Option<R::Timer>,
    timer_finished: bool,
    cell_msg_pause: bool,
    stream_cell_msg_pause: bool,
    span: Span,
}

const FLAG_CTRLMSG: u8 = 1 << 0;
const FLAG_CELLMSG: u8 = 1 << 1;
const FLAG_STREAMCELLMSG: u8 = 1 << 2;
const FLAG_TIMEOUT: u8 = 1 << 3;
const FLAG_EMPTY_HANDLE: u8 = 1 << 7;

impl<R: Runtime, C: CircuitController> Future for CircuitFutSteady<'_, R, C> {
    type Output = Result<Option<DestroyReason>, C::Error>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let mut this = self.project();

        let mut pending = 0;

        loop {
            let _guard = this.span.enter();

            // Process controller
            let mut has_event = false;

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
                    this.controller.handle(Timeout)?;
                    has_event = true;
                }
            }

            if pending & FLAG_CTRLMSG == 0 {
                while let Ready(msg) = this.ctrl_recv.as_mut().poll_next(cx) {
                    let Some(msg) = msg else {
                        error!(
                            "shutting down: control channel disconnected (this might be a bug in circuit manager)"
                        );
                        return Ready(Ok(None));
                    };

                    // Event: control message
                    this.controller.handle(ControlMsg(msg))?;
                    has_event = true;
                }

                pending |= FLAG_CTRLMSG;
            }

            if pending & FLAG_CELLMSG == 0 {
                while !*this.cell_msg_pause {
                    let msg = match this.recv.as_mut().poll_next(cx) {
                        Pending => {
                            pending |= FLAG_CELLMSG;
                            break;
                        }
                        Ready(None) => {
                            warn!("shutting down: channel is disconnected, possibly closed");
                            return Ready(Ok(None));
                        }
                        Ready(Some(v)) => v,
                    };

                    // Event: cell message
                    *this.cell_msg_pause = this.controller.handle(CellMsg(msg))?.0;
                    has_event = true;
                    if *this.cell_msg_pause {
                        debug!("pausing cell message receiving");
                    }
                }
            }

            if pending & FLAG_STREAMCELLMSG == 0 {
                while !*this.stream_cell_msg_pause {
                    let Ready(msg) = this.stream_map.poll_recv(cx) else {
                        pending |= FLAG_STREAMCELLMSG;
                        break;
                    };

                    // Event: stream cell message
                    *this.stream_cell_msg_pause = this
                        .controller
                        .handle(StreamCellMsg(
                            msg.expect("stream map aggregate receiver should never close"),
                        ))?
                        .0;
                    has_event = true;
                    if *this.stream_cell_msg_pause {
                        debug!("pausing stream cell message receiving");
                    }
                }
            }

            if has_event || pending & FLAG_EMPTY_HANDLE == 0 {
                // Handle channel
                let CircuitOutput {
                    shutdown,
                    timeout,
                    cell_msg_pause,
                    stream_cell_msg_pause,
                } = this.controller.handle((
                    CircuitInput::new(Instant::now(), this.send),
                    &mut *this.stream_map,
                ))?;

                if let Some(reason) = shutdown {
                    info!("controller requesting graceful shutdown");
                    return Ready(Ok(Some(reason)));
                }

                if let Some(t) = timeout {
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

                match (*this.cell_msg_pause, cell_msg_pause) {
                    (true, false) => debug!("resuming cell message receiving"),
                    (false, true) => debug!("pausing cell message receiving"),
                    _ => (),
                }
                *this.cell_msg_pause = cell_msg_pause;

                match (*this.stream_cell_msg_pause, stream_cell_msg_pause) {
                    (true, false) => debug!("resuming stream cell message receiving"),
                    (false, true) => debug!("pausing stream cell message receiving"),
                    _ => (),
                }
                *this.stream_cell_msg_pause = stream_cell_msg_pause;
            }
            // Mark empty handle as true, because either timeout already fires or it has been handled previously.
            pending |= FLAG_EMPTY_HANDLE;

            let mut retry = false;
            if pending & FLAG_TIMEOUT == 0 && !*this.timer_finished && this.timer.is_some() {
                trace!("repolling: timer wants to be polled");
                retry = true;
            }
            if pending & FLAG_CELLMSG == 0 && !*this.cell_msg_pause {
                trace!("repolling: cell aggregate channel wants to be polled");
                retry = true;
            }
            if pending & FLAG_STREAMCELLMSG == 0 && !*this.stream_cell_msg_pause {
                trace!("repolling: stream cell aggregate channel wants to be polled");
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

#[pin_project]
struct CircuitFutDestroy<'a, Cell> {
    #[pin]
    fut: Option<SendFut<'a, Cell>>,
    #[pin]
    recv: RecvStream<'a, Cell>,
}

impl<Cell> Future for CircuitFutDestroy<'_, Cell> {
    type Output = ();

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let mut this = self.project();

        let p1 = match this.fut.as_mut().as_pin_mut() {
            Some(f) => f.poll(cx),
            None => Ready(Ok(())),
        };
        let p2 = poll_until_closed(this.recv.as_mut(), cx);

        match ready!(p1) {
            Ok(()) => this.fut.set(None),
            Err(SendError(_)) => debug!("cannot send destroy cell, channel is closed"),
        }
        p2
    }
}

fn poll_until_closed<T>(mut recv: Pin<&mut RecvStream<'_, T>>, cx: &mut Context<'_>) -> Poll<()> {
    while ready!(recv.as_mut().poll_next(cx)).is_some() {}
    Ready(())
}
