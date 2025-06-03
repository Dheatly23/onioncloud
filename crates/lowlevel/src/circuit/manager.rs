use std::fmt::{Debug, Display};
use std::future::Future;
use std::num::NonZeroU32;
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
use tracing::{Span, debug, debug_span, error, info, instrument, trace, warn};

use super::controller::CircuitController;
use super::{CellMsg, CircuitInput, CircuitOutput, ControlMsg, Timeout};
use crate::channel::NewCircuit;
use crate::errors;
use crate::runtime::{Runtime, Timer};
use crate::util::FutureRepollable;

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
    runtime.spawn(handle_circuit(runtime.clone(), config, recv))
}

#[instrument(skip_all, fields(config = %cfg.config))]
async fn handle_circuit<
    R: Runtime,
    C: 'static + CircuitController,
    E: 'static + Send + Debug + Display,
>(
    rt: R,
    cfg: Arc<CircuitInner<C>>,
    recv: NewCircuitReceiver<C::Cell, E>,
) -> bool {
    let NewCircuit {
        id,
        sender,
        receiver,
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

    let fut = CircuitFut {
        id,
        send: sender,
        recv: receiver.into_stream(),
        runtime: rt,
        ctrl_recv: cfg.receiver.clone().into_stream(),
        state: State::Steady(C::new(cfg, id)),
        timer: None,
        timer_finished: false,
        cell_msg_pause: false,
        span: debug_span!("CircuitFut"),
    };

    match fut.await {
        Ok(()) => true,
        Err(e) => {
            error!(error = display(e), "circuit error");
            false
        }
    }
}

#[pin_project]
struct CircuitFut<R: Runtime, C: CircuitController> {
    id: NonZeroU32,
    runtime: R,
    #[pin]
    state: State<C>,
    #[pin]
    ctrl_recv: RecvStream<'static, C::ControlMsg>,
    send: Sender<C::Cell>,
    #[pin]
    recv: RecvStream<'static, C::Cell>,
    #[pin]
    timer: Option<R::Timer>,
    timer_finished: bool,
    cell_msg_pause: bool,
    span: Span,
}

#[pin_project(project = StateProj)]
enum State<C: CircuitController> {
    Steady(C),
    DestroySend(#[pin] SendFut<'static, C::Cell>),
    DestroyWait,
    ErrShutdown,
}

impl<R: Runtime, C: CircuitController> Future for CircuitFut<R, C> {
    type Output = Result<(), C::Error>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let mut this = self.project();

        const FLAG_CTRLMSG: u8 = 1 << 0;
        const FLAG_CELLMSG: u8 = 1 << 1;
        const FLAG_TIMEOUT: u8 = 1 << 2;
        const FLAG_EMPTY_HANDLE: u8 = 1 << 7;

        let mut pending = 0;

        'main: loop {
            let _guard = this.span.enter();

            let c = match this.state.as_mut().project() {
                StateProj::Steady(c) => c,
                StateProj::DestroySend(fut) => {
                    this.timer.set(None);

                    let p1 = fut.poll(cx);
                    // Poll result does not matter
                    let _ = poll_until_closed(this.recv.as_mut(), cx);

                    match ready!(p1) {
                        Ok(()) => (),
                        Err(SendError(_)) => {
                            debug!("cannot send destroy cell, channel is closed")
                        }
                    }

                    this.state.set(State::DestroyWait);
                    continue;
                }
                StateProj::DestroyWait => {
                    ready!(poll_until_closed(this.recv, cx));
                    return Ready(Ok(()));
                }
                StateProj::ErrShutdown => return Ready(Ok(())),
            };

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
                    match c.handle(Timeout) {
                        Ok(()) => (),
                        Err(e) => {
                            this.state.set(State::ErrShutdown);
                            return Ready(Err(e));
                        }
                    }
                    has_event = true;
                }
            }

            if pending & FLAG_CTRLMSG == 0 {
                while let Ready(msg) = this.ctrl_recv.as_mut().poll_next(cx) {
                    let Some(msg) = msg else {
                        error!(
                            "shutting down: control channel disconnected (this might be a bug in circuit manager)"
                        );
                        this.state.set(State::ErrShutdown);
                        continue 'main;
                    };

                    // Event: control message
                    match c.handle(ControlMsg(msg)) {
                        Ok(()) => (),
                        Err(e) => {
                            this.state.set(State::ErrShutdown);
                            return Ready(Err(e));
                        }
                    }
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
                            warn!("channel is disconnected, possibly closed");
                            this.state.set(State::ErrShutdown);
                            continue 'main;
                        }
                        Ready(Some(v)) => v,
                    };

                    // Event: cell message
                    *this.cell_msg_pause = match c.handle(CellMsg(msg)) {
                        Ok(v) => v.0,
                        Err(e) => {
                            this.state.set(State::ErrShutdown);
                            return Ready(Err(e));
                        }
                    };
                    has_event = true;
                    if *this.cell_msg_pause {
                        debug!("pausing cell message receiving");
                    }
                }
            }

            if has_event || pending & FLAG_EMPTY_HANDLE == 0 {
                let mut is_closed = false;
                // Handle channel
                let CircuitOutput {
                    shutdown,
                    timeout,
                    cell_msg_pause,
                    ..
                } = match c.handle(CircuitInput::new(
                    *this.id,
                    Instant::now(),
                    &mut is_closed,
                    this.send,
                )) {
                    Ok(v) => v,
                    Err(e) => {
                        this.state.set(State::ErrShutdown);
                        return Ready(Err(e));
                    }
                };

                if let Some(cell) = shutdown {
                    info!("controller requesting graceful shutdown");
                    this.state
                        .set(State::DestroySend(this.send.clone().into_send_async(cell)));
                    continue;
                } else if is_closed {
                    warn!("channel is disconnected, possibly closed");
                    this.state.set(State::ErrShutdown);
                    continue;
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

            if !retry {
                trace!("all futures are pending");
                // All futures are pending.
                return Pending;
            }
        }
    }
}

fn poll_until_closed<T>(mut recv: Pin<&mut RecvStream<'_, T>>, cx: &mut Context<'_>) -> Poll<()> {
    while ready!(recv.as_mut().poll_next(cx)).is_some() {}
    Ready(())
}
