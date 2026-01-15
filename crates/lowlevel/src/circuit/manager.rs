use std::fmt::{Debug, Display};
use std::future::Future;
use std::pin::Pin;
use std::task::Poll::*;
use std::task::{Context, Poll};

use futures_channel::oneshot::{Receiver as OneshotReceiver, Sender as OneshotSender, channel};
use futures_core::stream::Stream;
use futures_sink::Sink;
use futures_util::{FutureExt as _, SinkExt as _, select_biased};
use pin_project::pin_project;
use tracing::{Span, debug, debug_span, error, info, instrument, trace, warn};

use super::controller::CircuitController;
use super::{CircuitInput, CircuitOutput, SenderState, StreamMap};
use crate::channel::NewCircuit;
use crate::errors;
use crate::runtime::{Runtime, SendError};
use crate::util::cell_map::NewHandler;
use crate::util::sans_io::event::{
    ChannelClosed, ChildCellMsg, ControlMsg, ParentCellMsg, Timeout,
};
use crate::util::{FutureRepollable, TimerManager};

pub type NewCircuitSender<ID, R, C, E> = OneshotSender<Result<NewCircuit<ID, R, C>, E>>;
type NewCircuitReceiver<ID, R, C, E> = OneshotReceiver<Result<NewCircuit<ID, R, C>, E>>;

#[pin_project(!Unpin)]
struct Circuit<C: CircuitController> {
    #[pin]
    handle: FutureRepollable<<C::Runtime as Runtime>::Task<bool>>,
    #[pin]
    send_ctrl: <C::Runtime as Runtime>::SPSCSender<C::ControlMsg>,
}

/// Circuit manager that only manages one channel.
///
/// Useful if you want to manage channels yourself.
#[pin_project(!Unpin)]
pub struct SingleManager<C: CircuitController> {
    #[pin]
    inner: Circuit<C>,
}

/// A reference to circuit.
pub struct CircuitRef<'a, C: CircuitController> {
    inner: Pin<&'a mut Circuit<C>>,
}

impl<C: CircuitController> SingleManager<C> {
    /// Create new circuit.
    ///
    /// # Parameters
    /// - `runtime` : Runtime used. Must be [`Clone`]-able.
    /// - `config` : Channel configuration.
    ///
    /// # Return
    /// Returns manager and [`NewCircuitSender`]. Sender must be fed new circuit data for circuit to function.
    #[allow(clippy::type_complexity)]
    pub fn new<E>(
        runtime: &C::Runtime,
        config: C::Config,
    ) -> (NewCircuitSender<C::CircID, C::Runtime, C::Cell, E>, Self)
    where
        E: 'static + Send + Debug + Display,
        C: 'static,
        C::Runtime: Clone,
    {
        let (sender, receiver) = runtime.spsc_make(1);
        let (send, recv) = channel();

        (
            send,
            Self {
                inner: Circuit {
                    handle: runtime
                        .spawn(handle_create_circuit::<C, E>(
                            runtime.clone(),
                            config,
                            receiver,
                            recv,
                        ))
                        .into(),
                    send_ctrl: sender,
                },
            },
        )
    }

    /// Create new circuit with initialized parameters.
    ///
    /// # Parameters
    /// - `runtime` : Runtime used. Must be [`Clone`]-able.
    /// - `config` : Channel configuration.
    /// - `linkver` : Link version.
    /// - `circ_id` : Circuit ID.
    /// - `send` : Cell sender.
    /// - `recv` : Cell receiver.
    #[inline(always)]
    pub fn with_params(
        runtime: &C::Runtime,
        config: C::Config,
        linkver: u16,
        circ_id: C::CircID,
        send: <C::Runtime as Runtime>::MPSCSender<C::Cell>,
        recv: <C::Runtime as Runtime>::SPSCReceiver<C::Cell>,
    ) -> Self
    where
        C: 'static,
        C::Runtime: Clone,
    {
        let (sender, receiver) = runtime.spsc_make(1);

        Self {
            inner: Circuit {
                handle: runtime
                    .spawn(handle_circuit::<C>(
                        runtime.clone(),
                        config,
                        receiver,
                        linkver,
                        circ_id,
                        send,
                        recv,
                    ))
                    .into(),
                send_ctrl: sender,
            },
        }
    }

    /// Gets [`CircuitRef`] to self.
    pub fn as_ref(self: Pin<&mut Self>) -> CircuitRef<'_, C> {
        CircuitRef {
            inner: self.project().inner,
        }
    }
}

impl<C: CircuitController> Circuit<C> {
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
                Err(_) => Err(if this.handle.as_mut().await {
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
        if self.project().handle.as_mut().await {
            Ok(())
        } else {
            Err(errors::HandleError)
        }
    }
}

impl<C: CircuitController> CircuitRef<'_, C> {
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
}

#[instrument(skip_all)]
async fn handle_create_circuit<
    C: 'static + CircuitController,
    E: 'static + Send + Debug + Display,
>(
    rt: C::Runtime,
    cfg: C::Config,
    ctrl_recv: <C::Runtime as Runtime>::SPSCReceiver<C::ControlMsg>,
    recv: NewCircuitReceiver<C::CircID, C::Runtime, C::Cell, E>,
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
            error!(error = %e, "error in circuit creation");
            return false;
        }
    };

    handle_circuit::<C>(rt, cfg, ctrl_recv, linkver, id, sender, receiver).await
}

#[instrument(skip_all, fields(%circ_id, linkver))]
async fn handle_circuit<C: 'static + CircuitController>(
    rt: C::Runtime,
    cfg: C::Config,
    ctrl_recv: <C::Runtime as Runtime>::SPSCReceiver<C::ControlMsg>,
    linkver: u16,
    circ_id: C::CircID,
    send: <C::Runtime as Runtime>::MPSCSender<C::Cell>,
    recv: <C::Runtime as Runtime>::SPSCReceiver<C::Cell>,
) -> bool {
    let stream_map = StreamMap::new(&rt, C::channel_cap(&cfg), C::channel_aggregate_cap(&cfg));
    let mut controller = C::new(&rt, cfg, circ_id);
    controller.set_linkver(linkver);

    CircuitFut {
        state: State::Steady {
            controller,
            timer: TimerManager::new(),
            ctrl_recv,
            stream_map,
            parent_cell_msg_pause: true,
            child_cell_msg_pause: true,
        },
        rt,
        send,
        recv,
        span: debug_span!("CircuitFut"),
    }
    .await
}

#[pin_project(!Unpin, project = StateProj)]
enum State<C: CircuitController> {
    Steady {
        controller: C,
        #[pin]
        timer: TimerManager<C::Runtime>,
        #[pin]
        ctrl_recv: <C::Runtime as Runtime>::SPSCReceiver<C::ControlMsg>,
        #[pin]
        stream_map: StreamMap<C::Runtime, C::StreamCell, C::StreamMeta>,
        parent_cell_msg_pause: bool,
        child_cell_msg_pause: bool,
    },
    SendDestroy {
        cell: Option<C::Cell>,
    },
    ErrorSendDestroy {
        cell: Option<C::Cell>,
    },
    Shutdown,
}

#[pin_project(!Unpin)]
struct CircuitFut<C: CircuitController> {
    rt: C::Runtime,
    #[pin]
    send: <C::Runtime as Runtime>::MPSCSender<C::Cell>,
    #[pin]
    recv: <C::Runtime as Runtime>::SPSCReceiver<C::Cell>,
    #[pin]
    state: State<C>,
    span: Span,
}

const FLAG_CTRLMSG: u8 = 1 << 0;
const FLAG_PARENTCELLMSG: u8 = 1 << 1;
const FLAG_CHILDCELLMSG: u8 = 1 << 2;
const FLAG_TIMEOUT: u8 = 1 << 3;
const FLAG_CELLMAP: u8 = 1 << 5;
const FLAG_EMPTY_HANDLE: u8 = 1 << 7;

impl<C: CircuitController> Future for CircuitFut<C> {
    type Output = bool;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let mut this = self.project();

        let mut pending = 0;
        let mut err: Option<C::Error> = None;
        let mut send_state = SenderState::Start;

        'main: loop {
            let _guard = this.span.enter();

            let (
                controller,
                mut timer,
                mut ctrl_recv,
                mut stream_map,
                parent_cell_msg_pause,
                child_cell_msg_pause,
            ) = match this.state.as_mut().project() {
                StateProj::Steady {
                    controller,
                    timer,
                    ctrl_recv,
                    stream_map,
                    parent_cell_msg_pause,
                    child_cell_msg_pause,
                } => (
                    controller,
                    timer,
                    ctrl_recv,
                    stream_map,
                    parent_cell_msg_pause,
                    child_cell_msg_pause,
                ),
                StateProj::SendDestroy { cell } => {
                    if poll_send_destroy(this.send.as_mut(), this.recv.as_mut(), cell, cx)
                        .is_ready()
                    {
                        this.state.set(State::Shutdown);
                        debug_assert!(err.is_none(), "error value is not None");
                        return Ready(true);
                    } else {
                        debug_assert!(err.is_none(), "error value is not None");
                        return Pending;
                    }
                }
                StateProj::ErrorSendDestroy { cell } => {
                    if poll_send_destroy(this.send.as_mut(), this.recv.as_mut(), cell, cx)
                        .is_ready()
                    {
                        this.state.set(State::Shutdown);
                        debug_assert!(err.is_none(), "error value is not None");
                        return Ready(false);
                    } else {
                        debug_assert!(err.is_none(), "error value is not None");
                        return Pending;
                    }
                }
                StateProj::Shutdown => {
                    debug_assert!(err.is_none(), "error value is not None");
                    return Ready(false);
                }
            };

            if let Some(e) = err.take() {
                error!(error = %&e, "circuit error");
                let cell = controller.make_destroy_cell(C::error_reason(e));
                this.state.set(State::ErrorSendDestroy { cell: Some(cell) });
                continue;
            }

            // Process controller
            let mut has_event = false;

            if pending & FLAG_TIMEOUT == 0 && timer.wants_poll() {
                pending |= FLAG_TIMEOUT;

                if timer.as_mut().poll(cx).is_ready() {
                    // Event: timeout
                    if let Err(e) = controller.handle(Timeout) {
                        err = Some(e);
                        continue;
                    }
                    has_event = true;
                }
            }

            if pending & FLAG_CTRLMSG == 0 {
                while let Ready(msg) = ctrl_recv.as_mut().poll_next(cx) {
                    let Some(msg) = msg else {
                        error!(
                            "shutting down: control channel disconnected (this might be a bug in circuit manager)"
                        );
                        this.state.set(State::Shutdown);
                        continue 'main;
                    };

                    // Event: control message
                    if let Err(e) = controller.handle(ControlMsg(msg)) {
                        err = Some(e);
                        continue 'main;
                    }
                    has_event = true;
                }

                pending |= FLAG_CTRLMSG;
            }

            let mut has_ready = false;
            if pending & FLAG_CELLMAP == 0 {
                stream_map.as_mut().retain(|&id, mut v| {
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

                if err.is_some() {
                    continue;
                }

                pending |= FLAG_CELLMAP;
            }

            if pending & FLAG_PARENTCELLMSG == 0 {
                while !*parent_cell_msg_pause {
                    let msg = match this.recv.as_mut().poll_next(cx) {
                        Pending => {
                            pending |= FLAG_PARENTCELLMSG;
                            break;
                        }
                        Ready(None) => {
                            warn!("shutting down: channel is disconnected, possibly closed");
                            return Ready(true);
                        }
                        Ready(Some(v)) => v,
                    };

                    // Event: parent cell message
                    *parent_cell_msg_pause = match controller.handle(ParentCellMsg(msg)) {
                        Ok(v) => v.0,
                        Err(e) => {
                            err = Some(e);
                            continue 'main;
                        }
                    };
                    has_event = true;
                    if *parent_cell_msg_pause {
                        debug!("pausing cell message receiving");
                    }
                }
            }

            if pending & FLAG_CHILDCELLMSG == 0 {
                while !*child_cell_msg_pause {
                    let msg = match stream_map.as_mut().poll_recv(cx) {
                        Pending => {
                            pending |= FLAG_CHILDCELLMSG;
                            break;
                        }
                        Ready(Some(v)) => v,
                        Ready(None) => {
                            error!(
                                "shutting down: circuit map aggregate receiver disconnected (this might be a bug in runtime)"
                            );
                            this.state.set(State::Shutdown);
                            continue 'main;
                        }
                    };

                    // Event: child cell message
                    *child_cell_msg_pause = match controller.handle(ChildCellMsg(msg)) {
                        Ok(v) => v.0,
                        Err(e) => {
                            err = Some(e);
                            continue 'main;
                        }
                    };
                    has_event = true;
                    if *child_cell_msg_pause {
                        debug!("pausing stream cell message receiving");
                    }
                }
            }

            if has_event || pending & FLAG_EMPTY_HANDLE == 0 {
                // Handle channel
                let mut is_any_close = false;
                let CircuitOutput {
                    shutdown,
                    timeout,
                    parent_cell_msg_pause: _parent_cell_msg_pause,
                    child_cell_msg_pause: _child_cell_msg_pause,
                } = match controller.handle((
                    &*this.rt,
                    CircuitInput::new(
                        this.rt.get_time(),
                        has_ready,
                        cx,
                        stream_map.as_mut(),
                        &mut is_any_close,
                        this.send.as_mut(),
                        &mut send_state,
                    ),
                )) {
                    Ok(v) => v,
                    Err(e) => {
                        err = Some(e);
                        continue;
                    }
                };

                if let Some(reason) = shutdown {
                    info!("controller requesting graceful shutdown");
                    let cell = controller.make_destroy_cell(reason);
                    this.state.set(State::SendDestroy { cell: Some(cell) });
                    continue;
                }

                if matches!(send_state, SenderState::Closed) {
                    error!("shutting down: channel is disconnected, possibly closed");
                    return Ready(true);
                }

                if let Some(time) = timeout {
                    debug!(timeout = ?time, "resetting timer");
                    timer.as_mut().set(this.rt, time);
                    pending &= !FLAG_TIMEOUT;
                } else {
                    debug!("clearing timer");
                    timer.as_mut().unset();
                }

                match (*parent_cell_msg_pause, _parent_cell_msg_pause) {
                    (true, false) => debug!("resuming cell message receiving"),
                    (false, true) => debug!("pausing cell message receiving"),
                    _ => (),
                }
                *parent_cell_msg_pause = _parent_cell_msg_pause;

                match (*child_cell_msg_pause, _child_cell_msg_pause) {
                    (true, false) => debug!("resuming stream cell message receiving"),
                    (false, true) => debug!("pausing stream cell message receiving"),
                    _ => (),
                }
                *child_cell_msg_pause = _child_cell_msg_pause;

                if is_any_close {
                    // Rescan close stream
                    pending &= !FLAG_CELLMAP;
                }
            }
            // Mark empty handle as true, because either timeout already fires or it has been handled previously.
            pending |= FLAG_EMPTY_HANDLE;

            let mut retry = false;
            if pending & FLAG_TIMEOUT == 0 && timer.wants_poll() {
                trace!("repolling: timer wants to be polled");
                retry = true;
            }
            if pending & FLAG_PARENTCELLMSG == 0 && !*parent_cell_msg_pause {
                trace!("repolling: cell aggregate channel wants to be polled");
                retry = true;
            }
            if pending & FLAG_CHILDCELLMSG == 0 && !*child_cell_msg_pause {
                trace!("repolling: stream cell aggregate channel wants to be polled");
                retry = true;
            }
            if pending & FLAG_CELLMAP == 0 {
                trace!("repolling: some stream(s) are closed");
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

#[instrument(level = "trace", skip_all, fields(has_cell = cell.is_some()), ret)]
fn poll_send_destroy<C, St: Stream<Item = C>, Si: Sink<C>>(
    mut send: Pin<&mut Si>,
    mut recv: Pin<&mut St>,
    cell: &mut Option<C>,
    cx: &mut Context<'_>,
) -> Poll<()> {
    let r = loop {
        let r = if cell.is_some() {
            send.as_mut().poll_ready(cx)
        } else {
            send.as_mut().poll_close(cx)
        };
        break match r {
            Pending => None,
            Ready(Err(e)) => Some(e),
            Ready(Ok(())) => match cell.take() {
                Some(c) => {
                    trace!("sending cell");
                    match send.as_mut().start_send(c) {
                        Ok(()) => continue,
                        Err(e) => Some(e),
                    }
                }
                None => None,
            },
        };
    };
    if r.is_some() {
        debug!("cannot send destroy cell, channel is closed");
        *cell = None;
    }
    drop(r);

    loop {
        match recv.as_mut().poll_next(cx) {
            Pending => break Pending,
            Ready(None) => break Ready(()),
            _ => (),
        }
    }
}
