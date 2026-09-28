//! Channel controller type.

use std::error::Error;
use std::pin::Pin;
use std::task::Poll::*;
use std::task::{Context, Poll};

use onioncloud_runtime::{HasTimer, Timer};
use pin_project::pin_project;
use tracing::{Span, info_span, instrument, trace};

use crate::handle::{ChannelHandle, HandleBuilder};
use crate::stream::Stream;

/// Channel controller.
#[pin_project(project = ChannelControllerProj)]
#[derive(Debug)]
pub struct ChannelController<R: HasTimer, S, C> {
    rt: R,
    #[pin]
    stream: S,
    #[pin]
    state: State<R::Timer, C>,
    span: Option<Span>,
}

#[pin_project(project = StateProj)]
#[derive(Debug)]
enum State<T, C> {
    Main {
        state: MainState,
        #[pin]
        timer: T,
        #[pin]
        controller: C,
    },
    Shutdown,
}

#[derive(Debug)]
enum MainState {
    Init,
    Main,
}

impl<R: HasTimer, S: Stream, C: ChannelHandle<R>> ChannelController<R, S, C> {
    pub fn poll_inner(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        is_same_poll: bool,
    ) -> Poll<Result<(), impl Error>> {
        let ChannelControllerProj {
            rt,
            mut stream,
            mut state,
            span,
        } = self.project();
        let _g = span
            .get_or_insert_with(|| info_span!("ChannelController::poll_inner"))
            .enter();

        if stream.as_mut().poll_inner(cx, is_same_poll)?.is_ready() {
            // Stream shut down.
            state.set(State::Shutdown);
            return Ready(Ok::<_, C::Error>(()));
        } else if stream.is_init() || matches!(&*state, State::Shutdown) {
            return Pending;
        }

        const FLAG_SAME_POLL: u8 = 1 << 0;
        const FLAG_TIMER: u8 = 1 << 1;
        const FLAG_EMPTY_HANDLE: u8 = 1 << 7;
        let mut flags = 0u8;
        if is_same_poll {
            flags |= FLAG_SAME_POLL;
        }

        match state.as_mut().project() {
            StateProj::Main {
                state,
                controller,
                timer,
            } => {
                if matches!(state, MainState::Init) {
                    *state = MainState::Main;
                    controller.set_peer_addr(stream.peer_addr())?;
                }

                let has_timeout = timer.get_timeout().is_some();
                if timer.poll(cx).is_ready() && has_timeout {
                    flags |= FLAG_TIMER;
                }
            }
            StateProj::Shutdown => return Pending,
        }

        loop {
            let (controller, mut timer) = match state.as_mut().project() {
                StateProj::Main {
                    controller, timer, ..
                } => (controller, timer),
                StateProj::Shutdown => {
                    return match stream.poll_inner(cx, true) {
                        Pending => Pending,
                        Ready(Ok(())) => Ready(Ok(())),
                        Ready(Err(e)) => Ready(Err(C::Error::from(e))),
                    };
                }
            };

            let mut has_event = false;
            let mut builder = HandleBuilder::default();
            builder
                .time(rt.current_time())
                .is_same_poll(flags & FLAG_SAME_POLL != 0)
                .is_timeout(flags & FLAG_TIMER != 0);
            flags &= !FLAG_TIMER;

            has_event |= stream.wants_poll() | (flags & FLAG_EMPTY_HANDLE == 0);
            let handle = builder.stream(stream.as_mut()).cx(cx).build();
            drop(builder);

            has_event |= handle.is_timeout();

            let mut repoll = false;
            if has_event {
                flags |= FLAG_EMPTY_HANDLE | FLAG_SAME_POLL;
                let ret = controller.handle(handle)?;

                if ret.is_shutdown {
                    trace!("controller request graceful shutdown");
                    state.set(State::Shutdown);
                    let _ = stream.as_mut().poll_close(cx)?;
                    continue;
                }

                if let Some(t) = ret.timeout {
                    if Some(t) != timer.get_timeout() {
                        timer.as_mut().set(t);

                        if timer.poll(cx).is_ready() {
                            flags |= FLAG_TIMER;

                            trace!("repolling: timer timeout");
                            repoll = true;
                        }
                    }
                } else if timer.get_timeout().is_some() {
                    trace!("clearing timer");
                    timer.reset();
                }
            }

            if stream.as_mut().poll_inner(cx, true)?.is_ready() {
                state.set(State::Shutdown);
                return Ready(Ok(()));
            }
            if stream.wants_poll() {
                trace!("repolling: stream has more data");
                repoll = true;
            }

            if !repoll {
                return Pending;
            }
        }
    }
}

#[derive(Debug)]
pub struct ChannelControllerBuilder<R, S, C> {
    rt: R,
    stream: S,
    controller: C,
}

impl Default for ChannelControllerBuilder<(), (), ()> {
    fn default() -> Self {
        Self {
            rt: (),
            stream: (),
            controller: (),
        }
    }
}

impl<R, S, C> ChannelControllerBuilder<R, S, C> {
    pub fn runtime<R2: HasTimer>(self, rt: R2) -> ChannelControllerBuilder<R2, S, C> {
        ChannelControllerBuilder {
            rt,
            stream: self.stream,
            controller: self.controller,
        }
    }

    pub fn stream<S2: Stream>(self, stream: S2) -> ChannelControllerBuilder<R, S2, C> {
        ChannelControllerBuilder {
            rt: self.rt,
            stream,
            controller: self.controller,
        }
    }

    pub fn controller<C2: ChannelHandle<R>>(
        self,
        controller: C2,
    ) -> ChannelControllerBuilder<R, S, C2> {
        ChannelControllerBuilder {
            rt: self.rt,
            stream: self.stream,
            controller,
        }
    }
}

impl<R: HasTimer, S: Stream, C: ChannelHandle<R>> ChannelControllerBuilder<R, S, C> {
    #[instrument(name = "ChannelControllerBuilder::build", skip_all)]
    pub fn build(self) -> ChannelController<R, S, C> {
        ChannelController {
            state: State::Main {
                state: MainState::Init,
                timer: self.rt.make_timer(None),
                controller: self.controller,
            },
            stream: self.stream,
            rt: self.rt,
            span: None,
        }
    }
}
