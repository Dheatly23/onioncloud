//! Channel controller type.

use std::error::Error;
use std::io::Result as IoResult;
use std::net::SocketAddr;
use std::pin::Pin;
use std::task::Poll::*;
use std::task::{Context, Poll};

use onioncloud_runtime::{HasNetwork, HasTimer, Timer};
use pin_project::pin_project;
use tracing::{Span, info_span, instrument, trace};

use crate::handle::{ChannelHandle, HandleBuilder};
use crate::stream::Stream;

/// Channel controller.
#[pin_project(project = ChannelControllerProj)]
#[derive(Debug)]
#[must_use = "channel controller does nothing until polled"]
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
    #[allow(clippy::too_many_lines)]
    fn poll_inner(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        is_same_poll: bool,
    ) -> Poll<Result<(), impl Error + use<R, S, C>>> {
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
                .runtime(rt)
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

    /// Polls controller.
    ///
    /// Error type is intentionally opaque.
    #[inline]
    pub fn poll(
        self: Pin<&mut Self>,
        cx: &mut Context,
    ) -> Poll<Result<(), impl Error + use<R, S, C>>> {
        self.poll_inner(cx, false)
    }

    /// Polls controller in same polling cycle.
    ///
    /// Unlike [`Self::poll`], this one for optimization
    /// where controller is polled multiple times within the same async poll.
    /// If you're unsure, use [`Self::poll`] instead.
    #[inline]
    pub fn poll_same(
        self: Pin<&mut Self>,
        cx: &mut Context,
    ) -> Poll<Result<(), impl Error + use<R, S, C>>> {
        self.poll_inner(cx, true)
    }

    /// Gets reference to runtime.
    #[inline]
    pub fn runtime(&self) -> &R {
        &self.rt
    }
}

/// Builder for [`ChannelController`].
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
    /// Sets runtime.
    #[inline]
    pub fn runtime<R2: HasTimer>(self, rt: R2) -> ChannelControllerBuilder<R2, S, C> {
        ChannelControllerBuilder {
            rt,
            stream: self.stream,
            controller: self.controller,
        }
    }

    /// Sets stream.
    #[inline]
    pub fn stream<S2: Stream>(self, stream: S2) -> ChannelControllerBuilder<R, S2, C> {
        ChannelControllerBuilder {
            rt: self.rt,
            stream,
            controller: self.controller,
        }
    }

    /// Sets controller.
    #[inline]
    pub fn controller<C2>(self, controller: C2) -> ChannelControllerBuilder<R, S, C2> {
        ChannelControllerBuilder {
            rt: self.rt,
            stream: self.stream,
            controller,
        }
    }
}

impl<R: HasTimer, S: Stream, C: ChannelHandle<R>> ChannelControllerBuilder<R, S, C> {
    /// Builds [`ChannelController`].
    ///
    /// # Panics
    ///
    /// May panics if required fields aren't set.
    #[instrument(name = "ChannelControllerBuilder::build", skip_all)]
    #[inline]
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

#[inline]
pub async fn open<R: HasTimer + HasNetwork, S: Stream, C: ChannelHandle<R>>(
    rt: R,
    addrs: &[SocketAddr],
    stream: impl FnOnce(R::Socket) -> IoResult<S>,
    controller: impl FnOnce() -> C,
) -> IoResult<ChannelController<R, S, C>> {
    let s = rt.connect(addrs).await.and_then(stream)?;
    Ok(ChannelControllerBuilder::default()
        .runtime(rt)
        .stream(s)
        .controller(controller())
        .build())
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::fmt::{Debug, Display, Formatter, Result as FmtResult};
    use std::future::poll_fn;
    use std::io::Error as IoError;
    use std::pin::pin;
    use std::time::Duration;

    use anyhow::Error as AnyError;
    use futures_io::{AsyncRead, AsyncWrite};
    use onioncloud_runtime::Socket;
    use onioncloud_tart::rt::{Executor, Runtime};
    use test_log::test;
    use tracing::info;

    use crate::handle::{Handle, Return};
    use crate::stream::StreamNoTls;

    struct AnyErr(AnyError);

    impl Debug for AnyErr {
        fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
            Debug::fmt(&self.0, f)
        }
    }

    impl Display for AnyErr {
        fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
            Display::fmt(&self.0, f)
        }
    }

    impl Error for AnyErr {
        fn source(&self) -> Option<&(dyn Error + 'static)> {
            self.0.chain().next()
        }
    }

    impl From<IoError> for AnyErr {
        fn from(e: IoError) -> Self {
            Self(e.into())
        }
    }

    #[derive(Default)]
    struct AlwaysPending {
        close: bool,
    }

    impl AsyncRead for AlwaysPending {
        fn poll_read(
            self: Pin<&mut Self>,
            _: &mut Context<'_>,
            _: &mut [u8],
        ) -> Poll<IoResult<usize>> {
            if self.close { Ready(Ok(0)) } else { Pending }
        }
    }

    impl AsyncWrite for AlwaysPending {
        fn poll_write(
            self: Pin<&mut Self>,
            _: &mut Context<'_>,
            _: &[u8],
        ) -> Poll<IoResult<usize>> {
            if self.close { Ready(Ok(0)) } else { Pending }
        }

        fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<IoResult<()>> {
            Ready(Ok(()))
        }

        fn poll_close(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<IoResult<()>> {
            Pin::into_inner(self).close = true;
            Ready(Ok(()))
        }
    }

    impl Socket for AlwaysPending {
        fn peer_addr(&self) -> IoResult<SocketAddr> {
            Ok(SocketAddr::from(([127, 0, 0, 1], 9001)))
        }
    }

    #[test]
    #[instrument]
    fn test_controller() {
        struct Controller;

        impl ChannelHandle<Runtime> for Controller {
            type Error = AnyErr;

            #[instrument(skip_all)]
            fn handle(self: Pin<&mut Self>, args: Handle<Runtime>) -> Result<Return, Self::Error> {
                Ok(Return::new(&args).with_shutdown())
            }
        }

        let mut executor = Executor::builder().build();

        let rt = executor.runtime();
        rt.clone().spawn(async move {
            let mut cont = pin!(
                ChannelControllerBuilder::default()
                    .runtime(rt)
                    .stream(StreamNoTls::new(AlwaysPending::default()).unwrap())
                    .controller(Controller)
                    .build()
            );
            poll_fn(|cx| cont.as_mut().poll(cx)).await.unwrap();
        });

        executor.run();
    }

    #[test]
    #[instrument]
    fn test_controller_timer() {
        struct Controller;

        impl ChannelHandle<Runtime> for Controller {
            type Error = AnyErr;

            #[instrument(skip_all)]
            fn handle(self: Pin<&mut Self>, args: Handle<Runtime>) -> Result<Return, Self::Error> {
                let ret = Return::new(&args);
                info!("is timeout? {}", args.is_timeout());
                Ok(if args.is_timeout() {
                    ret.with_shutdown()
                } else {
                    ret.with_timeout(Some(args.time() + Duration::from_secs(60)))
                })
            }
        }

        let mut executor = Executor::builder().build();

        let rt = executor.runtime();
        rt.clone().spawn(async move {
            let mut cont = pin!(
                ChannelControllerBuilder::default()
                    .runtime(rt)
                    .stream(StreamNoTls::new(AlwaysPending::default()).unwrap())
                    .controller(Controller)
                    .build()
            );
            poll_fn(|cx| cont.as_mut().poll(cx)).await.unwrap();
        });

        executor.run();
    }
}
