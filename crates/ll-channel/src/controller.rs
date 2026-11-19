//! Channel controller type.

use std::future::Future;
use std::io::Result as IoResult;
use std::net::SocketAddr;
use std::pin::Pin;
use std::task::Poll::{Pending, Ready};
use std::task::{Context, Poll};

use onioncloud_runtime::{HasNetwork, HasTimer, Timer as _};
use pin_project::pin_project;
use tracing::{Span, info_span, instrument, trace};

use crate::handle::{ChannelHandle, HandleBuilder, ShutdownCause, ShutdownHandleBuilder};
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
    GracefulShutdown,
}

impl<R: HasTimer, S: Stream, C: ChannelHandle<R>> ChannelController<R, S, C> {
    #[expect(clippy::too_many_lines, clippy::items_after_statements)]
    fn poll_inner2(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        is_same_poll: bool,
    ) -> Poll<Result<(), C::Error>> {
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
            if let StateProj::Main {
                controller, state, ..
            } = state.as_mut().project()
            {
                let mut builder = ShutdownHandleBuilder::default();
                builder
                    .cx(cx)
                    .runtime(rt)
                    .time(rt.current_time())
                    .cause(match state {
                        MainState::Init | MainState::Main => ShutdownCause::SocketClosed,
                        MainState::GracefulShutdown => ShutdownCause::GracefulShutdown,
                    });
                let handle = builder.build();
                drop(builder);
                controller.shutdown(handle);
            }
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
            StateProj::Main { state, timer, .. } => {
                if matches!(state, MainState::Init) {
                    *state = MainState::Main;
                }

                let has_timeout = timer.get_timeout().is_some();
                if timer.poll(cx).is_ready() && has_timeout {
                    flags |= FLAG_TIMER;
                }
            }
            StateProj::Shutdown => return Pending,
        }

        loop {
            let (mut controller, mut timer, inner_state) = match state.as_mut().project() {
                StateProj::Shutdown => return Ready(Ok(())),
                StateProj::Main {
                    controller,
                    state: MainState::GracefulShutdown,
                    ..
                } => match stream.poll_inner(cx, true) {
                    Pending => return Pending,
                    Ready(Ok(())) => {
                        let mut builder = ShutdownHandleBuilder::default();
                        builder
                            .cx(cx)
                            .runtime(rt)
                            .time(rt.current_time())
                            .cause(ShutdownCause::GracefulShutdown);
                        let handle = builder.build();
                        drop(builder);
                        controller.shutdown(handle);

                        state.set(State::Shutdown);
                        return Ready(Ok(()));
                    }
                    Ready(Err(e)) => return Ready(Err(C::Error::from(e))),
                },
                StateProj::Main {
                    controller,
                    timer,
                    state,
                } => (controller, timer, state),
            };

            let mut has_event = false;
            let mut builder = HandleBuilder::default();
            builder
                .runtime(rt)
                .time(rt.current_time())
                .is_same_poll(flags & FLAG_SAME_POLL != 0)
                .is_timeout(flags & FLAG_TIMER != 0);
            flags &= !FLAG_TIMER;

            has_event |= stream.wants_poll() || (flags & FLAG_EMPTY_HANDLE == 0);
            let handle = builder.stream(stream.as_mut()).cx(cx).build();
            drop(builder);

            has_event |= handle.is_timeout();

            let mut repoll = false;
            if has_event {
                flags |= FLAG_EMPTY_HANDLE | FLAG_SAME_POLL;
                let ret = controller.as_mut().handle(handle)?;

                if ret.is_shutdown {
                    trace!("controller request graceful shutdown");
                    *inner_state = MainState::GracefulShutdown;
                    stream.as_mut().request_shutdown();
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

            if stream.wants_poll() {
                trace!("repolling: stream has more data");
                flags &= !FLAG_EMPTY_HANDLE;
                repoll = true;

                if stream.as_mut().poll_inner(cx, true)?.is_ready() {
                    let mut builder = ShutdownHandleBuilder::default();
                    builder
                        .cx(cx)
                        .runtime(rt)
                        .time(rt.current_time())
                        .cause(ShutdownCause::SocketClosed);
                    let handle = builder.build();
                    drop(builder);
                    controller.shutdown(handle);

                    state.set(State::Shutdown);
                    return Ready(Ok(()));
                }
            }

            if !repoll {
                return Pending;
            }
        }
    }

    fn poll_inner(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        is_same_poll: bool,
    ) -> Poll<Result<(), C::Error>> {
        let ret = self.as_mut().poll_inner2(cx, is_same_poll);

        if let Ready(Err(e)) = &ret
            && let ChannelControllerProj {
                rt,
                mut state,
                span: Some(span),
                ..
            } = self.project()
            && let StateProj::Main { controller, .. } = state.as_mut().project()
        {
            let _g = span.enter();

            let mut builder = ShutdownHandleBuilder::default();
            builder
                .cx(cx)
                .runtime(rt)
                .time(rt.current_time())
                .cause(ShutdownCause::Error(e));
            let handle = builder.build();
            drop(builder);
            controller.shutdown(handle);

            state.set(State::Shutdown);
        }

        ret
    }

    /// Polls controller in same polling cycle.
    ///
    /// Unlike [`Self::poll`], this one for optimization
    /// where controller is polled multiple times within the same async poll.
    /// If you're unsure, use [`Self::poll`] instead.
    #[inline]
    pub fn poll_same(self: Pin<&mut Self>, cx: &mut Context) -> Poll<Result<(), C::Error>> {
        self.poll_inner(cx, true)
    }
}

impl<R: HasTimer, S, C> ChannelController<R, S, C> {
    /// Gets reference to runtime.
    #[inline]
    #[must_use]
    pub fn runtime(&self) -> &R {
        &self.rt
    }

    /// Gets reference to stream.
    #[inline]
    #[must_use]
    pub fn stream(&self) -> &S {
        &self.stream
    }

    /// Gets reference to controller.
    #[inline]
    #[must_use]
    pub fn controller(&self) -> Option<&C> {
        match &self.state {
            State::Main { controller: c, .. } => Some(c),
            State::Shutdown => None,
        }
    }

    /// Gets mutable reference to controller.
    #[inline]
    #[must_use]
    pub fn controller_mut(self: Pin<&mut Self>) -> Option<Pin<&mut C>> {
        match self.project().state.project() {
            StateProj::Main { controller: c, .. } => Some(c),
            StateProj::Shutdown => None,
        }
    }
}

impl<R: HasTimer, S: Stream, C: ChannelHandle<R>> Future for ChannelController<R, S, C> {
    type Output = Result<(), C::Error>;

    /// Polls controller.
    #[inline]
    fn poll(self: Pin<&mut Self>, cx: &mut Context) -> Poll<Self::Output> {
        self.poll_inner(cx, false)
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

/// Helper function to connect and create [`ChannelController`].
///
/// # Errors
///
/// Return error if it can't open stream.
#[inline]
pub async fn open<R: HasTimer + HasNetwork, S: Stream, C: ChannelHandle<R>>(
    rt: R,
    addrs: &[SocketAddr],
    stream: impl AsyncFnOnce(R::Socket) -> IoResult<S>,
    controller: impl FnOnce() -> C,
) -> IoResult<ChannelController<R, S, C>> {
    let s = stream(rt.connect(addrs).await?).await?;
    Ok(ChannelControllerBuilder::default()
        .runtime(rt)
        .stream(s)
        .controller(controller())
        .build())
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::error::Error;
    use std::fmt::{Debug, Display, Formatter, Result as FmtResult};
    use std::future::poll_fn;
    use std::pin::pin;
    use std::time::{Duration, Instant};

    use anyhow::Error as AnyError;
    use futures_io::{AsyncRead, AsyncWrite};
    use onioncloud_runtime::Socket;
    use onioncloud_tart::rt::{Executor, Runtime};
    use onioncloud_tart::timer::Timer;
    use test_log::test;
    use tracing::info;

    use crate::error::ChannelError;
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

    impl From<ChannelError> for AnyErr {
        fn from(e: ChannelError) -> Self {
            Self(match e {
                ChannelError::Io(e) => e.into(),
                ChannelError::Rustls(e) => e.into(),
            })
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

        #[instrument(name = "AlwaysPending::poll_close", skip_all)]
        fn poll_close(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<IoResult<()>> {
            info!("closing socket");
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

            #[instrument(name = "Controller::handle", skip_all)]
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

            #[instrument(name = "Controller::handle", skip_all)]
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

    #[test]
    #[instrument]
    fn test_controller_timer2() {
        struct Controller;

        impl ChannelHandle<Runtime> for Controller {
            type Error = AnyErr;

            #[instrument(name = "Controller::handle", skip_all)]
            fn handle(self: Pin<&mut Self>, args: Handle<Runtime>) -> Result<Return, Self::Error> {
                let ret = Return::new(&args);
                info!("is timeout? {}", args.is_timeout());
                Ok(if args.is_timeout() {
                    assert!(args.is_same_poll(), "controller not immediately repolled");
                    ret.with_shutdown()
                } else {
                    assert!(!args.is_same_poll(), "controller not immediately repolled");
                    ret.with_timeout(Some(args.time()))
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

    #[test]
    #[instrument]
    fn test_controller_timer3() {
        #[pin_project]
        #[derive(Default)]
        struct Controller {
            time: Option<Instant>,
            #[pin]
            timer: Option<Timer>,
        }

        impl ChannelHandle<Runtime> for Controller {
            type Error = AnyErr;

            #[instrument(name = "Controller::handle", skip_all)]
            fn handle(
                self: Pin<&mut Self>,
                mut args: Handle<Runtime>,
            ) -> Result<Return, Self::Error> {
                let mut this = self.project();
                loop {
                    match this.timer.as_mut().as_pin_mut() {
                        Some(timer) => {
                            break Ok(if timer.poll(args.cx()).is_ready() {
                                assert_eq!(args.time(), *this.time.as_ref().unwrap());
                                Return::new(&args).with_shutdown()
                            } else {
                                Return::new(&args)
                            });
                        }
                        None => {
                            let time = args.time() + Duration::from_secs(60);
                            this.timer
                                .set(Some(Timer::with_instant(args.runtime().clone(), time)));
                            *this.time = Some(time);
                        }
                    }
                }
            }
        }

        let mut executor = Executor::builder().build();

        let rt = executor.runtime();
        rt.clone().spawn(async move {
            let mut cont = pin!(
                ChannelControllerBuilder::default()
                    .runtime(rt)
                    .stream(StreamNoTls::new(AlwaysPending::default()).unwrap())
                    .controller(Controller::default())
                    .build()
            );
            poll_fn(|cx| cont.as_mut().poll(cx)).await.unwrap();
        });

        executor.run();
    }
}
