use std::collections::HashMap;
use std::error::Error;
use std::future::Future;
use std::task::{Context, Poll};
use std::pin::Pin;
use std::mem::replace;
use std::io::{ErrorKind, Result as IoResult, IoSlice, IoSliceMut};
use std::time::Instant;

use flume::{Receiver, Sender, bounded};
use tracing::{instrument, warn, error, debug_span, Span, info};
use rustls::client::ClientConnection;
use futures_io::{AsyncRead, AsyncWrite};
use futures_core::ready;

use super::controller::ChannelController;
use super::{ChannelConfig, ChannelInput, ChannelOutput, Stream};
use crate::cell::Cell;
use crate::crypto::relay::RelayId;
use crate::runtime::Runtime;
use crate::util::{print_hex, AsyncWriteWrapper, AsyncReadWrapper, err_is_would_block};
use crate::util::sans_io::Handle;
use crate::crypto::tls::setup_client;

struct CircuitData {
    sender: Sender<Cell>,
}

struct Channel<R: Runtime, M> {
    handle: R::Task<bool>,
    sender: Sender<CircuitData>,
}

pub struct ChannelRef<'a, R: Runtime, M>(&'a mut Channel<R, M>);

pub struct ChannelManager<R: Runtime, M> {
    runtime: R,
    channels: HashMap<RelayId, Channel<R, M>>,
}

impl<R: Runtime> ChannelManager<R> {
    pub fn new(runtime: R) -> Self {
        Self {
            runtime,
            channels: HashMap::new(),
        }
    }

    pub fn get<'a>(&'a mut self, peer: &RelayId) -> Option<ChannelRef<'a, R, M>> {
        ChannelRef(self.channels.get(peer))
    }

    pub fn get_or_create<'a, C>(
        &'a mut self,
        peer: &RelayId,
        cfg: impl FnOnce(&RelayId) -> (C::Config, M),
    ) -> Option<ChannelRef<'a, R, M>>
    where
        C: ChannelController,
        R: Clone,
    {
    }
}

#[instrument(skip_all, fields(cfg.peer_id = %print_hex(cfg.peer_id()), cfg.link_addrs = &cfg.link_addrs()[..]))]
async fn handle_channel<R: Runtime, C: ChannelController>(rt: R, cfg: C::Config) -> bool {
    let stream = match rt.connect(&cfg.link_addrs()[..]).await {
        Ok(v) => v,
        Err(e) => {
            error!(error = e, "cannot connect to peer");
            return false;
        }
    };

    let peer_addr = match stream.peer_addr() {
        Ok(v) => v,
        Err(e) => {
            error!(error = e, "cannot get peer address");
            return false;
        }
    };

    let tls = match setup_client(peer_addr) {
        Ok(v) => v,
        Err(e) => {
            error!(error = e, "rustls setup");
            return false;
        }
    };

    let fut = ChannelFut {
        runtime: rt,
        stream,
        timer: TimerState::Nothing,
        tls,
        cont: C::new(cfg)
        state: State::Normal,
        span: debug_span!("ChannelFut"),
    };
    match fut.await {
        Ok(()) => true,
        Err(e) => {
            error!(error = e, "channel error");
            false
        },
    }
}

enum State {
    Normal,
    Shutdown,
}

enum TimerState<T> {
    Nothing,
    Pending(T, Instant),
    Finished,
}

struct ChannelFut<R: Runtime, C: ChannelController> {
    runtime: R,
    stream: R::Stream,
    timer: TimerState<R::Timer>,
    tls: TlsWrapper,
    cont: C,
    state: State,
    span: Span,
}

impl<R: Runtime, C: ChannelController> Future for ChannelFut<R, C> {
    type Output = Result<(), C::Error>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        // SAFETY: Values are pin projected (except for controller and TLS).
        let (runtime, mut stream, mut timer, tls, cont, state, span) = unsafe {
            let Self {runtime, stream, timer, tls, cont} = Pin::into_inner_unchecked(self);
            (runtime, Pin::new_unchecked(stream), Pin::new_unchecked(timer), tls, cont, state, span)
        };

        'main: loop {
            let guard = span.enter();

            // Process shutdown
            if matches!(state, State::Shutdown) {
                return ready!(stream.poll_close(cx));
            }

            // Process TLS
            let mut pending = 0u8;
            loop {
                if pending & 1 == 0 {
                    while tls.0.wants_write() {
                        let mut wrapper = AsyncWriteWrapper::new(cx, stream.as_mut());
                        match tls.0.write_tls(&mut wrapper) {
                            Ok(0) => {
                                info!("shutting down: TLS write finished");
                                *state = State::Shutdown;
                                continue 'main;
                            },
                            Ok(_) => (),
                            Err(e) => {
                                if matches!(e.kind(), ErrorKind::Interrupted | ErrorKind::WouldBlock) {
                                    pending |= 1 | 4;
                                    break;
                                }

                                warn!("shutting down: IO error");
                                *state = State::Shutdown;
                                return Poll::Ready(Err(e.into()));
                            }
                        }
                    }

                    if let Poll::Ready(Err(e)) = stream.poll_flush(cx) {
                        return Poll::Ready(Err(e.into()));
                    }
                }

                if pending & 2 == 0 {
                    while tls.0.wants_read() {
                        let mut wrapper = AsyncReadWrapper::new(cx, stream.as_mut());
                        match tls.0.read_tls(&mut wrapper) {
                            Ok(0) => {
                                pending |= 2;
                                break;
                            }
                            Ok(_) => (),
                            Err(e) => {
                                if matches!(e.kind(), ErrorKind::Interrupted | ErrorKind::WouldBlock) {
                                    pending |= 2 | 4;
                                    break;
                                }

                                warn!("shutting down: IO error");
                                *state = State::Shutdown;
                                return Poll::Ready(Err(e.into()));
                            }
                        }
                    }
                }

                if let Err(e) = tls.0.process_new_packets() {
                    warn!("shutting down: TLS error");
                    *state = Shutdown;
                    return Poll::Ready(Err(e.into()));
                } else if pending & 3 == 3 || !(tls.0.wants_read() || tls.0.wants_write()) {
                    break;
                }
            }

            debug_assert!(pending & 4 != 0, "TLS handshake pending but IO is not");
            if tls.0.is_handshaking() {
                return Ok(());
            }

            // Process controller
            let time = Instant::now();
            let is_timeout = match *timer {
                TimerState::Pending(_, t) => t <= time,
                TimerState::Nothing => false,
                TimerState::Finished => true,
            };
            let ret = match cont.handle(ChannelInput::new(tls, time, is_timeout)) {
                Ok(v) => v,
                Err(e) => {
                    warn!("shutting down: controller error");
                    *state = State::Shutdown;
                    return Poll::Ready(Err(e.into()));
                }
            };

            if let Some(t) = ret.timeout {
                loop {
                    // SAFETY: Timer future will not be moved.
                    if let TimerState::Pending(f, time) = unsafe { Pin::into_inner_unchecked(timer) } {
                        // SAFETY: Timer future is pin projected.
                        let f = unsafe { Pin::new_unchecked(f) };
                        if *time != t {
                            f.reset(t);
                            *time = t;
                        }

                        if f.poll(cx).is_ready() {
                            timer.set(TimerState::Finished);
                        }
                        break;
                    } else {
                        timer.set(TimerState::Pending((runtime.timer(t), t)));
                    }
                }
            } else {
                timer.set(TimerState::Nothing);
            }

            if ret.shutdown {
                *state = State::Shutdown;
                continue;
            }

            // All futures are pending.
            return Poll::Pending;
        }
    }
}

struct TlsWrapper(ClientConnection);

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
        self.0.peer_certificates()?.get(0).as_deref()
    }
}
