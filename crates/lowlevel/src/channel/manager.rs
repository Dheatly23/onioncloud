use std::collections::HashMap;
use std::error::Error;
use std::future::Future;
use std::task::{Context, Poll};
use std::pin::Pin;
use std::mem::replace;
use std::io::{ErrorKind, Result as IoResult, IoSlice, IoSliceMut};
use std::time::Instant;

use flume::{Receiver, Sender, bounded};
use flume::r#async::{SendSink, RecvStream};
use tracing::{instrument, warn, error, debug_span, Span, info, debug};
use rustls::client::ClientConnection;
use futures_io::{AsyncRead, AsyncWrite};
use scopeguard::guard;

use super::controller::{ChannelController, Timeout, ControlMsg};
use super::{ChannelConfig, ChannelInput, ChannelOutput, Stream, CircuitMap};
use crate::cell::Cell;
use crate::crypto::relay::RelayId;
use crate::runtime::Runtime;
use crate::util::{print_hex, AsyncWriteWrapper, AsyncReadWrapper, err_is_would_block};
use crate::util::sans_io::Handle;
use crate::crypto::tls::setup_client;

struct CircuitData {
    sender: Sender<Cell>,
}

struct ChannelInner {
    config: Cfg,
    sender: Sender<CircuitData>,
    receiver: Receiver<CircuitData>,
}

struct Channel<R: Runtime, M> {
    handle: R::Task<bool>,
    inner: Arc<ChannelInner>,
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

#[derive(PartialEq, Eq)]
enum State {
    Normal,
    ReqShutdown,
    TlsShutdown,
    Shutdown,
}

struct ChannelFut<R: Runtime, C: ChannelController> {
    runtime: R,
    stream: R::Stream,
    timer: Option<R::Timer>,
    timer_state: TimerState,
    tls: TlsWrapper,
    ctrl_recv: Option<RecvStream<C::ControlMsg>>,
    circ_map: Option<CircuitMap<C::Cell, C::CircMeta>>,
    cont: C,
    state: State,
    span: Span,
}

impl<R: Runtime, C: ChannelController> Future for ChannelFut<R, C> {
    type Output = Result<(), C::Error>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        // SAFETY: Values are pin projected (except for controller and TLS).
        let (runtime, mut stream, mut timer, timer_finished, tls, mut ctrl_recv, circ_map, cont, state, span) = unsafe {
            let Self {runtime, stream, timer, timer_finished, tls, ctrl_recv, circ_map, cont, state, span} = Pin::into_inner_unchecked(self);
            (runtime, Pin::new_unchecked(stream), Pin::new_unchecked(timer), timer_finished, tls, Pin::new(ctrl_recv), circ_map, cont, state, span)
        };
        let mut pending = 0u8;

        const FLAG_READ: u8 = 1 << 0;
        const FLAG_WRITE: u8 = 1 << 1;
        const FLAG_TIMEOUT: u8 = 1 << 2;
        const FLAG_CTRLMSG: u8 = 1 << 3;

        'main: loop {
            let guard = span.enter();

            // Process shutdown
            match state {
                State::Shutdown => {
                    timer.set(TimerState::Nothing);
                    *circ_map = None;
                    ctrl_recv.set(None);
                    return stream.poll_close(cx).map_err(|e| e.into());
                }
                State::ReqShutdown => {
                    debug!("graceful shutdown request received");
                    tls.0.send_close_notify();
                    *state = State::TlsShutdown;
                    *circ_map = None;
                    ctrl_recv.set(None);
                    continue;
                }
                _ => (),
            }

            // Process TLS
            loop {
                if let Err(e) = tls.0.process_new_packets() {
                    warn!("shutting down: TLS error");
                    *state = Shutdown;
                    return Poll::Ready(Err(e.into()));
                } else if !(tls.0.wants_read() || tls.0.wants_write()) {
                    break;
                }

                while tls.0.wants_write() {
                    let mut wrapper = guard(AsyncWriteWrapper::new(cx, stream.as_mut()), |w| {
                        if w.finish() {
                            pending |= FLAG_WRITE;
                        }
                    });
                    match tls.0.write_tls(&mut wrapper) {
                        Ok(0) => {
                            debug_assert!(!tls.0.wants_write(), "TLS writes EOF yet wants to write more");
                            info!("shutting down: TLS write finished");
                            *state = State::Shutdown;
                            continue 'main;
                        },
                        Ok(_) => (),
                        Err(e) if matches!(e.kind(), ErrorKind::Interrupted | ErrorKind::WouldBlock) => break,
                        Err(e) => {
                            warn!("shutting down: IO error");
                            *state = State::Shutdown;
                            return Poll::Ready(Err(e.into()));
                        }
                    }
                }

                if let Poll::Ready(Err(e)) = stream.poll_flush(cx) {
                    return Poll::Ready(Err(e.into()));
                }

                while tls.0.wants_read() {
                    let mut wrapper = guard(AsyncReadWrapper::new(cx, stream.as_mut()), |w| {
                        if w.finish() {
                            pending |= FLAG_READ;
                        }
                    });
                    match tls.0.read_tls(&mut wrapper) {
                        Ok(0) => {
                            debug_assert!(!tls.0.wants_read(), "TLS reads EOF yet wants to read more");
                            break;
                        }
                        Ok(_) => (),
                        Err(e) if matches!(e.kind(), ErrorKind::Interrupted | ErrorKind::WouldBlock) => break,
                        Err(e) => {
                            warn!("shutting down: IO error");
                            *state = State::Shutdown;
                            return Poll::Ready(Err(e.into()));
                        }
                    }
                }
            }

            if tls.0.is_handshaking() || *state == State::TlsShutdown {
                debug_assert_ne!(pending & (FLAG_READ | FLAG_WRITE), 0, "TLS handshake pending but IO is not");
                return Poll::Ready(Ok(()));
            }

            const fn match_out<E>(v: Result<ChannelOutput, E>) -> bool {
                matches!(r, Ok(ChannelOutput { shutdown: false, .. }))
            }

            // Process controller
            let ctrl_recv = ctrl_recv.as_pin_mut().expect("control receiver should not be dropped");
            let circ_map = circ_map.as_mut().expect("circuit map should not be dropped");

            let mut time = None;
            let mut time = move || time.get_or_insert_with(Instant::now);
            let mut ret = None;
            if !*timer_finished {
                if timer.as_pin_mut().is_some_and(|t| t.poll(cx).is_ready()) {
                    *timer_finished = true;
                    // Event: timeout
                    ret = cont.handle((Timeout, ChannelInput::new(tls, cx, circ_map, time())));
                } else {
                    pending |= FLAG_TIMEOUT;
                }
            }

            let mut ret = match ret {
                Some(r) if !match_out(r) => r,
                _ => cont.handle(ChannelInput::new(tls, cx, circ_map, time())),
            };

            if pending & FLAG_CTRLMSG == 0 {
                while match_out(ret) {
                    let msg = match ctrl_recv.poll_next(cx) {
                        Poll::Pending => {
                            pending |= FLAG_CTRLMSG;
                            break;
                        },
                        Poll::Ready(Some(v)) => v,
                        Poll::Ready(None) => {
                            error!("shutting down: control channel disconnected (this might be a bug in channel manager)");
                            *state = State::Shutdown;
                            continue 'main;
                        },
                    };

                    // Event: control message
                    ret = cont.handle((ControlMsg(msg), ChannelInput::new(tls, cx, circ_map, time())));
                }
            }

            let ret = match ret {
                Ok(v) => v,
                Err(e) => {
                    warn!("shutting down: controller error");
                    *state = State::Shutdown;
                    return Poll::Ready(Err(e));
                }
            };

            if ret.shutdown {
                *state = State::Shutdown;
                continue;
            } else if let Some(t) = ret.timeout {
                let f = loop {
                    if let Some(f) = timer.as_pin_mut() {
                        break f;
                    }
                    timer.set(runtime.timer(t));
                };

                f.reset(t);
                *timer_finished = false;
                pending &= !FLAG_TIMEOUT;
            } else {
                // Regardless, mark timer as "finished"
                *timer_finished = true;
            }

            let mut retry = false;
            if pending & FLAG_READ == 0 && tls.0.wants_read() {
                debug!("repolling: TLS wants to read");
                retry = true;
            }
            if pending & FLAG_WRITE == 0 && tls.0.wants_write() {
                debug!("repolling: TLS wants to write");
                retry = true;
            }
            if pending & FLAG_TIMEOUT == 0 && !*timer_finished && timer.is_some() {
                debug!("repolling: timer wants to be polled");
                retry = true;
            }

            if !retry {
                // All futures are pending.
                return Poll::Pending;
            }
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
