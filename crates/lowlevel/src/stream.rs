use std::error::Error;
use std::future::poll_fn;
use std::io::{Error as IoError, ErrorKind, IoSlice, IoSliceMut, Result as IoResult};
use std::iter::from_fn;
use std::mem::take;
use std::num::{NonZeroU16, NonZeroU32};
use std::pin::Pin;
use std::task::Poll::*;
use std::task::{Context, Poll};

use futures_core::{Stream, ready};
use futures_io::{AsyncBufRead, AsyncRead, AsyncWrite};
use futures_sink::Sink;
use futures_util::AsyncWriteExt as _;
use pin_project::pin_project;
use tracing::{debug, info, info_span, instrument, trace, warn};

use crate::cache::{Cached, CellCache, CellCacheExt};
use crate::cell::relay::begin_dir::RelayBeginDir;
use crate::cell::relay::connected::RelayConnected;
use crate::cell::relay::data::RelayData;
use crate::cell::relay::drop::RelayDrop;
use crate::cell::relay::end::{EndReason, RelayEnd};
use crate::cell::relay::sendme::RelaySendme;
use crate::cell::relay::v0::{RELAY_DATA_LENGTH, RelayExt};
use crate::cell::relay::{IntoRelay, Relay, RelayVersion, cast};
use crate::circuit::NewStream;
use crate::errors::CircuitClosedError;
use crate::runtime::{Runtime, SendError};
use crate::util::GenerationalData;
use crate::util::cell_map::NewHandler;

type CachedCell<Cache, Cell = Relay> = Cached<GenerationalData<Cell>, Cache>;

/// Directory stream type.
///
/// # Buffering
///
/// Both reads and writes are buffered to [`RELAY_DATA_LENGTH`].
/// Use [`AsyncWrite::poll_flush`] to flush write buffer.
///
/// # Note on closing
///
/// Don't forget to close stream to ensure proper closing sequence.
/// When closing, all reads will be dropped and no further bytes will be returned.
#[pin_project(!Unpin, project = DirStreamProj)]
pub struct DirStream<Cache, Send, Recv> {
    #[pin]
    inner: DirStreamInner<Cache, Send, Recv>,

    recv_buf: [u8; RELAY_DATA_LENGTH],
    recv_buf_len: usize,
    send_buf: [u8; RELAY_DATA_LENGTH],
    send_buf_len: usize,

    state: State,
    end_reason: Option<EndReason>,
}

#[pin_project(!Unpin, project = DirStreamInnerProj)]
struct DirStreamInner<Cache, Send, Recv> {
    circ_id: NonZeroU32,
    stream_id: GenerationalData<NonZeroU16>,
    cache: Cache,
    #[pin]
    send: Send,
    #[pin]
    recv: Recv,
}

/// State of [`DirStream`].
enum State {
    /// Init state. Must call `poll_init` to finish initialization.
    Init(InitState),
    /// Normal operation. `end_reason` must be None.
    Normal,
    /// Shutdown request. Write buffer flushing happened here.
    ShutdownRequest,
    /// Shutdown sequence. All data must be flushed, and any remaining ones will be discarded.
    Shutdown,
}

#[allow(clippy::type_complexity)]
/// Opens a new [`DirStream`] using RELAY_BEGIN_DIR.
pub fn open_dir_stream<Cache: 'static + Send + Sync + Clone + CellCache, R: Runtime>(
    cache: Cache,
    data: NewStream<GenerationalData<NonZeroU16>, R, CachedCell<Cache>>,
) -> DirStream<Cache, R::MPSCSender<CachedCell<Cache>>, R::SPSCReceiver<CachedCell<Cache>>> {
    let NewStream {
        circ_id,
        inner:
            NewHandler {
                id: stream_id,
                sender: send,
                receiver: recv,
            },
    } = data;
    DirStream::new(
        cache,
        circ_id,
        stream_id,
        send,
        recv,
        InitState::BeginDirStart,
    )
}

impl<
    C: 'static + Send + Sync + Clone + CellCache,
    S: Sink<CachedCell<C>, Error = SendError<CachedCell<C>>>,
    R: Stream<Item = CachedCell<C>>,
> DirStream<C, S, R>
{
    #[inline(always)]
    fn new(
        cache: C,
        circ_id: NonZeroU32,
        stream_id: GenerationalData<NonZeroU16>,
        send: S,
        recv: R,
        state: InitState,
    ) -> Self {
        Self {
            inner: DirStreamInner {
                circ_id,
                stream_id,
                cache,
                send,
                recv,
            },

            recv_buf: [0; RELAY_DATA_LENGTH],
            recv_buf_len: 0,
            send_buf: [0; RELAY_DATA_LENGTH],
            send_buf_len: 0,

            state: State::Init(state),
            end_reason: None,
        }
    }

    /// Close with reason.
    ///
    /// Using [`Self::poll_close`] does not give any reason.
    /// Use this to provide explicit reason instead.
    pub fn close_with(self: Pin<&mut Self>, reason: EndReason) {
        let DirStreamProj {
            state, end_reason, ..
        } = self.project();
        match state {
            State::Normal => *state = State::ShutdownRequest,
            State::Init(_) => (),
            State::Shutdown | State::ShutdownRequest => return,
        }

        debug_assert!(end_reason.is_none(), "end reason is not None");
        *end_reason = Some(reason);
    }

    /// Async wrapper for [`Self::close_with`].
    pub async fn close_with_async(mut self: Pin<&mut Self>, reason: EndReason) -> IoResult<()> {
        poll_fn(|cx| self.as_mut().poll_init(cx)).await?;
        self.as_mut().close_with(reason);
        self.close().await
    }

    /// Returns `true` if stream is closing.
    pub fn is_closed(&self) -> bool {
        matches!(
            self,
            Self {
                state: State::Shutdown | State::ShutdownRequest,
                ..
            } | Self {
                end_reason: Some(_),
                ..
            },
        )
    }

    fn poll_init(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<IoResult<()>> {
        let DirStreamProj {
            inner,
            state,
            end_reason,
            send_buf_len,
            recv_buf_len,
            ..
        } = self.project();
        let State::Init(init) = state else {
            return Ready(Ok(()));
        };

        debug_assert_eq!(*send_buf_len, 0);
        debug_assert_eq!(*recv_buf_len, 0);

        *state = if ready!(init.run_init(inner, cx))? {
            // Peer closing our stream. Straight to shutdown.
            State::Shutdown
        } else if end_reason.is_some() {
            // `close_with` is called while initializing.
            State::ShutdownRequest
        } else {
            State::Normal
        };
        Ready(Ok(()))
    }

    #[instrument(skip_all)]
    fn poll_read_until_data(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<IoResult<Option<RelayData>>> {
        let DirStreamProj {
            inner,
            state,
            end_reason,
            ..
        } = self.as_mut().project();
        let DirStreamInnerProj {
            circ_id: &mut circ_id,
            stream_id: &mut ref stream_id,
            cache: &mut ref cache,
            mut recv,
            ..
        } = inner.project();
        debug_assert!(!matches!(state, State::Init(_)), "state is init");

        if !matches!(state, State::Normal) {
            // Stream closing
            ready!(self.close_inner(cx))?;
            return Ready(Ok(None));
        }

        debug_assert!(end_reason.is_none(), "end reason is not None");

        while let Some(cell) = ready!(recv.as_mut().poll_next(cx)) {
            debug_assert_eq!(cell.generation, stream_id.generation);
            debug_assert_eq!(cell.inner.circuit, circ_id);
            debug_assert_eq!(cell.inner.stream(), stream_id.inner.into());
            let mut cell = Cached::map(cell, |c| Some(c.into_inner()));

            if let Some(cell) =
                cast::<RelayData>(&mut cell, RelayVersion::V0).map_err(map_io_err)?
            {
                // RELAY_DATA cell
                if !cell.data().is_empty() {
                    return Ready(Ok(Some(cell)));
                }
                cache.discard(cell);
            } else if let Some(cell) =
                cast::<RelayEnd>(&mut cell, RelayVersion::V0).map_err(map_io_err)?
            {
                // RELAY_END cell
                let reason = cache.cache_b(cell).reason();
                info!(%reason, "stream closed");

                // Ensure remaining data is flushed.
                *state = State::ShutdownRequest;
                ready!(self.close_inner(cx))?;
                break;
            } else if let Some(cell) =
                cast::<RelayDrop>(&mut cell, RelayVersion::V0).map_err(map_io_err)?
            {
                // RELAY_DROP cell
                cache.discard(cell);
            } else if let Some(cell) =
                cast::<RelaySendme>(&mut cell, RelayVersion::V0).map_err(map_io_err)?
            {
                // RELAY_SENDME cell
                cache.discard(cell);
            } else if let Some(cell) = Cached::transpose(cell) {
                // NOTE: Potential protocol violation
                debug!("unhandled cell with command {} received", cell.command());
            }
        }

        Ready(Ok(None))
    }

    #[instrument(skip_all)]
    fn poll_flush_buf(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<IoResult<()>> {
        let DirStreamProj {
            inner,
            state,
            send_buf,
            send_buf_len,
            ..
        } = self.project();
        let DirStreamInnerProj {
            circ_id: &mut circ_id,
            stream_id: &mut ref stream_id,
            cache: &mut ref cache,
            mut send,
            ..
        } = inner.project();
        debug_assert!(!matches!(state, State::Init(_)), "state is init");

        if *send_buf_len == 0 {
            return Ready(Ok(()));
        }

        // Flush write buffer.
        if !handle_write_err(ready!(send.as_mut().poll_ready(cx))) {
            let n = take(send_buf_len);
            let cell = <_>::try_into_relay_cached(
                cache.cache(
                    RelayData::new(cache.get_cached(), stream_id.inner, &send_buf[..n]).unwrap(),
                ),
                circ_id,
                RelayVersion::V0,
            )
            .unwrap();
            if !handle_write_err(send.as_mut().start_send(gen_cached(cell, stream_id))) {
                trace!("flushed {n} bytes");
                return Ready(Ok(()));
            }
        }

        debug!("failed to flush buffer");
        *state = State::Shutdown;
        Ready(Err(IoError::new(ErrorKind::WriteZero, CircuitClosedError)))
    }

    #[instrument(skip_all)]
    fn close_inner(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<IoResult<()>> {
        debug_assert!(!matches!(self.state, State::Init(_)), "state is init");

        loop {
            let DirStreamProj {
                inner,
                state,
                end_reason,
                send_buf_len: &mut ref send_buf_len,
                ..
            } = self.as_mut().project();
            let DirStreamInnerProj {
                circ_id: &mut circ_id,
                stream_id: &mut ref stream_id,
                cache: &mut ref cache,
                mut send,
                mut recv,
                ..
            } = inner.project();

            // Read and drop all cells
            while let Ready(Some(_)) = recv.as_mut().poll_next(cx) {}

            match state {
                State::Normal => {
                    debug_assert!(end_reason.is_none(), "end reason is not None");
                    *state = State::ShutdownRequest;
                    *end_reason = Some(EndReason::Done);
                }
                State::ShutdownRequest => {
                    if *send_buf_len > 0 {
                        // Requesting closing, but there are data in write buffer.
                        ready!(self.as_mut().poll_flush_buf(cx)?);
                    } else {
                        // Flushing done, set state to shutdown.
                        *state = State::Shutdown;
                    }
                }
                State::Shutdown => {
                    if handle_write_err(ready!(send.as_mut().poll_flush(cx))) {
                        break;
                    }
                    let Some(reason) = end_reason.take() else {
                        break;
                    };
                    let cell = <_>::try_into_relay_cached(
                        cache.cache(RelayEnd::new(cache.get_cached(), stream_id.inner, reason)),
                        circ_id,
                        RelayVersion::V0,
                    )
                    .unwrap();
                    if handle_write_err(send.as_mut().start_send(gen_cached(cell, stream_id))) {
                        break;
                    }
                }
                State::Init(_) => unreachable!("state must not be init"),
            }
        }

        Ready(Ok(()))
    }
}

fn map_io_err(e: impl 'static + Error + Send + Sync) -> IoError {
    IoError::other(Box::new(e))
}

impl<
    C: 'static + Send + Sync + Clone + CellCache,
    S: Sink<CachedCell<C>, Error = SendError<CachedCell<C>>>,
    R: Stream<Item = CachedCell<C>>,
> AsyncRead for DirStream<C, S, R>
{
    #[instrument(level = "trace", skip_all, fields(circ_id = self.inner.circ_id, stream_id = self.inner.stream_id.inner))]
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<IoResult<usize>> {
        ready!(self.as_mut().poll_init(cx))?;

        let DirStreamProj {
            recv_buf,
            recv_buf_len,
            ..
        } = self.as_mut().project();

        let n = if *recv_buf_len > 0 {
            let n = buf.len().min(*recv_buf_len);
            let s = RELAY_DATA_LENGTH - *recv_buf_len;
            buf[..n].copy_from_slice(&recv_buf[s..s + n]);
            *recv_buf_len -= n;
            n
        } else if let Some(cell) = ready!(self.as_mut().poll_read_until_data(cx))? {
            let DirStreamProj {
                inner,
                recv_buf,
                recv_buf_len,
                ..
            } = self.project();
            let cell = inner.cache.cache_b(cell);
            let data = cell.data();

            debug_assert_eq!(*recv_buf_len, 0);

            if buf.len() >= data.len() {
                // Buffer can read all cell data.
                buf[..data.len()].copy_from_slice(data);
                data.len()
            } else {
                // Some data must be moved to recv_buf.
                let (a, b) = data.split_at(buf.len());
                buf.copy_from_slice(a);
                *recv_buf_len = b.len();
                recv_buf[RELAY_DATA_LENGTH - b.len()..].copy_from_slice(b);
                buf.len()
            }
        } else {
            0
        };

        trace!("read {n} bytes");
        Ready(Ok(n))
    }

    #[instrument(level = "trace", skip_all, fields(circ_id = self.inner.circ_id, stream_id = self.inner.stream_id.inner))]
    fn poll_read_vectored(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &mut [IoSliceMut<'_>],
    ) -> Poll<IoResult<usize>> {
        ready!(self.as_mut().poll_init(cx))?;

        let DirStreamProj {
            recv_buf,
            recv_buf_len,
            ..
        } = self.as_mut().project();

        let n = if *recv_buf_len > 0 {
            let mut s = &recv_buf[RELAY_DATA_LENGTH - *recv_buf_len..];
            let mut n = 0;
            for d in bufs {
                let i = d.len().min(s.len());
                let b;
                (b, s) = s.split_at(i);
                d[..i].copy_from_slice(b);
                n += i;
                if s.is_empty() {
                    break;
                }
                debug_assert_eq!(i, d.len());
            }
            *recv_buf_len -= n;
            n
        } else if let Some(cell) = ready!(self.as_mut().poll_read_until_data(cx))? {
            let DirStreamProj {
                inner,
                recv_buf,
                recv_buf_len,
                ..
            } = self.project();
            let cell = inner.cache.cache_b(cell);
            let mut s = cell.data();

            debug_assert_eq!(*recv_buf_len, 0);

            let mut n = 0;
            for d in bufs {
                let i = d.len().min(s.len());
                let b;
                (b, s) = s.split_at(i);
                d[..i].copy_from_slice(b);
                n += i;
                if s.is_empty() {
                    break;
                }
                debug_assert_eq!(i, d.len());
            }
            recv_buf[RELAY_DATA_LENGTH - s.len()..].copy_from_slice(s);
            *recv_buf_len = s.len();
            n
        } else {
            0
        };

        trace!("read {n} bytes");
        Ready(Ok(n))
    }
}

impl<
    C: 'static + Send + Sync + Clone + CellCache,
    S: Sink<CachedCell<C>, Error = SendError<CachedCell<C>>>,
    R: Stream<Item = CachedCell<C>>,
> AsyncBufRead for DirStream<C, S, R>
{
    #[instrument(level = "trace", skip_all, fields(circ_id = self.inner.circ_id, stream_id = self.inner.stream_id.inner))]
    fn poll_fill_buf(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<IoResult<&[u8]>> {
        ready!(self.as_mut().poll_init(cx))?;

        if self.recv_buf_len == 0 {
            // Fill buffer
            if !matches!(self.state, State::Normal) {
                // Stream closing
                ready!(self.as_mut().close_inner(cx))?;
            } else if let Some(cell) = ready!(self.as_mut().poll_read_until_data(cx))? {
                let DirStreamProj {
                    inner,
                    recv_buf,
                    recv_buf_len,
                    ..
                } = self.as_mut().project();
                let cell = inner.cache.cache_b(cell);
                let data = cell.data();

                // Copy data into buffer
                *recv_buf_len = data.len();
                recv_buf[RELAY_DATA_LENGTH - data.len()..].copy_from_slice(data);
            }
        }

        let Self {
            recv_buf,
            recv_buf_len,
            ..
        } = self.into_ref().get_ref();
        Ready(Ok(&recv_buf[RELAY_DATA_LENGTH - *recv_buf_len..]))
    }

    #[instrument(level = "trace", skip_all, fields(circ_id = self.inner.circ_id, stream_id = self.inner.stream_id.inner, amount = amount))]
    fn consume(self: Pin<&mut Self>, amount: usize) {
        let p = self.project().recv_buf_len;
        *p = match (*p).checked_sub(amount) {
            Some(v) => v,
            None => panic!("too many bytes consumed! (max is {}, got {})", *p, amount),
        };
    }
}

fn handle_write_err<T>(ret: Result<(), SendError<T>>) -> bool {
    let Err(_) = ret else { return false };
    drop(ret);
    debug!("circuit disconnected");
    true
}

impl<
    C: 'static + Send + Sync + Clone + CellCache,
    S: Sink<CachedCell<C>, Error = SendError<CachedCell<C>>>,
    R: Stream<Item = CachedCell<C>>,
> AsyncWrite for DirStream<C, S, R>
{
    #[instrument(level = "trace", skip_all, fields(circ_id = self.inner.circ_id, stream_id = self.inner.stream_id.inner))]
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<IoResult<usize>> {
        ready!(self.as_mut().poll_init(cx))?;

        let n = if !matches!(self.state, State::Normal) {
            // Stream closing
            ready!(self.close_inner(cx))?;
            0
        } else if self.send_buf_len.saturating_add(buf.len()) >= RELAY_DATA_LENGTH {
            // Avoids copying to buffer
            let DirStreamProj {
                inner,
                state,
                send_buf,
                send_buf_len,
                ..
            } = self.project();
            let DirStreamInnerProj {
                circ_id: &mut circ_id,
                stream_id: &mut ref stream_id,
                cache: &mut ref cache,
                mut send,
                ..
            } = inner.project();

            let mut ok = !handle_write_err(ready!(send.as_mut().poll_ready(cx)));
            let mut n = 0;

            if ok {
                n = RELAY_DATA_LENGTH - *send_buf_len;
                let cell = <_>::try_into_relay_cached(
                    cache.cache(
                        RelayData::new_multipart(
                            cache.get_cached(),
                            stream_id.inner,
                            [&send_buf[..take(send_buf_len)], &buf[..n]],
                        )
                        .unwrap(),
                    ),
                    circ_id,
                    RelayVersion::V0,
                )
                .unwrap();
                ok = !handle_write_err(send.as_mut().start_send(gen_cached(cell, stream_id)));
            }

            if ok {
                n
            } else {
                // EOF
                // XXX: Should it be WriteZero error instead?
                *state = State::Shutdown;
                0
            }
        } else {
            // Copy bytes to buffer
            let DirStreamProj {
                send_buf,
                send_buf_len,
                ..
            } = self.project();
            debug_assert!(*send_buf_len < RELAY_DATA_LENGTH);

            let n = buf.len().min(RELAY_DATA_LENGTH - *send_buf_len);
            send_buf[*send_buf_len..*send_buf_len + n].copy_from_slice(&buf[..n]);
            *send_buf_len += n;
            n
        };

        trace!("write {n} bytes");
        Ready(Ok(n))
    }

    #[instrument(level = "trace", skip_all, fields(circ_id = self.inner.circ_id, stream_id = self.inner.stream_id.inner))]
    fn poll_write_vectored(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        mut bufs: &[IoSlice<'_>],
    ) -> Poll<IoResult<usize>> {
        ready!(self.as_mut().poll_init(cx))?;

        let n = if !matches!(self.state, State::Normal) {
            // Stream closing
            ready!(self.close_inner(cx))?;
            0
        } else {
            let DirStreamProj {
                inner,
                state,
                send_buf,
                send_buf_len,
                ..
            } = self.project();
            let DirStreamInnerProj {
                circ_id: &mut circ_id,
                stream_id: &mut ref stream_id,
                cache: &mut ref cache,
                mut send,
                ..
            } = inner.project();
            debug_assert!(*send_buf_len < RELAY_DATA_LENGTH);

            let mut ok = !handle_write_err(ready!(send.as_mut().poll_ready(cx)));
            let mut n = 0;

            if ok {
                let r = RELAY_DATA_LENGTH - *send_buf_len;

                let mut t = 0usize;
                let mut is_overflow = false;
                for buf in bufs {
                    let (v @ ..RELAY_DATA_LENGTH, false) = buf.len().overflowing_add(t) else {
                        is_overflow = true;
                        break;
                    };
                    t = v;
                }

                if is_overflow {
                    // Avoids copying to buffer
                    let mut s = Some(&send_buf[..take(send_buf_len)]);
                    let it = from_fn(|| {
                        if let s @ Some(_) = s.take() {
                            return s;
                        } else if n == r {
                            return None;
                        }

                        let buf;
                        (buf, bufs) = bufs.split_first()?;
                        let i = buf.len().min(r - n);
                        n += i;
                        Some(&buf[..i])
                    });
                    let cell = <_>::try_into_relay_cached(
                        cache.cache(
                            RelayData::new_multipart(cache.get_cached(), stream_id.inner, it)
                                .unwrap(),
                        ),
                        circ_id,
                        RelayVersion::V0,
                    )
                    .unwrap();
                    ok = !handle_write_err(send.as_mut().start_send(gen_cached(cell, stream_id)));
                } else {
                    // Copy bytes to buffer
                    let mut d = &mut send_buf[*send_buf_len..];
                    for buf in bufs {
                        let b;
                        (b, d) = d.split_at_mut(buf.len().min(d.len()));
                        b.copy_from_slice(&buf[..b.len()]);
                        n += b.len();
                        if d.is_empty() {
                            break;
                        }
                    }
                    *send_buf_len += n;
                }
            }

            if ok {
                n
            } else {
                // EOF
                // XXX: Should it be WriteZero error instead?
                *state = State::Shutdown;
                0
            }
        };

        trace!("write {n} bytes");
        Ready(Ok(n))
    }

    #[instrument(level = "trace", skip_all, fields(circ_id = self.inner.circ_id, stream_id = self.inner.stream_id.inner))]
    fn poll_close(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<IoResult<()>> {
        ready!(self.as_mut().poll_init(cx))?;
        self.close_inner(cx)
    }

    #[instrument(level = "trace", skip_all, fields(circ_id = self.inner.circ_id, stream_id = self.inner.stream_id.inner))]
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<IoResult<()>> {
        ready!(self.as_mut().poll_init(cx))?;

        if !matches!(self.state, State::Normal) {
            // Stream closing
            return self.close_inner(cx);
        }

        ready!(self.as_mut().poll_flush_buf(cx)?);

        let DirStreamProj { inner, state, .. } = self.project();

        if handle_write_err(ready!(inner.project().send.poll_flush(cx))) {
            *state = State::Shutdown;
        }

        Ready(Ok(()))
    }
}

/// Init state stages.
#[allow(clippy::enum_variant_names)]
#[derive(Debug, Clone)]
enum InitState {
    /// Start of RELAY_BEGIN_DIR.
    BeginDirStart,
    /// RELAY_BEGIN_DIR queued for sending.
    BeginDirSend,
    /// RELAY_BEGIN_DIR sent. Waiting for RELAY_CONNECTED.
    BeginDirConnected,
}

impl InitState {
    fn run_init<
        C: 'static + Send + Sync + Clone + CellCache,
        S: Sink<CachedCell<C>, Error = SendError<CachedCell<C>>>,
        R: Stream<Item = CachedCell<C>>,
    >(
        &mut self,
        inner: Pin<&mut DirStreamInner<C, S, R>>,
        cx: &mut Context<'_>,
    ) -> Poll<IoResult<bool>> {
        let DirStreamInnerProj {
            circ_id: &mut circ_id,
            stream_id: &mut ref stream_id,
            cache: &mut ref cache,
            mut send,
            mut recv,
        } = inner.project();

        loop {
            let _g = info_span!("run_init", state = ?self).entered();
            match self {
                Self::BeginDirStart => {
                    let mut ret = ready!(send.as_mut().poll_ready(cx));
                    if ret.is_ok() {
                        let cell =
                            cache.cache(RelayBeginDir::new(cache.get_cached(), stream_id.inner));
                        let cell = <_>::try_into_relay_cached(cell, circ_id, RelayVersion::V0)
                            .expect("relay conversion must succeed");
                        let cell = gen_cached(cell, stream_id);
                        ret = send.as_mut().start_send(cell);
                    }

                    if ret.is_err() {
                        drop(ret);
                        return Ready(Err(IoError::new(ErrorKind::BrokenPipe, CircuitClosedError)));
                    }

                    *self = Self::BeginDirSend;
                }
                Self::BeginDirSend => {
                    if ready!(send.as_mut().poll_flush(cx)).is_err() {
                        return Ready(Err(IoError::new(ErrorKind::BrokenPipe, CircuitClosedError)));
                    }

                    *self = Self::BeginDirConnected;
                }
                Self::BeginDirConnected => loop {
                    let Some(cell) = ready!(recv.as_mut().poll_next(cx)) else {
                        return Ready(Err(IoError::new(ErrorKind::BrokenPipe, CircuitClosedError)));
                    };
                    debug_assert_eq!(cell.generation, stream_id.generation);
                    debug_assert_eq!(cell.inner.circuit, circ_id);
                    debug_assert_eq!(cell.inner.stream(), stream_id.inner.into());
                    let mut cell = Cached::map(cell, |c| Some(c.into_inner()));

                    if let Some(cell) =
                        cast::<RelayEnd>(&mut cell, RelayVersion::V0).map_err(map_io_err)?
                    {
                        // RELAY_END cell
                        let reason = cache.cache_b(cell).reason();
                        info!(%reason, "stream closed");
                        return Ready(Ok(true));
                    } else if let Some(cell) =
                        cast::<RelayConnected>(&mut cell, RelayVersion::V0).map_err(map_io_err)?
                    {
                        // RELAY_CONNECTED cell
                        let cell = cache.cache_b(cell);
                        if cfg!(debug_assertions)
                            && let Some((ip, ttl)) = cell.data()
                        {
                            warn!("expected empty RELAY_CONNECTED cell, got ({ip}, {ttl})");
                        }

                        debug!("stream initialized");
                        return Ready(Ok(false));
                    } else if let Some(cell) = Cached::transpose(cell) {
                        // NOTE: Potential protocol violation
                        debug!("unhandled cell with command {} received", cell.command());
                    }
                },
            }
        }
    }
}

fn gen_cached<C: CellCache>(
    value: Cached<Relay, C>,
    stream_id: &GenerationalData<NonZeroU16>,
) -> Cached<GenerationalData<Relay>, C> {
    Cached::map(value, |value| {
        GenerationalData::new(value, stream_id.generation)
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::future::Future;
    use std::mem::transmute;
    use std::pin::pin;
    use std::sync::Arc;

    use futures_util::{AsyncReadExt as _, SinkExt as _, StreamExt as _};
    use proptest::collection::vec;
    use proptest::prelude::*;
    use test_log::test;

    use crate::cache::StandardCellCache;
    use crate::runtime::test::{TestExecutor, TestRuntime};

    fn run_test<F>(f: impl FnOnce(TestRuntime) -> F)
    where
        F: 'static + Send + Future,
        F::Output: 'static + Send,
    {
        let mut exec = TestExecutor::default();

        let rt = exec.runtime();
        rt.spawn(f(rt.clone()));

        exec.run_tasks_until_finished();
    }

    fn data_strat() -> impl Strategy<Value = (Vec<u8>, Vec<usize>)> {
        // TODO: Test sending empty data cell.
        (
            vec(any::<u8>(), 1..=2048),
            vec(1..=RELAY_DATA_LENGTH, 0..64),
        )
    }

    const CIRC_ID: NonZeroU32 = NonZeroU32::new(465620).unwrap();
    const STREAM_ID: GenerationalData<NonZeroU16> =
        GenerationalData::new(NonZeroU16::new(561).unwrap(), 485283);

    type CacheTy = Arc<StandardCellCache>;

    fn new_stream(
        rt: &TestRuntime,
        cache: CacheTy,
    ) -> (
        DirStream<
            CacheTy,
            <TestRuntime as Runtime>::MPSCSender<CachedCell<CacheTy>>,
            <TestRuntime as Runtime>::SPSCReceiver<CachedCell<CacheTy>>,
        >,
        <TestRuntime as Runtime>::SPSCSender<CachedCell<CacheTy>>,
        <TestRuntime as Runtime>::MPSCReceiver<CachedCell<CacheTy>>,
    ) {
        let (s1, r1) = rt.spsc_make(4);
        let (s2, r2) = rt.mpsc_make(4);
        (
            open_dir_stream::<CacheTy, TestRuntime>(
                cache,
                NewStream {
                    circ_id: CIRC_ID,
                    inner: NewHandler {
                        id: STREAM_ID,
                        receiver: r1,
                        sender: s2,
                    },
                },
            ),
            s1,
            r2,
        )
    }

    #[instrument(skip_all)]
    async fn handle_init_stream<S, R>(cache: &CacheTy, mut send: Pin<&mut S>, mut recv: Pin<&mut R>)
    where
        S: Sink<CachedCell<CacheTy>, Error = SendError<CachedCell<CacheTy>>>,
        R: Stream<Item = CachedCell<CacheTy>>,
    {
        {
            let cell = recv
                .next()
                .await
                .expect("should be sending RELAY_BEGIN_DIR cell");
            let mut cell = Cached::map(cell, |c| Some(c.into_inner()));
            let Some(cell) = cast::<RelayBeginDir>(&mut cell, RelayVersion::V0).unwrap() else {
                panic!(
                    "unknown cell with command {}",
                    Cached::transpose(cell).unwrap().command()
                );
            };
            cache.discard(cell);
        }

        {
            let cell = <_>::try_into_relay_cached(
                cache.cache(RelayConnected::new_empty(
                    cache.get_cached(),
                    STREAM_ID.inner,
                )),
                CIRC_ID,
                RelayVersion::V0,
            )
            .unwrap();
            send.send(gen_cached(cell, &STREAM_ID)).await.unwrap();
        }

        debug!("handshake done");
    }

    #[test]
    fn test_read() {
        let cache = CacheTy::default();

        async fn f(rt: TestRuntime, cache: CacheTy, data: (Vec<u8>, Vec<usize>)) {
            let data = Arc::new(data);
            let (stream, send, recv) = new_stream(&rt, cache.clone());

            rt.spawn({
                let data = data.clone();
                async move {
                    let mut send = pin!(send);
                    let mut recv = pin!(recv);
                    handle_init_stream(&cache, send.as_mut(), recv.as_mut()).await;

                    info!("sending data");
                    let mut s = &data.0[..];
                    for &i in &data.1 {
                        let b;
                        (b, s) = s.split_at(i.min(s.len()));
                        if b.is_empty() {
                            continue;
                        }

                        info!("sending {} bytes", b.len());
                        let cell = <_>::try_into_relay_cached(
                            cache.cache(
                                RelayData::new(cache.get_cached(), STREAM_ID.inner, b).unwrap(),
                            ),
                            CIRC_ID,
                            RelayVersion::V0,
                        )
                        .unwrap();
                        send.feed(gen_cached(cell, &STREAM_ID)).await.unwrap();
                        if s.is_empty() {
                            break;
                        }
                    }

                    while !s.is_empty() {
                        let b;
                        (b, s) = s.split_at(RELAY_DATA_LENGTH.min(s.len()));
                        info!("sending {} bytes", b.len());
                        let cell = <_>::try_into_relay_cached(
                            cache.cache(
                                RelayData::new(cache.get_cached(), STREAM_ID.inner, b).unwrap(),
                            ),
                            CIRC_ID,
                            RelayVersion::V0,
                        )
                        .unwrap();
                        send.feed(gen_cached(cell, &STREAM_ID)).await.unwrap();
                    }
                    send.flush().await.unwrap();
                    debug!("send done");

                    let mut cell = Cached::map(
                        recv.next().await.expect("should be sending closing cell"),
                        |c| Some(c.into_inner()),
                    );
                    let Some(cell) = cast::<RelayEnd>(&mut cell, RelayVersion::V0).unwrap() else {
                        panic!(
                            "unknown cell with command {}",
                            Cached::transpose(cell).unwrap().command()
                        );
                    };
                    cache.discard(cell);
                    info!("received end cell");
                }
            });

            info!("reading data");
            let mut stream = pin!(stream);
            let mut v = vec![0; data.0.len()];
            let mut n = 0;
            for &i in &data.1 {
                let e = v.len().min(n + i);
                let b = &mut v[n..e];
                stream.as_mut().read_exact(b).await.unwrap();
                n += b.len();
                if n == v.len() {
                    break;
                }
            }
            if n < v.len() {
                stream.as_mut().read_exact(&mut v[n..]).await.unwrap();
            }
            debug!("read success");

            assert_eq!(v, data.0);
            info!("closing");
            stream.close().await.unwrap();
            debug!("close success");
        }

        proptest!(move |(data in data_strat())| run_test(|rt| f(rt, cache.clone(), data)));
    }

    #[test]
    fn test_read_vectored() {
        let cache = CacheTy::default();

        async fn f(rt: TestRuntime, cache: CacheTy, data: (Vec<u8>, Vec<usize>)) {
            let data = Arc::new(data);
            let (stream, send, recv) = new_stream(&rt, cache.clone());

            rt.spawn({
                let data = data.clone();
                async move {
                    let mut send = pin!(send);
                    let mut recv = pin!(recv);
                    handle_init_stream(&cache, send.as_mut(), recv.as_mut()).await;

                    info!("sending data");
                    let mut s = &data.0[..];
                    for &i in &data.1 {
                        let b;
                        (b, s) = s.split_at(i.min(s.len()));
                        if b.is_empty() {
                            continue;
                        }

                        info!("sending {} bytes", b.len());
                        let cell = <_>::try_into_relay_cached(
                            cache.cache(
                                RelayData::new(cache.get_cached(), STREAM_ID.inner, b).unwrap(),
                            ),
                            CIRC_ID,
                            RelayVersion::V0,
                        )
                        .unwrap();
                        send.feed(gen_cached(cell, &STREAM_ID)).await.unwrap();
                        if s.is_empty() {
                            break;
                        }
                    }

                    while !s.is_empty() {
                        let b;
                        (b, s) = s.split_at(RELAY_DATA_LENGTH.min(s.len()));
                        info!("sending {} bytes", b.len());
                        let cell = <_>::try_into_relay_cached(
                            cache.cache(
                                RelayData::new(cache.get_cached(), STREAM_ID.inner, b).unwrap(),
                            ),
                            CIRC_ID,
                            RelayVersion::V0,
                        )
                        .unwrap();
                        send.feed(gen_cached(cell, &STREAM_ID)).await.unwrap();
                    }
                    send.flush().await.unwrap();
                    debug!("send done");

                    let mut cell = Cached::map(
                        recv.next().await.expect("should be sending closing cell"),
                        |c| Some(c.into_inner()),
                    );
                    let Some(cell) = cast::<RelayEnd>(&mut cell, RelayVersion::V0).unwrap() else {
                        panic!(
                            "unknown cell with command {}",
                            Cached::transpose(cell).unwrap().command()
                        );
                    };
                    cache.discard(cell);
                    info!("received end cell");
                }
            });

            info!("reading data");
            let mut stream = pin!(stream);
            let mut v = vec![0; data.0.len()];
            {
                let mut s = &mut v[..];
                let mut v = Vec::with_capacity(data.1.len() + 1);
                for &i in &data.1 {
                    let b;
                    (b, s) = s.split_at_mut(i.min(s.len()));
                    v.push(IoSliceMut::new(b));
                }
                v.push(IoSliceMut::new(s));

                let mut s = &mut v[..];
                while s.iter().any(|s| !s.is_empty()) {
                    // SAFETY: We have to transmute, otherwise the slice lifetime is kinda get swallowed.
                    let n = stream
                        .as_mut()
                        .read_vectored(unsafe {
                            transmute::<&mut [IoSliceMut<'_>], &mut [IoSliceMut<'_>]>(s)
                        })
                        .await
                        .unwrap();
                    IoSliceMut::advance_slices(&mut s, n);
                }
            }
            debug!("read success");

            assert_eq!(v, data.0);
            info!("closing");
            stream.close().await.unwrap();
            debug!("close success");
        }

        proptest!(move |(data in data_strat())| run_test(|rt| f(rt, cache.clone(), data)));
    }

    #[test]
    fn test_write() {
        let cache = CacheTy::default();

        async fn f(rt: TestRuntime, cache: CacheTy, data: (Vec<u8>, Vec<usize>)) {
            let data = Arc::new(data);
            let (stream, send, recv) = new_stream(&rt, cache.clone());

            rt.spawn({
                let data = data.clone();
                async move {
                    let mut stream = pin!(stream);

                    info!("sending data");
                    let mut s = &data.0[..];
                    for &i in &data.1 {
                        let b;
                        (b, s) = s.split_at(i.min(s.len()));

                        info!("sending {} bytes", b.len());
                        stream.as_mut().write_all(b).await.unwrap();
                        if s.is_empty() {
                            break;
                        }
                    }

                    if !s.is_empty() {
                        info!("sending {} bytes", s.len());
                        stream.as_mut().write_all(s).await.unwrap();
                    }
                    stream.as_mut().flush().await.unwrap();
                    debug!("send done");

                    info!("closing");
                    let mut a = [0; RELAY_DATA_LENGTH];
                    while stream.as_mut().read(&mut a).await.unwrap() > 0 {}
                    stream.as_mut().close().await.unwrap();
                    debug!("close done");
                }
            });

            let mut send = pin!(send);
            let mut recv = pin!(recv);
            handle_init_stream(&cache, send.as_mut(), recv.as_mut()).await;

            info!("reading data");
            let mut v = vec![0; data.0.len()];
            let mut n = 0;
            while n < v.len() {
                let cell = {
                    let mut cell = Cached::map(
                        recv.next().await.expect("stream should not be dropped"),
                        |c| Some(c.into_inner()),
                    );
                    let Some(cell) = cast::<RelayData>(&mut cell, RelayVersion::V0).unwrap() else {
                        panic!(
                            "unknown cell with command {}",
                            Cached::transpose(cell).unwrap().command()
                        );
                    };
                    cache.cache_b(cell)
                };
                let data = cell.data();
                v[n..n + data.len()].copy_from_slice(data);
                n += data.len();
            }
            debug!("read success");

            assert_eq!(v, data.0);
            info!("closing");
            let cell = <_>::try_into_relay_cached(
                cache.cache(RelayEnd::new(
                    cache.get_cached(),
                    STREAM_ID.inner,
                    EndReason::default(),
                )),
                CIRC_ID,
                RelayVersion::V0,
            )
            .unwrap();
            send.send(gen_cached(cell, &STREAM_ID)).await.unwrap();
            debug!("close success");
        }

        proptest!(move |(data in data_strat())| run_test(|rt| f(rt, cache.clone(), data)));
    }

    #[test]
    fn test_write_vectored() {
        let cache = CacheTy::default();

        async fn f(rt: TestRuntime, cache: CacheTy, data: (Vec<u8>, Vec<usize>)) {
            let data = Arc::new(data);
            let (stream, send, recv) = new_stream(&rt, cache.clone());

            rt.spawn({
                let data = data.clone();
                async move {
                    let mut stream = pin!(stream);

                    info!("sending data");
                    {
                        let mut s = &data.0[..];
                        let mut v = Vec::with_capacity(data.1.len() + 1);
                        for &i in &data.1 {
                            let b;
                            (b, s) = s.split_at(i.min(s.len()));
                            v.push(IoSlice::new(b));
                        }
                        v.push(IoSlice::new(s));

                        let mut s = &mut v[..];
                        while s.iter().any(|s| !s.is_empty()) {
                            let n = stream.as_mut().write_vectored(s).await.unwrap();
                            IoSlice::advance_slices(&mut s, n);
                        }
                    }
                    stream.as_mut().flush().await.unwrap();
                    debug!("send done");

                    info!("closing");
                    let mut a = [0; RELAY_DATA_LENGTH];
                    while stream.as_mut().read(&mut a).await.unwrap() > 0 {}
                    debug!("close done");
                    stream.as_mut().close().await.unwrap();
                }
            });

            let mut send = pin!(send);
            let mut recv = pin!(recv);
            handle_init_stream(&cache, send.as_mut(), recv.as_mut()).await;

            info!("reading data");
            let mut v = vec![0; data.0.len()];
            let mut n = 0;
            while n < v.len() {
                let cell = {
                    let mut cell = Cached::map(
                        recv.next().await.expect("stream should not be dropped"),
                        |c| Some(c.into_inner()),
                    );
                    let Some(cell) = cast::<RelayData>(&mut cell, RelayVersion::V0).unwrap() else {
                        panic!(
                            "unknown cell with command {}",
                            Cached::transpose(cell).unwrap().command()
                        );
                    };
                    cache.cache_b(cell)
                };
                let data = cell.data();
                v[n..n + data.len()].copy_from_slice(data);
                n += data.len();
                debug!("read {} bytes", data.len());
            }
            debug!("read success");

            assert_eq!(v, data.0);
            info!("closing");
            let cell = <_>::try_into_relay_cached(
                cache.cache(RelayEnd::new(
                    cache.get_cached(),
                    STREAM_ID.inner,
                    EndReason::default(),
                )),
                CIRC_ID,
                RelayVersion::V0,
            )
            .unwrap();
            send.send(gen_cached(cell, &STREAM_ID)).await.unwrap();
            debug!("close success");
        }

        proptest!(move |(data in data_strat())| run_test(|rt| f(rt, cache.clone(), data)));
    }
}
