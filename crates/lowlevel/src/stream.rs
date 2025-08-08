use std::error::Error;
use std::io::{Error as IoError, ErrorKind, Result as IoResult};
use std::mem::take;
use std::num::{NonZeroU16, NonZeroU32};
use std::pin::Pin;
use std::sync::Arc;
use std::task::Poll::*;
use std::task::{Context, Poll};

use flume::SendError;
use flume::r#async::{RecvStream, SendSink};
use futures_core::{Stream as _, ready};
use futures_io::{AsyncBufRead, AsyncRead, AsyncWrite};
use futures_sink::Sink as _;
use futures_util::AsyncWriteExt as _;
use pin_project::pin_project;
use tracing::{debug, info, instrument, trace};

use crate::cache::{Cached, CellCache, CellCacheExt};
use crate::cell::relay::data::RelayData;
use crate::cell::relay::drop::RelayDrop;
use crate::cell::relay::end::{EndReason, RelayEnd};
use crate::cell::relay::sendme::RelaySendme;
use crate::cell::relay::{IntoRelay, RELAY_DATA_LENGTH, Relay, RelayLike, cast};
use crate::circuit::NewStream;
use crate::util::cell_map::NewHandler;

type CacheTy = Arc<dyn Send + Sync + CellCache>;
type CachedCell<C = Relay> = Cached<C, CacheTy>;

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
#[pin_project(project = DirStreamProj)]
pub struct DirStream {
    cache: CacheTy,
    circ_id: NonZeroU32,
    stream_id: NonZeroU16,

    #[pin]
    send: SendSink<'static, CachedCell>,
    #[pin]
    recv: RecvStream<'static, CachedCell>,

    recv_buf: [u8; RELAY_DATA_LENGTH],
    recv_buf_len: usize,
    send_buf: [u8; RELAY_DATA_LENGTH],
    send_buf_len: usize,

    state: State,
}

enum State {
    Normal,
    ShutdownRequest(EndReason),
    Shutdown,
}

impl DirStream {
    /// Create new [`DirStream`].
    ///
    /// # Parameters
    /// - `cache` : Cell cache.
    /// - `data` : Parameter for new stream.
    pub fn new(cache: Arc<dyn Send + Sync + CellCache>, data: NewStream<CachedCell>) -> Self {
        let NewStream {
            circ_id,
            inner:
                NewHandler {
                    id: stream_id,
                    receiver: recv,
                    sender: send,
                },
        } = data;

        Self {
            cache,
            circ_id,
            stream_id: stream_id.try_into().expect("invalid stream ID"),
            recv_buf: [0; RELAY_DATA_LENGTH],
            recv_buf_len: 0,
            send_buf: [0; RELAY_DATA_LENGTH],
            send_buf_len: 0,
            state: State::Normal,

            send: send.into_sink(),
            recv: recv.into_stream(),
        }
    }

    /// Close with reason.
    ///
    /// Using [`Self::poll_close`] does not give any reason.
    /// Use this to provide explicit reason instead.
    pub fn close_with(self: Pin<&mut Self>, reason: EndReason) {
        if let state @ State::Normal = self.project().state {
            *state = State::ShutdownRequest(reason);
        }
    }

    /// Async wrapper for [`Self::close_with`].
    pub async fn close_with_async(mut self: Pin<&mut Self>, reason: EndReason) -> IoResult<()> {
        self.as_mut().close_with(reason);
        self.close().await
    }

    /// Returns `true` if stream is closing.
    pub fn is_closed(&self) -> bool {
        !matches!(self.state, State::Normal)
    }

    fn poll_read_until_data(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<IoResult<Option<RelayData>>> {
        let DirStreamProj {
            circ_id: &mut circ_id,
            stream_id: &mut stream_id,
            cache,
            state,
            mut recv,
            ..
        } = self.as_mut().project();
        let cache: &(dyn Send + Sync + CellCache) = &cache;

        if !matches!(state, State::Normal) {
            // Stream closing
            ready!(self.poll_close(cx))?;
            return Ready(Ok(None));
        }

        while let Some(cell) = ready!(recv.as_mut().poll_next(cx)) {
            debug_assert_eq!(cell.circuit, circ_id);
            debug_assert_eq!(cell.stream(), stream_id.into());
            let mut cell = Cached::map(cell, Some);

            if let Some(cell) = cast::<RelayData>(&mut cell).map_err(map_io_err)? {
                // RELAY_DATA cell
                return Ready(Ok(Some(cell)));
            } else if let Some(cell) = cast::<RelayEnd>(&mut cell).map_err(map_io_err)? {
                // RELAY_END cell
                let reason = cache.cache_b(cell).reason();
                info!(reason = display(reason), "stream closed");
                *state = State::Shutdown;
                ready!(self.poll_close(cx))?;
                break;
            } else if let Some(cell) = cast::<RelayDrop>(&mut cell).map_err(map_io_err)? {
                // RELAY_DROP cell
                cache.discard(cell);
            } else if let Some(cell) = cast::<RelaySendme>(&mut cell).map_err(map_io_err)? {
                // RELAY_SENDME cell
                cache.discard(cell);
            } else if let Some(cell) = Cached::transpose(cell) {
                // NOTE: Potential protocol violation
                trace!("unhandled cell with command {} received", cell.command());
            }
        }

        Ready(Ok(None))
    }

    fn poll_flush_buf(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<IoResult<()>> {
        let DirStreamProj {
            circ_id: &mut circ_id,
            stream_id: &mut stream_id,
            cache: &mut ref cache,
            state,
            send_buf,
            send_buf_len,
            mut send,
            ..
        } = self.project();

        if *send_buf_len == 0 {
            return Ready(Ok(()));
        }

        // Flush write buffer.
        if !handle_write_err(ready!(send.as_mut().poll_ready(cx))) {
            let cell = RelayData::new(
                cache.get_cached(),
                stream_id,
                &send_buf[..take(send_buf_len)],
            )
            .into_relay(circ_id);
            if !handle_write_err(send.as_mut().start_send(cache.cache(cell))) {
                return Ready(Ok(()));
            }
        }

        *state = State::Shutdown;
        Ready(Err(IoError::new(
            ErrorKind::WriteZero,
            "failed to flush buffer",
        )))
    }
}

fn map_io_err(e: impl 'static + Error + Send + Sync) -> IoError {
    IoError::other(Box::new(e))
}

impl AsyncRead for DirStream {
    #[instrument(level = "trace", skip_all, fields(circ_id = self.circ_id, stream_id = self.stream_id))]
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<IoResult<usize>> {
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
            return Ready(Ok(n));
        } else if let Some(cell) = ready!(self.as_mut().poll_read_until_data(cx))? {
            let DirStreamProj {
                cache: &mut ref cache,
                recv_buf,
                recv_buf_len,
                ..
            } = self.project();
            let cell = (**cache).cache_b(cell);
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
}

impl AsyncBufRead for DirStream {
    #[instrument(level = "trace", skip_all, fields(circ_id = self.circ_id, stream_id = self.stream_id))]
    fn poll_fill_buf(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<IoResult<&[u8]>> {
        if self.recv_buf_len == 0 {
            // Fill buffer
            if !matches!(self.state, State::Normal) {
                // Stream closing
                ready!(self.as_mut().poll_close(cx))?;
            } else if let Some(cell) = ready!(self.as_mut().poll_read_until_data(cx))? {
                let DirStreamProj {
                    cache,
                    recv_buf,
                    recv_buf_len,
                    ..
                } = self.as_mut().project();
                let cell = (**cache).cache_b(cell);
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

    #[instrument(level = "trace", skip_all, fields(circ_id = self.circ_id, stream_id = self.stream_id, amount = amount))]
    fn consume(self: Pin<&mut Self>, amount: usize) {
        let p = self.project().recv_buf_len;
        *p = match (*p).checked_sub(amount) {
            Some(v) => v,
            None => panic!("too many bytes consumed! (max is {}, got {})", *p, amount),
        };
    }
}

fn handle_write_err(ret: Result<(), SendError<CachedCell>>) -> bool {
    let Err(_) = ret else { return false };
    debug!("circuit disconnected");
    true
}

impl AsyncWrite for DirStream {
    #[instrument(level = "trace", skip_all, fields(circ_id = self.circ_id, stream_id = self.stream_id))]
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<IoResult<usize>> {
        let n = if !matches!(self.state, State::Normal) {
            // Stream is closed. Reuse poll_close
            ready!(self.poll_close(cx))?;
            0
        } else if self.send_buf_len.saturating_add(buf.len()) >= RELAY_DATA_LENGTH {
            // Avoids copying to buffer
            let DirStreamProj {
                circ_id: &mut circ_id,
                stream_id: &mut stream_id,
                cache: &mut ref cache,
                state,
                send_buf,
                send_buf_len,
                mut send,
                ..
            } = self.project();

            let mut ok = !handle_write_err(ready!(send.as_mut().poll_ready(cx)));
            let mut n = 0;

            if ok {
                n = RELAY_DATA_LENGTH - *send_buf_len;
                let cell = RelayData::new_multipart(
                    cache.get_cached(),
                    stream_id,
                    [&send_buf[..take(send_buf_len)], &buf[..n]],
                )
                .into_relay(circ_id);
                ok = !handle_write_err(send.as_mut().start_send(cache.cache(cell)));
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

    #[instrument(level = "trace", skip_all, fields(circ_id = self.circ_id, stream_id = self.stream_id))]
    fn poll_close(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<IoResult<()>> {
        if !matches!(self.state, State::Shutdown) && self.send_buf_len > 0 {
            // Requesting closing, but there are data in write buffer.
            ready!(self.as_mut().poll_flush_buf(cx)?);
        }

        let DirStreamProj {
            circ_id: &mut circ_id,
            stream_id: &mut stream_id,
            cache: &mut ref cache,
            state,
            mut send,
            mut recv,
            ..
        } = self.project();

        loop {
            // Read and drop all cells
            while let Ready(Some(_)) = recv.as_mut().poll_next(cx) {}

            match state {
                State::Normal => *state = State::ShutdownRequest(EndReason::Done),
                State::Shutdown => {
                    handle_write_err(ready!(send.as_mut().poll_flush(cx)));
                    break;
                }
                State::ShutdownRequest(reason) => {
                    if handle_write_err(ready!(send.as_mut().poll_ready(cx))) {
                        *state = State::Shutdown;
                        break;
                    }

                    let reason = reason.clone();
                    *state = State::Shutdown;
                    let cell =
                        RelayEnd::new(cache.get_cached(), stream_id, reason).into_relay(circ_id);
                    if handle_write_err(send.as_mut().start_send(cache.cache(cell))) {
                        break;
                    }
                }
            }
        }

        Ready(Ok(()))
    }

    #[instrument(level = "trace", skip_all, fields(circ_id = self.circ_id, stream_id = self.stream_id))]
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<IoResult<()>> {
        if !matches!(self.state, State::Normal) {
            // Stream is closed
            return self.poll_close(cx);
        }

        ready!(self.as_mut().poll_flush_buf(cx)?);

        let DirStreamProj { state, send, .. } = self.project();

        if handle_write_err(ready!(send.poll_flush(cx))) {
            *state = State::Shutdown;
        }

        Ready(Ok(()))
    }
}
