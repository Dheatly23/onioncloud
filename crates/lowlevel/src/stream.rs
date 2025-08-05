use std::error::Error;
use std::io::{Error as IoError, Result as IoResult};
use std::mem::{take, transmute};
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

    fn process_relay_end(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        cell: RelayEnd,
        n: usize,
    ) -> Poll<IoResult<()>> {
        let reason = (*self.cache).cache_b(cell).reason();
        info!(reason = display(reason), "stream closed");
        *self.as_mut().project().state = State::Shutdown;
        match self.poll_close(cx) {
            Pending if n != 0 => Ready(Ok(())),
            r => r,
        }
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
        mut buf: &mut [u8],
    ) -> Poll<IoResult<usize>> {
        let DirStreamProj {
            state: &mut ref state,
            recv_buf,
            recv_buf_len,
            ..
        } = self.as_mut().project();

        let mut n = 0;
        if *recv_buf_len > 0 {
            n = buf.len().min(*recv_buf_len);
            let b;
            (b, buf) = buf.split_at_mut(n);
            b.copy_from_slice(&recv_buf[RELAY_DATA_LENGTH - n..]);
            *recv_buf_len -= n;
        }
        debug_assert!(buf.is_empty() || *recv_buf_len == 0);

        if !matches!(state, State::Normal) {
            return if self.poll_close(cx)?.is_pending() && n == 0 {
                Pending
            } else {
                trace!("read {n} bytes");
                Ready(Ok(n))
            };
        }

        while !buf.is_empty() {
            let DirStreamProj {
                circ_id: &mut circ_id,
                stream_id: &mut stream_id,
                cache,
                recv_buf,
                recv_buf_len,
                recv,
                ..
            } = self.as_mut().project();
            let cache: &(dyn Send + Sync + CellCache) = &cache;

            let cell = match recv.poll_next(cx) {
                Ready(None) => break,
                Ready(Some(cell)) => cell,
                // Ensure read bytes aren't dropped.
                Pending if n != 0 => break,
                Pending => return Pending,
            };

            debug_assert_eq!(cell.circuit, circ_id);
            debug_assert_eq!(cell.stream(), stream_id.into());
            let mut cell = Cached::map(cell, Some);

            if let Some(cell) = cast::<RelayData>(&mut cell).map_err(map_io_err)? {
                // RELAY_DATA cell
                let cell = cache.cache_b(cell);
                let data = cell.data();

                n += if buf.len() >= data.len() {
                    // Buffer can read all cell data.
                    let b;
                    (b, buf) = buf.split_at_mut(data.len());
                    b.copy_from_slice(data);
                    data.len()
                } else {
                    // Some data must be moved to recv_buf.
                    let l = buf.len();
                    let (a, b) = data.split_at(l);
                    take(&mut buf).copy_from_slice(a);
                    *recv_buf_len = b.len();
                    recv_buf[RELAY_DATA_LENGTH - b.len()..].copy_from_slice(b);
                    l
                };
            } else if let Some(cell) = cast::<RelayEnd>(&mut cell).map_err(map_io_err)? {
                // RELAY_END cell
                ready!(self.process_relay_end(cx, cell, n)?);
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

        trace!("read {n} bytes");
        Ready(Ok(n))
    }
}

impl AsyncBufRead for DirStream {
    #[instrument(level = "trace", skip_all, fields(circ_id = self.circ_id, stream_id = self.stream_id))]
    fn poll_fill_buf(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<IoResult<&[u8]>> {
        let DirStreamProj {
            circ_id: &mut circ_id,
            stream_id: &mut stream_id,
            state: &mut ref state,
            cache,
            recv_buf,
            recv_buf_len,
            mut recv,
            ..
        } = self.as_mut().project();
        let cache: &(dyn Send + Sync + CellCache) = &cache;

        if *recv_buf_len > 0 {
            // Use existing buffer.
            let b = &recv_buf[RELAY_DATA_LENGTH - *recv_buf_len..];
            // SAFETY: Lifetime extension is valid because self lifetime is captured.
            return Ready(Ok(unsafe { transmute::<&[u8], &[u8]>(b) }));
        }

        if !matches!(state, State::Normal) {
            ready!(self.poll_close(cx)?);
            return Ready(Ok(&[]));
        }

        // Otherwise receive cells and fill buffer.
        while let Some(cell) = ready!(recv.as_mut().poll_next(cx)) {
            debug_assert_eq!(cell.circuit, circ_id);
            debug_assert_eq!(cell.stream(), stream_id.into());
            let mut cell = Cached::map(cell, Some);

            if let Some(cell) = cast::<RelayData>(&mut cell).map_err(map_io_err)? {
                // RELAY_DATA cell
                let cell = cache.cache_b(cell);
                let data = cell.data();

                // Copy data into buffer
                *recv_buf_len = data.len();
                let b = &mut recv_buf[RELAY_DATA_LENGTH - data.len()..];
                b.copy_from_slice(data);

                // Return buffer
                // SAFETY: Lifetime extension is valid because self lifetime is captured.
                return Ready(Ok(unsafe { transmute::<&[u8], &[u8]>(b) }));
            } else if let Some(cell) = cast::<RelayEnd>(&mut cell).map_err(map_io_err)? {
                // RELAY_END cell
                ready!(self.process_relay_end(cx, cell, 0)?);
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

        // Receiver is finished.
        Ready(Ok(&[]))
    }

    #[instrument(level = "trace", skip_all, fields(circ_id = self.circ_id, stream_id = self.stream_id, amount))]
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
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        mut buf: &[u8],
    ) -> Poll<IoResult<usize>> {
        let DirStreamProj {
            circ_id: &mut circ_id,
            stream_id: &mut stream_id,
            cache: &mut ref cache,
            state,
            mut send,
            ..
        } = self.as_mut().project();

        let mut n = 0;
        while !buf.is_empty() {
            if !matches!(state, State::Normal) {
                // Stream is closed. Reuse poll_close
                if self.poll_close(cx)?.is_pending() && n == 0 {
                    return Pending;
                } else {
                    break;
                }
            }

            // Wait until sender is ready to send.
            match send.as_mut().poll_ready(cx) {
                Ready(Err(_)) => {
                    debug!("circuit disconnected");
                    break;
                }
                Ready(Ok(())) => (),
                Pending if n != 0 => break,
                Pending => return Pending,
            }

            let i = buf.len().min(RELAY_DATA_LENGTH);
            n += i;
            let b;
            (b, buf) = buf.split_at(i);
            let cell = RelayData::new(cache.get_cached(), stream_id, b).into_relay(circ_id);
            if handle_write_err(send.as_mut().start_send(cache.cache(cell))) {
                *state = State::Shutdown;
                break;
            }
        }

        trace!("write {n} bytes");
        Ready(Ok(n))
    }

    #[instrument(level = "trace", skip_all, fields(circ_id = self.circ_id, stream_id = self.stream_id))]
    fn poll_close(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<IoResult<()>> {
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
        let DirStreamProj { state, send, .. } = self.as_mut().project();

        if !matches!(state, State::Normal) {
            // Stream is closed
            return self.poll_close(cx);
        }

        if handle_write_err(ready!(send.poll_flush(cx))) {
            *state = State::Shutdown;
        }

        Ready(Ok(()))
    }
}
