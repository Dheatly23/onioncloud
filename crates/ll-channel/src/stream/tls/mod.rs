#[cfg(feature = "test-dummy-tls")]
pub(crate) mod tls_dummy;
pub(crate) mod tls_impl;

use std::borrow::Cow;
use std::future::poll_fn;
use std::io::{Error as IoError, ErrorKind, IoSlice, IoSliceMut, Read, Result as IoResult, Write};
use std::net::SocketAddr;
use std::pin::Pin;
use std::task::Poll::*;
use std::task::{Context, Poll, ready};

use futures_io::{AsyncRead, AsyncWrite};
use onioncloud_runtime::Socket;
use pin_project::pin_project;
use tracing::{instrument, trace};

use super::Stream;
use crate::error::ChannelError;

/// Private trait for anything TLS-like.
pub trait TLSLike {
    fn leaf_cert(&self) -> Option<Cow<'_, [u8]>>;
    fn is_handshaking(&self) -> bool;
    fn wants_read(&self) -> bool;
    fn wants_write(&self) -> bool;
    fn process_new_packets(&mut self) -> Result<(), ChannelError>;
    fn send_close_notify(&mut self);
    fn reader(&mut self) -> impl '_ + Read;
    fn writer(&mut self) -> impl '_ + Write;
    fn read_tls(&mut self, r: &mut dyn Read) -> IoResult<usize>;
    fn write_tls(&mut self, w: &mut dyn Write) -> IoResult<usize>;
}

/// Private trait for anything client TLS-like.
pub trait ClientTLSLike: TLSLike + Sized {
    fn new(peer_addr: SocketAddr) -> Result<Self, ChannelError>;
}

/// Inner implementation of stream TLS.
#[pin_project]
#[derive(Debug)]
pub struct StreamTLSInner<S, T: TLSLike> {
    #[pin]
    stream: S,
    peer_addr: SocketAddr,
    tls: T,
    state: State,
    flags: u8,
}

#[derive(Debug)]
enum State {
    Init,
    Main,
    InitClosing,
    TlsClose,
    SocketClose,
    Closed,
}

const FLAG_READ: u8 = 1 << 0;
const FLAG_WRITE: u8 = 1 << 1;
const FLAG_READ_CLOSED: u8 = 1 << 2;
const FLAG_WRITE_CLOSED: u8 = 1 << 3;

impl<S: Socket, T: TLSLike> AsyncRead for StreamTLSInner<S, T> {
    #[inline]
    fn poll_read(
        self: Pin<&mut Self>,
        _: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<IoResult<usize>> {
        let this = self.project();
        match ready!(poll_io_unwrap(this.tls.reader().read(buf))) {
            Ok(0) if *this.flags & FLAG_READ_CLOSED == 0 => Pending,
            v => Ready(v),
        }
    }

    #[inline]
    fn poll_read_vectored(
        self: Pin<&mut Self>,
        _: &mut Context<'_>,
        bufs: &mut [IoSliceMut<'_>],
    ) -> Poll<IoResult<usize>> {
        let this = self.project();
        match ready!(poll_io_unwrap(this.tls.reader().read_vectored(bufs))) {
            Ok(0) if *this.flags & FLAG_READ_CLOSED == 0 => Pending,
            v => Ready(v),
        }
    }
}

impl<S: Socket, T: TLSLike> AsyncWrite for StreamTLSInner<S, T> {
    #[inline]
    fn poll_write(self: Pin<&mut Self>, _: &mut Context<'_>, buf: &[u8]) -> Poll<IoResult<usize>> {
        let this = self.project();
        match this.state {
            State::Main => (),
            State::Closed => return Ready(Ok(0)),
            _ => return Pending,
        }
        match ready!(poll_io_unwrap(this.tls.writer().write(buf))) {
            Ok(0) if *this.flags & FLAG_WRITE_CLOSED == 0 => Pending,
            v => Ready(v),
        }
    }

    #[inline]
    fn poll_write_vectored(
        self: Pin<&mut Self>,
        _: &mut Context<'_>,
        bufs: &[IoSlice<'_>],
    ) -> Poll<IoResult<usize>> {
        let this = self.project();
        match this.state {
            State::Main => (),
            State::Closed => return Ready(Ok(0)),
            _ => return Pending,
        }
        match ready!(poll_io_unwrap(this.tls.writer().write_vectored(bufs))) {
            Ok(0) if *this.flags & FLAG_WRITE_CLOSED == 0 => Pending,
            v => Ready(v),
        }
    }

    #[inline]
    fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<IoResult<()>> {
        let this = self.project();
        match this.state {
            State::Main => (),
            State::Closed => return Ready(Ok(())),
            _ => return Pending,
        }
        ready!(poll_io_unwrap(this.tls.writer().flush()))?;
        if this.tls.wants_write() && *this.flags & FLAG_WRITE_CLOSED == 0 {
            Pending
        } else {
            Ready(Ok(()))
        }
    }

    #[inline]
    fn poll_close(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<IoResult<()>> {
        let this = self.project();
        match this.state {
            State::Init => *this.state = State::InitClosing,
            State::Main => {
                this.tls.send_close_notify();
                *this.state = State::TlsClose;
            }
            State::Closed => return Ready(Ok(())),
            _ => (),
        }

        Pending
    }
}

impl<S: Socket, T: TLSLike> Stream for StreamTLSInner<S, T> {
    fn peer_addr(&self) -> SocketAddr {
        self.peer_addr
    }

    fn is_init(&self) -> bool {
        matches!(self.state, State::Init | State::InitClosing)
    }

    fn leaf_cert(&self) -> Option<Cow<'_, [u8]>> {
        self.tls.leaf_cert()
    }

    fn wants_poll(&self) -> bool {
        matches!(self.state, State::SocketClose | State::Closed)
            || (self.flags & (FLAG_READ | FLAG_READ_CLOSED) == 0 && self.tls.wants_read())
            || (self.flags & (FLAG_WRITE | FLAG_WRITE_CLOSED) == 0 && self.tls.wants_write())
    }

    #[instrument(level = "debug", skip_all, fields(is_same_poll))]
    fn poll_inner(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        is_same_poll: bool,
    ) -> Poll<Result<(), ChannelError>> {
        let mut this = self.project();

        if !is_same_poll {
            *this.flags &= !(FLAG_READ | FLAG_WRITE);
        }

        loop {
            trace!(state = ?this.state, flags = this.flags, "poll inner loop");

            match this.state {
                State::Main | State::TlsClose => (),
                State::Init | State::InitClosing if this.tls.is_handshaking() => {
                    let mut w = WrapAsync {
                        cx,
                        p: this.stream.as_mut(),
                    };

                    let wants_write = this.tls.wants_write();
                    let wants_read = this.tls.wants_read();
                    if !wants_write && !wants_read {
                        unreachable!("handshaking but TLS does not want to read nor write");
                    } else if *this.flags & FLAG_WRITE == 0 && wants_write {
                        match poll_io_unwrap(this.tls.write_tls(&mut w)) {
                            Pending => *this.flags |= FLAG_WRITE,
                            Ready(Err(e)) => return Ready(Err(e.into())),
                            Ready(Ok(0)) => {
                                return Ready(Err(
                                    IoError::from(ErrorKind::ConnectionAborted).into()
                                ));
                            }
                            Ready(Ok(_)) => (),
                        }
                    } else if *this.flags & FLAG_READ == 0 && wants_read {
                        match poll_io_unwrap(this.tls.read_tls(&mut w)) {
                            Pending => *this.flags |= FLAG_READ,
                            Ready(Err(e)) => return Ready(Err(e.into())),
                            Ready(Ok(0)) => {
                                return Ready(Err(
                                    IoError::from(ErrorKind::ConnectionAborted).into()
                                ));
                            }
                            Ready(Ok(_)) => (),
                        }

                        this.tls.process_new_packets()?;
                    } else {
                        return Pending;
                    }

                    continue;
                }
                State::Init => *this.state = State::Main,
                State::InitClosing => {
                    this.tls.send_close_notify();
                    *this.state = State::TlsClose;
                }
                State::SocketClose => match this.stream.poll_close(cx) {
                    Ready(Ok(())) => {
                        *this.state = State::Closed;
                        return Ready(Ok(()));
                    }
                    r => return r.map_err(ChannelError::from),
                },
                State::Closed => return Ready(Ok(())),
            }

            let mut w = WrapAsync {
                cx,
                p: this.stream.as_mut(),
            };

            let wants_write = this.tls.wants_write();
            let wants_read = this.tls.wants_read();
            trace!(wants_read, wants_write, "reading/writing into TLS");

            if *this.flags & (FLAG_READ_CLOSED | FLAG_WRITE_CLOSED)
                == FLAG_READ_CLOSED | FLAG_WRITE_CLOSED
            {
                match this.state {
                    State::Main => {
                        this.tls.send_close_notify();
                        *this.state = State::TlsClose;
                    }
                    State::TlsClose => *this.state = State::SocketClose,
                    _ => unreachable!(),
                }
            } else if !wants_write && !wants_read {
                return Pending;
            } else if *this.flags & (FLAG_WRITE | FLAG_WRITE_CLOSED) == 0 && wants_write {
                match poll_io_unwrap(this.tls.write_tls(&mut w)) {
                    Pending => *this.flags |= FLAG_WRITE,
                    Ready(Err(e)) => return Ready(Err(e.into())),
                    Ready(Ok(0)) => *this.flags |= FLAG_WRITE_CLOSED,
                    Ready(Ok(_)) => (),
                }
            } else if *this.flags & (FLAG_READ | FLAG_READ_CLOSED) == 0 && wants_read {
                match poll_io_unwrap(this.tls.read_tls(&mut w)) {
                    Pending => *this.flags |= FLAG_READ,
                    Ready(Err(e)) => return Ready(Err(e.into())),
                    Ready(Ok(0)) => *this.flags |= FLAG_READ_CLOSED,
                    Ready(Ok(_)) => (),
                }

                this.tls.process_new_packets()?;
            } else {
                return Pending;
            }
        }
    }
}

impl<S: Socket, T: ClientTLSLike> StreamTLSInner<S, T> {
    /// Creates new stream.
    pub async fn new(stream: S) -> Result<Self, ChannelError>
    where
        S: Unpin,
    {
        let mut ret = Self::new_uninit(stream)?;

        poll_fn(|cx| match Pin::new(&mut ret).poll_inner(cx, false) {
            Poll::Pending if !ret.is_init() => Poll::Ready(Ok(())),
            r => r,
        })
        .await?;
        Ok(ret)
    }

    /// Creates new uninitialized stream.
    pub fn new_uninit(stream: S) -> Result<Self, ChannelError> {
        let peer_addr = stream.peer_addr()?;
        let tls = T::new(peer_addr)?;

        Ok(Self {
            peer_addr,
            tls,
            stream,
            state: State::Init,
            flags: 0,
        })
    }
}

/// Wrapper for [`AsyncRead`] and [`AsyncWrite`].
struct WrapAsync<'a, 'b, S> {
    cx: &'a mut Context<'b>,
    p: Pin<&'a mut S>,
}

impl<S: AsyncRead> Read for WrapAsync<'_, '_, S> {
    fn read(&mut self, buf: &mut [u8]) -> IoResult<usize> {
        poll_io_wrap(self.p.as_mut().poll_read(self.cx, buf))
    }

    fn read_vectored(&mut self, bufs: &mut [IoSliceMut<'_>]) -> IoResult<usize> {
        poll_io_wrap(self.p.as_mut().poll_read_vectored(self.cx, bufs))
    }
}

impl<S: AsyncWrite> Write for WrapAsync<'_, '_, S> {
    fn write(&mut self, buf: &[u8]) -> IoResult<usize> {
        poll_io_wrap(self.p.as_mut().poll_write(self.cx, buf))
    }

    fn write_vectored(&mut self, bufs: &[IoSlice<'_>]) -> IoResult<usize> {
        poll_io_wrap(self.p.as_mut().poll_write_vectored(self.cx, bufs))
    }

    fn flush(&mut self) -> IoResult<()> {
        poll_io_wrap(self.p.as_mut().poll_flush(self.cx))
    }
}

fn poll_io_wrap<R>(v: Poll<IoResult<R>>) -> IoResult<R> {
    match v {
        Ready(v) => v,
        Pending => Err(ErrorKind::WouldBlock.into()),
    }
}

fn poll_io_unwrap<R>(v: IoResult<R>) -> Poll<IoResult<R>> {
    match v {
        Err(e) if e.kind() == ErrorKind::WouldBlock => Pending,
        v => Ready(v),
    }
}
