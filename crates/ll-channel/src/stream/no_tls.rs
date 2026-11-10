use std::borrow::Cow;
use std::io::{ErrorKind, Read, Result as IoResult, Write};
use std::net::SocketAddr;
use std::pin::Pin;
use std::task::Poll::*;
use std::task::{Context, Poll};

use onioncloud_runtime::Socket;
use pin_project::pin_project;

use super::Stream;
use crate::error::ChannelError;

/// Wrapper for [`Socket`] without TLS.
#[pin_project]
#[derive(Debug)]
pub struct StreamNoTls<S> {
    read_buf: [u8; 128],
    read_ix: u8,
    read_len: u8,
    write_buf: [u8; 128],
    write_ix: u8,
    write_len: u8,

    state: State,
    flags: u8,
    peer_addr: SocketAddr,
    #[pin]
    stream: S,
}

#[derive(Debug)]
enum State {
    None,
    Closing,
    Closed,
}

const FLAG_CLOSED: u8 = 128;
const FLAG_READ: u8 = 1 << 0;
const FLAG_WRITE: u8 = 1 << 1;

impl<S> Read for StreamNoTls<S> {
    fn read(&mut self, buf: &mut [u8]) -> IoResult<usize> {
        if buf.is_empty() {
            return Ok(0);
        } else if self.read_len == 0 {
            return if self.read_ix & FLAG_CLOSED == 0 {
                Err(ErrorKind::WouldBlock.into())
            } else {
                Ok(0)
            };
        }

        let i = (self.read_ix & !FLAG_CLOSED) as usize;
        let n = buf.len().min(self.read_len as usize).min(128 - i);
        buf[..n].copy_from_slice(&self.read_buf[i..i + n]);
        self.read_ix = (self.read_ix & FLAG_CLOSED) | (((i + n) as u8) % 128);
        self.read_len -= n as u8;
        Ok(n)
    }
}

impl<S> Write for StreamNoTls<S> {
    fn write(&mut self, buf: &[u8]) -> IoResult<usize> {
        if buf.is_empty() {
            return Ok(0);
        } else if self.write_len == 0 {
            return if self.write_ix & FLAG_CLOSED == 0 {
                Err(ErrorKind::WouldBlock.into())
            } else {
                Ok(0)
            };
        }

        let i = (((self.write_ix & !FLAG_CLOSED) + self.write_len) % 128) as usize;
        let n = buf.len().min(128 - self.write_len as usize).min(128 - i);
        self.write_buf[i..i + n].copy_from_slice(&buf[..n]);
        self.write_len += n as u8;
        Ok(n)
    }

    fn flush(&mut self) -> IoResult<()> {
        if matches!(self.state, State::Closed)
            || self.write_ix & FLAG_CLOSED != 0
            || self.write_len == 0
        {
            Ok(())
        } else {
            Err(ErrorKind::WouldBlock.into())
        }
    }
}

impl<S: Socket> Stream for StreamNoTls<S> {
    fn peer_addr(&self) -> SocketAddr {
        self.peer_addr
    }

    fn leaf_cert(&self) -> Option<Cow<'_, [u8]>> {
        None
    }

    fn wants_poll(&self) -> bool {
        match self.state {
            State::Closed => false,
            State::Closing => self.flags & FLAG_CLOSED == 0,
            State::None => {
                (self.read_ix & FLAG_CLOSED == 0
                    && self.flags & FLAG_READ == 0
                    && self.read_len < 128)
                    || (self.write_ix == 0 && self.flags & FLAG_WRITE == 0 && self.write_len > 0)
            }
        }
    }

    fn request_shutdown(self: Pin<&mut Self>) {
        let this = self.project();
        if matches!(this.state, State::None) {
            *this.state = State::Closing;
        }
    }

    fn poll_inner(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        is_same_poll: bool,
    ) -> Poll<Result<(), ChannelError>> {
        let mut this = self.project();
        if !is_same_poll {
            *this.flags = 0;
        }

        match this.state {
            State::None => (),
            State::Closing if *this.flags & FLAG_CLOSED != 0 => return Pending,
            State::Closing => {
                return match this.stream.poll_close(cx) {
                    Ready(Ok(())) => {
                        *this.state = State::Closed;
                        *this.read_ix |= FLAG_CLOSED;
                        *this.write_ix |= FLAG_CLOSED;
                        Ready(Ok(()))
                    }
                    Ready(Err(e)) => Ready(Err(e.into())),
                    Pending => {
                        *this.flags |= FLAG_CLOSED;
                        Pending
                    }
                };
            }
            State::Closed => return Ready(Ok(())),
        }

        if *this.read_ix & FLAG_CLOSED == 0 && *this.flags & FLAG_READ == 0 {
            while *this.read_len < 128 {
                let i = (*this.read_ix + *this.read_len) % 128;
                let mut b = &mut this.read_buf[i as usize..];
                let j = b.len().min((128 - *this.read_len) as usize);
                b = &mut b[..j];

                match this.stream.as_mut().poll_read(cx, b) {
                    Pending => {
                        *this.flags |= FLAG_READ;
                        break;
                    }
                    Ready(Err(e)) => return Ready(Err(e.into())),
                    Ready(Ok(0)) => {
                        *this.read_ix |= FLAG_CLOSED;
                        break;
                    }
                    Ready(Ok(n)) => *this.read_len += n as u8,
                }
            }
        }

        if *this.write_ix & FLAG_CLOSED == 0 && *this.flags & FLAG_WRITE == 0 {
            while *this.write_len > 0 {
                let mut b = &this.write_buf[*this.write_ix as usize..];
                b = &b[..b.len().min(*this.write_len as usize)];

                match this.stream.as_mut().poll_write(cx, b) {
                    Pending => {
                        *this.flags |= FLAG_WRITE;
                        break;
                    }
                    Ready(Err(e)) => return Ready(Err(e.into())),
                    Ready(Ok(0)) => {
                        *this.write_ix |= FLAG_CLOSED;
                        break;
                    }
                    Ready(Ok(n)) => {
                        *this.write_ix = (*this.write_ix + n as u8) % 128;
                        *this.write_len -= n as u8;
                    }
                }
            }
        }

        if *this.read_ix & FLAG_CLOSED != 0 && *this.write_ix & FLAG_CLOSED != 0 {
            *this.state = State::Closing;
        }

        Pending
    }
}

impl<S: Socket> StreamNoTls<S> {
    /// Creates new stream.
    pub fn new(stream: S) -> IoResult<Self> {
        let peer_addr = stream.peer_addr()?;
        Ok(Self {
            read_buf: [0; 128],
            read_ix: 0,
            read_len: 0,
            write_buf: [0; 128],
            write_ix: 0,
            write_len: 0,

            state: State::None,
            flags: 0,
            peer_addr,
            stream,
        })
    }
}
