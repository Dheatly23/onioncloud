use std::borrow::Cow;
use std::future::poll_fn;
use std::io::{ErrorKind, Read, Result as IoResult, Write};
use std::mem::take;
use std::net::SocketAddr;
use std::pin::Pin;
use std::task::Poll::*;

use futures_io::{AsyncRead, AsyncWrite};
use tracing::{instrument, trace};

use super::{ClientTLSLike, TLSLike};
use crate::error::ChannelError;

const BUF_SIZE: usize = 64;

static HANDSHAKE_MSG: &[u8] = b"\x00open\x00";
static CLOSE_MSG: &[u8] = b"\x00close\x00";

#[derive(Debug)]
pub struct DummyWrapper {
    read_buf: [u8; BUF_SIZE],
    read_ix: u8,
    read_len: u8,
    read_state: State,

    write_buf: [u8; BUF_SIZE],
    write_ix: u8,
    write_len: u8,
    write_state: State,

    req_close: bool,
}

#[derive(Debug, Clone, Copy)]
enum State {
    Handshake(u8),
    Main(IoState),
    Closing(u8),
    Closed,
}

#[derive(Debug, Clone, Copy)]
enum IoState {
    Byte,
    Escape,
}

struct DummyWrapperIO<'a>(&'a mut DummyWrapper);

impl Read for DummyWrapperIO<'_> {
    #[instrument(level = "debug", name = "DummyWrapper::read", skip_all, fields(len = buf.len()))]
    fn read(&mut self, mut buf: &mut [u8]) -> IoResult<usize> {
        if buf.is_empty() {
            return Ok(0);
        } else if self.0.read_len == 0 {
            return if matches!(self.0.read_state, State::Closed) {
                trace!("Read 0 bytes");
                Ok(0)
            } else {
                trace!("Pending read");
                Err(ErrorKind::WouldBlock.into())
            };
        }

        let i = usize::from(self.0.read_ix);
        let mut n = usize::from(self.0.read_len)
            .min(BUF_SIZE - i)
            .min(buf.len());
        buf[..n].copy_from_slice(&self.0.read_buf[i..i + n]);
        buf = &mut buf[n..];
        self.0.read_ix = (self.0.read_ix + n as u8) % (BUF_SIZE as u8);
        self.0.read_len -= n as u8;

        if !buf.is_empty() && self.0.read_len > 0 {
            let i = usize::from(self.0.read_ix);
            let n_ = usize::from(self.0.read_len)
                .min(BUF_SIZE - i)
                .min(buf.len());
            buf[..n_].copy_from_slice(&self.0.read_buf[i..i + n_]);
            self.0.read_ix = (self.0.read_ix + n_ as u8) % (BUF_SIZE as u8);
            self.0.read_len -= n_ as u8;
            n += n_;
        }

        trace!("Read {n} bytes");
        Ok(n)
    }
}

impl Write for DummyWrapperIO<'_> {
    #[instrument(level = "debug", name = "DummyWrapper::write", skip_all, fields(len = buf.len()))]
    fn write(&mut self, mut buf: &[u8]) -> IoResult<usize> {
        if buf.is_empty() || matches!(self.0.write_state, State::Closed) {
            trace!("Wrote 0 bytes");
            return Ok(0);
        } else if self.0.write_len == BUF_SIZE as u8
            || matches!(self.0.write_state, State::Handshake(_) | State::Closing(_))
            || self.0.req_close
        {
            trace!("Pending write");
            return Err(ErrorKind::WouldBlock.into());
        }

        let i = usize::from((self.0.write_ix + self.0.write_len) % BUF_SIZE as u8);
        let mut n = usize::from(BUF_SIZE as u8 - self.0.write_len)
            .min(BUF_SIZE - i)
            .min(buf.len());
        self.0.write_buf[i..i + n].copy_from_slice(&buf[..n]);
        buf = &buf[n..];
        self.0.write_len += n as u8;

        if !buf.is_empty() && self.0.write_len != BUF_SIZE as u8 {
            let i = usize::from((self.0.write_ix + self.0.write_len) % BUF_SIZE as u8);
            let n_ = usize::from(BUF_SIZE as u8 - self.0.write_len)
                .min(BUF_SIZE - i)
                .min(buf.len());
            self.0.write_buf[i..i + n_].copy_from_slice(&buf[..n_]);
            self.0.write_len += n_ as u8;
            n += n_;
        }

        trace!("Wrote {n} bytes");
        Ok(n)
    }

    fn flush(&mut self) -> IoResult<()> {
        if matches!(self.0.write_state, State::Closed) || self.0.write_len == 0 {
            trace!("Flushed buffer");
            Ok(())
        } else {
            trace!("Pending flush");
            Err(ErrorKind::WouldBlock.into())
        }
    }
}

impl TLSLike for DummyWrapper {
    fn leaf_cert(&self) -> Option<Cow<'_, [u8]>> {
        None
    }

    fn is_handshaking(&self) -> bool {
        matches!(
            self,
            Self {
                read_state: State::Handshake(_),
                ..
            } | Self {
                write_state: State::Handshake(_),
                ..
            }
        )
    }

    fn wants_read(&self) -> bool {
        match self.read_state {
            State::Handshake(_) | State::Closing(_) | State::Closed => true,
            State::Main(_) => self.read_len < BUF_SIZE as u8,
        }
    }

    fn wants_write(&self) -> bool {
        match self.write_state {
            State::Handshake(_) | State::Closing(_) | State::Closed => true,
            State::Main(_) => self.req_close || self.write_len > 0,
        }
    }

    fn process_new_packets(&mut self) -> Result<(), ChannelError> {
        Ok(())
    }

    fn send_close_notify(&mut self) {
        match self.write_state {
            State::Main(_) if self.write_len == 0 => self.write_state = State::Closing(0),
            State::Main(_) | State::Handshake(_) => self.req_close = true,
            _ => (),
        }
    }

    fn reader(&mut self) -> impl '_ + Read {
        DummyWrapperIO(self)
    }

    fn writer(&mut self) -> impl '_ + Write {
        DummyWrapperIO(self)
    }

    #[instrument(level = "debug", name = "DummyWrapper::read_tls", skip_all)]
    fn read_tls(&mut self, r: &mut dyn Read) -> IoResult<usize> {
        let mut n = 0;
        while self.wants_read() {
            trace!(state = ?self.read_state, "Reading in TLS");

            let mut arr = [0; BUF_SIZE];

            let state = match &mut self.read_state {
                State::Handshake(v) => {
                    let i = usize::from(*v);
                    let buf = &mut arr[..HANDSHAKE_MSG.len() - i];

                    let t = r.read(buf)?;
                    if t == 0 && !buf.is_empty() {
                        trace!("Read closed, read 0 bytes");
                        self.read_state = State::Closed;
                        break;
                    }
                    n += t;

                    assert_eq!(
                        &buf[..t],
                        &HANDSHAKE_MSG[i..i + t],
                        "received message mismatch."
                    );
                    *v += t as u8;
                    if usize::from(*v) == HANDSHAKE_MSG.len() {
                        self.read_state = State::Main(IoState::Byte);
                    }

                    continue;
                }
                State::Closing(v) => {
                    let i = usize::from(*v);
                    let buf = &mut arr[..CLOSE_MSG.len() - i];

                    let t = r.read(buf)?;
                    if t == 0 && !buf.is_empty() {
                        trace!("Read closed, read 0 bytes");
                        self.read_state = State::Closed;
                        break;
                    }
                    n += t;

                    assert_eq!(
                        &buf[..t],
                        &CLOSE_MSG[i..i + t],
                        "received message mismatch."
                    );
                    *v += t as u8;
                    if usize::from(*v) == CLOSE_MSG.len() {
                        trace!("Read closed, received close message");
                        self.read_state = State::Closed;
                    }

                    break;
                }
                State::Main(s) => s,
                State::Closed => break,
            };

            let t = r.read(&mut arr[..usize::from(BUF_SIZE as u8 - self.read_len)])?;
            if t == 0 {
                self.read_state = State::Closed;
                break;
            }
            n += t;

            let mut i = (self.read_ix + self.read_len) % BUF_SIZE as u8;

            let mut buf = &arr[..t];
            while let [b, ref r @ ..] = *buf {
                buf = r;
                let b = match (*state, b) {
                    (IoState::Byte, b @ 1..=254) => b,
                    (IoState::Byte, 255) => {
                        *state = IoState::Escape;
                        continue;
                    }
                    (IoState::Escape, 255) => {
                        *state = IoState::Byte;
                        255
                    }
                    (IoState::Escape, 1) => {
                        *state = IoState::Byte;
                        0
                    }
                    (IoState::Byte | IoState::Escape, 0) => {
                        let n = (buf.len() + 1).min(CLOSE_MSG.len());
                        assert_eq!(
                            &buf[..n - 1],
                            &CLOSE_MSG[1..n],
                            "received message mismatch."
                        );
                        self.read_state = State::Closing(n as u8);
                        break;
                    }
                    (s, b) => panic!("invalid read IO state ({s:?}, {b})"),
                };
                self.read_buf[usize::from(i)] = b;
                i = (i + 1) % BUF_SIZE as u8;
                self.read_len += 1;
            }
        }

        Ok(n)
    }

    #[instrument(level = "debug", name = "DummyWrapper::write_tls", skip_all)]
    fn write_tls(&mut self, w: &mut dyn Write) -> IoResult<usize> {
        let mut n = 0;
        while self.wants_write() {
            if self.write_len == 0 && take(&mut self.req_close) {
                self.write_state = State::Closing(0);
            }

            trace!(state = ?self.write_state, "Writing in TLS");

            let state = match &mut self.write_state {
                State::Handshake(v) => {
                    let i = usize::from(*v);
                    let buf = &HANDSHAKE_MSG[i..];

                    let t = w.write(buf)?;
                    if t == 0 && !buf.is_empty() {
                        trace!("Write closed, wrote 0 bytes");
                        self.write_state = State::Closed;
                        break;
                    }
                    n += t;

                    *v += t as u8;
                    if usize::from(*v) == HANDSHAKE_MSG.len() {
                        self.write_state = if take(&mut self.req_close) {
                            State::Closing(0)
                        } else {
                            State::Main(IoState::Byte)
                        };
                    }

                    continue;
                }
                State::Closing(v) => {
                    let i = usize::from(*v);
                    let buf = &CLOSE_MSG[i..];

                    let t = w.write(buf)?;
                    if t == 0 && !buf.is_empty() {
                        trace!("Write closed, wrote 0 bytes");
                        self.write_state = State::Closed;
                        break;
                    }
                    n += t;

                    *v += t as u8;
                    if usize::from(*v) == CLOSE_MSG.len() {
                        trace!("Write closed, sent close message");
                        self.write_state = State::Closed;
                    }

                    break;
                }
                State::Main(s) => s,
                State::Closed => break,
            };

            let mut arr = [0; const { BUF_SIZE * 2 }];
            let mut l = self.write_len;
            let mut ix = self.write_ix;
            let mut i = 0;
            while l > 0 {
                if i == 0 && matches!(state, IoState::Escape) {
                    arr[i] = match self.write_buf[usize::from(ix)] {
                        255 => 255,
                        0 => 1,
                        b => panic!("invalid write IO state ({:?}, {b})", state),
                    };
                    i += 1;
                } else {
                    match self.write_buf[usize::from(ix)] {
                        b @ 1..=254 => {
                            arr[i] = b;
                            i += 1;
                        }
                        255 => {
                            arr[i] = 255;
                            arr[i + 1] = 255;
                            i += 2;
                        }
                        0 => {
                            arr[i] = 255;
                            arr[i + 1] = 1;
                            i += 2;
                        }
                    }
                }
                ix = (ix + 1) % BUF_SIZE as u8;
                l -= 1;
            }

            let t = w.write(&arr[..i])?;
            if t == 0 {
                self.write_state = State::Closed;
                break;
            }
            n += t;

            let mut l = 0u8;
            for b in &arr[..t] {
                match (*state, b) {
                    (IoState::Byte, 1..=254) => (),
                    (IoState::Byte, 255) => {
                        *state = IoState::Escape;
                        continue;
                    }
                    (IoState::Escape, 1 | 255) => *state = IoState::Byte,
                    (s, b) => panic!("invalid write IO state ({s:?}, {b})"),
                }
                l += 1;
            }
            debug_assert!(l <= self.write_len, "{} > {}", l, self.write_len);
            self.write_ix = (self.write_ix + l) % BUF_SIZE as u8;
            self.write_len -= l;
        }

        Ok(n)
    }
}

impl ClientTLSLike for DummyWrapper {
    fn new(_: SocketAddr) -> Result<Self, ChannelError> {
        Ok(Self {
            read_buf: [0; BUF_SIZE],
            read_ix: 0,
            read_len: 0,
            read_state: State::Handshake(0),

            write_buf: [0; BUF_SIZE],
            write_ix: 0,
            write_len: 0,
            write_state: State::Handshake(0),

            req_close: false,
        })
    }
}

#[must_use]
pub fn transform_server_message(buf: &[u8]) -> Vec<u8> {
    let mut ret = Vec::with_capacity(HANDSHAKE_MSG.len() + buf.len() + CLOSE_MSG.len());
    ret.extend_from_slice(HANDSHAKE_MSG);
    for &b in buf {
        match b {
            b @ 1..=254 => ret.push(b),
            0 => ret.extend_from_slice(&[255, 1]),
            255 => ret.extend_from_slice(&[255, 255]),
        }
    }
    ret.extend_from_slice(CLOSE_MSG);
    ret
}

/// Do handshake protocol.
pub async fn do_handshake<T>(mut socket: Pin<&mut T>) -> IoResult<()>
where
    T: AsyncRead + AsyncWrite,
{
    let mut read_ix = 0;
    let mut write_ix = 0;

    poll_fn(|cx| {
        while write_ix < HANDSHAKE_MSG.len() {
            write_ix += match socket.as_mut().poll_write(cx, &HANDSHAKE_MSG[write_ix..]) {
                Pending => break,
                Ready(Err(e)) => return Ready(Err(e)),
                Ready(Ok(0)) => return Ready(Err(ErrorKind::UnexpectedEof.into())),
                Ready(Ok(n)) => n,
            };
        }

        let mut buf = [0; const { HANDSHAKE_MSG.len() }];
        while read_ix < HANDSHAKE_MSG.len() {
            let n = match socket.as_mut().poll_read(cx, &mut buf[read_ix..]) {
                Pending => break,
                Ready(Err(e)) => return Ready(Err(e)),
                Ready(Ok(0)) => return Ready(Err(ErrorKind::UnexpectedEof.into())),
                Ready(Ok(n)) => n,
            };

            if &buf[read_ix..read_ix + n] != &HANDSHAKE_MSG[read_ix..read_ix + n] {
                return Ready(Err(ErrorKind::UnexpectedEof.into()));
            }

            read_ix += n;
        }

        if read_ix >= HANDSHAKE_MSG.len() && write_ix >= HANDSHAKE_MSG.len() {
            Ready(Ok(()))
        } else {
            Pending
        }
    })
    .await
}

/// Do closing protocol and closes socket.
pub async fn do_close<T>(mut socket: Pin<&mut T>) -> IoResult<()>
where
    T: AsyncRead + AsyncWrite,
{
    let mut read_ix = 0;
    let mut write_ix = 0;

    poll_fn(|cx| {
        while write_ix < CLOSE_MSG.len() {
            write_ix += match socket.as_mut().poll_write(cx, &CLOSE_MSG[write_ix..]) {
                Pending => break,
                Ready(Err(e)) => return Ready(Err(e)),
                Ready(Ok(0)) => return Ready(Err(ErrorKind::UnexpectedEof.into())),
                Ready(Ok(n)) => n,
            };
        }

        let mut buf = [0; const { CLOSE_MSG.len() }];
        while read_ix < CLOSE_MSG.len() {
            let n = match socket.as_mut().poll_read(cx, &mut buf[read_ix..]) {
                Pending => break,
                Ready(Err(e)) => return Ready(Err(e)),
                Ready(Ok(0)) => return Ready(Err(ErrorKind::UnexpectedEof.into())),
                Ready(Ok(n)) => n,
            };

            if &buf[read_ix..read_ix + n] != &CLOSE_MSG[read_ix..read_ix + n] {
                return Ready(Err(ErrorKind::UnexpectedEof.into()));
            }

            read_ix += n;
        }

        if read_ix >= CLOSE_MSG.len() && write_ix >= CLOSE_MSG.len() {
            Ready(Ok(()))
        } else {
            Pending
        }
    })
    .await?;

    poll_fn(|cx| socket.as_mut().poll_close(cx)).await
}
