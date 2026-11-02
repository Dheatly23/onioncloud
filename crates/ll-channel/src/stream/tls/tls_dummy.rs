use std::borrow::Cow;
use std::io::{ErrorKind, Read, Result as IoResult, Write};
use std::mem::take;
use std::net::SocketAddr;

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
    fn read(&mut self, buf: &mut [u8]) -> IoResult<usize> {
        if buf.is_empty() {
            return Ok(0);
        } else if self.0.read_len == 0 {
            if matches!(self.0.read_state, State::Closed) {
                return Ok(0);
            }
            return Err(ErrorKind::WouldBlock.into());
        }

        let i = usize::from(self.0.read_ix);
        let n = usize::from(self.0.read_len)
            .min(BUF_SIZE - i)
            .min(buf.len());
        buf[..n].copy_from_slice(&self.0.read_buf[i..i + n]);
        self.0.read_ix = (self.0.read_ix + n as u8) % (BUF_SIZE as u8);
        self.0.read_len -= n as u8;
        Ok(n)
    }
}

impl Write for DummyWrapperIO<'_> {
    fn write(&mut self, buf: &[u8]) -> IoResult<usize> {
        if buf.is_empty() || matches!(self.0.write_state, State::Closed) {
            return Ok(0);
        } else if self.0.write_len == BUF_SIZE as u8
            || matches!(self.0.write_state, State::Handshake(_) | State::Closing(_))
            || self.0.req_close
        {
            return Err(ErrorKind::WouldBlock.into());
        }

        let i = usize::from((self.0.write_ix + self.0.write_len) % BUF_SIZE as u8);
        let n = usize::from(BUF_SIZE as u8 - self.0.write_len)
            .min(BUF_SIZE - i)
            .min(buf.len());
        self.0.write_buf[i..i + n].copy_from_slice(&buf[..n]);
        self.0.write_len += n as u8;
        Ok(n)
    }

    fn flush(&mut self) -> IoResult<()> {
        if matches!(self.0.write_state, State::Closed) || self.0.write_len == 0 {
            Ok(())
        } else {
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

    fn read_tls(&mut self, r: &mut dyn Read) -> IoResult<usize> {
        let mut n = 0;
        while self.wants_read() {
            let mut arr = [0; BUF_SIZE];

            let state = match &mut self.read_state {
                State::Handshake(v) => {
                    let i = usize::from(*v);
                    let buf = &mut arr[..HANDSHAKE_MSG.len() - i];

                    let t = r.read(buf)?;
                    if t == 0 && !buf.is_empty() {
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

    fn write_tls(&mut self, w: &mut dyn Write) -> IoResult<usize> {
        let mut n = 0;
        while self.wants_write() {
            if self.write_len == 0 && take(&mut self.req_close) {
                self.write_state = State::Closing(0);
            }

            let state = match &mut self.write_state {
                State::Handshake(v) => {
                    let i = usize::from(*v);
                    let buf = &HANDSHAKE_MSG[i..];

                    let t = w.write(buf)?;
                    if t == 0 && !buf.is_empty() {
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
                        self.write_state = State::Closed;
                        break;
                    }
                    n += t;

                    *v += t as u8;
                    if usize::from(*v) == CLOSE_MSG.len() {
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
