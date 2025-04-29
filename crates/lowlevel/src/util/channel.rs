use std::borrow::Cow;
use std::collections::VecDeque;
use std::io::{ErrorKind, IoSlice, IoSliceMut, Read, Result as IoResult, Write};
use std::time::{Duration, Instant};

use crate::channel::controller::{ChannelController, ControlMsg, Timeout};
use crate::channel::{ChannelInput, CircuitMap, Stream};

pub struct TestController<C: ChannelController> {
    stream: TestStream,
    time: Instant,
    timeout: Option<Instant>,
    controller: C,
    circ_map: CircuitMap<C::Cell, C::CircMeta>,
    ctrl_msgs: Vec<C::ControlMsg>,
}

impl<C: ChannelController> TestController<C> {
    pub fn new(controller: C, link_cert: impl Into<Cow<'static, [u8]>>) -> Self {
        Self {
            stream: TestStream {
                link_cert: link_cert.into(),
                send: VecDeque::new(),
                recv: VecDeque::new(),
                send_eof: false,
                recv_eof: false,
            },
            controller,
            circ_map: CircuitMap::new(),
            time: Instant::now(),
            timeout: None,
            ctrl_msgs: Vec::new(),
        }
    }

    pub fn circ_map(&mut self) -> &mut CircuitMap<C::Cell, C::CircMeta> {
        &mut self.circ_map
    }

    pub fn cur_time(&self) -> Instant {
        self.time
    }

    pub fn timeout(&self) -> Option<Instant> {
        self.timeout
    }

    pub fn advance_time(&mut self, dur: Duration) {
        self.time += dur;
    }

    pub fn send_stream(&mut self) -> &mut VecDeque<u8> {
        &mut self.stream.send
    }

    pub fn recv_stream(&mut self) -> &mut VecDeque<u8> {
        &mut self.stream.recv
    }

    pub fn close_send(&mut self) {
        self.stream.send_eof = true;
    }

    pub fn close_recv(&mut self) {
        self.stream.recv_eof = true;
    }

    pub fn submit_msg(&mut self, msg: C::ControlMsg) {
        self.ctrl_msgs.push(msg);
    }

    pub fn process(&mut self) -> Result<ProcessedChannelOutput, C::Error> {
        let mut ret = if self.timeout.is_some_and(|t| t >= self.time) {
            self.timeout = None;
            self.controller.handle((
                Timeout,
                ChannelInput::new(&mut self.stream, None, &mut self.circ_map, self.time),
            ))
        } else {
            self.controller.handle(ChannelInput::new(
                &mut self.stream,
                None,
                &mut self.circ_map,
                self.time,
            ))
        }?;

        for m in self.ctrl_msgs.drain(..) {
            if ret.shutdown {
                break;
            }

            ret = self.controller.handle((
                ControlMsg(m),
                ChannelInput::new(&mut self.stream, None, &mut self.circ_map, self.time),
            ))?;
        }

        self.timeout = ret.timeout;
        Ok(ProcessedChannelOutput {
            shutdown: ret.shutdown,
        })
    }
}

#[non_exhaustive]
pub struct ProcessedChannelOutput {
    pub shutdown: bool,
}

struct TestStream {
    send: VecDeque<u8>,
    recv: VecDeque<u8>,
    send_eof: bool,
    recv_eof: bool,
    link_cert: Cow<'static, [u8]>,
}

impl Read for TestStream {
    fn read(&mut self, buf: &mut [u8]) -> IoResult<usize> {
        match self.send.read(buf) {
            Ok(0) if !self.send_eof && !buf.is_empty() => Err(ErrorKind::WouldBlock.into()),
            r => r,
        }
    }

    fn read_vectored(&mut self, bufs: &mut [IoSliceMut<'_>]) -> IoResult<usize> {
        match self.send.read_vectored(bufs) {
            Ok(0) if !self.send_eof && bufs.iter().any(|b| !b.is_empty()) => {
                Err(ErrorKind::WouldBlock.into())
            }
            r => r,
        }
    }

    fn read_to_end(&mut self, buf: &mut Vec<u8>) -> IoResult<usize> {
        if self.send_eof {
            self.send.read_to_end(buf)
        } else {
            self.send.clear();
            Err(ErrorKind::WouldBlock.into())
        }
    }

    fn read_to_string(&mut self, buf: &mut String) -> IoResult<usize> {
        if self.send_eof {
            self.send.read_to_string(buf)
        } else {
            self.send.clear();
            Err(ErrorKind::WouldBlock.into())
        }
    }

    fn read_exact(&mut self, buf: &mut [u8]) -> IoResult<()> {
        match self.send.read_exact(buf) {
            Err(e) if !self.send_eof && e.kind() == ErrorKind::UnexpectedEof => {
                Err(ErrorKind::WouldBlock.into())
            }
            r => r,
        }
    }
}

impl Write for TestStream {
    fn write(&mut self, buf: &[u8]) -> IoResult<usize> {
        if self.recv_eof {
            return Ok(0);
        }
        self.recv.write(buf)
    }

    fn flush(&mut self) -> IoResult<()> {
        Ok(())
    }

    fn write_vectored(&mut self, bufs: &[IoSlice<'_>]) -> IoResult<usize> {
        if self.recv_eof {
            return Ok(0);
        }
        self.recv.write_vectored(bufs)
    }
}

impl Stream for TestStream {
    fn link_cert(&self) -> Option<&[u8]> {
        Some(&self.link_cert[..])
    }
}
