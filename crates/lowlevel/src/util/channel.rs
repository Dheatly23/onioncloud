use std::borrow::Cow;
use std::collections::VecDeque;
use std::io::{ErrorKind, IoSlice, IoSliceMut, Read, Result as IoResult, Write};
use std::time::{Duration, Instant};

use crate::channel::controller::{ChannelController, ControlMsg, Timeout};
use crate::channel::{ChannelInput, CircuitMap, Stream};

/// Test controller.
///
/// Useful for testing [`ChannelController`].
pub struct TestController<C: ChannelController> {
    stream: TestStream,
    time: Instant,
    timeout: Option<Instant>,
    controller: C,
    circ_map: CircuitMap<C::Cell, C::CircMeta>,
    ctrl_msgs: Vec<C::ControlMsg>,
}

impl<C: ChannelController> TestController<C> {
    /// Create new [`TestController`].
    ///
    /// # Parameters
    /// - `controller` : Channel controller to be tested.
    /// - `link_cert` : Link certificate.
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

    /// Get reference to controller.
    pub fn controller(&mut self) -> &mut C {
        &mut self.controller
    }

    /// Get reference to [`CircuitMap`].
    pub fn circ_map(&mut self) -> &mut CircuitMap<C::Cell, C::CircMeta> {
        &mut self.circ_map
    }

    /// Get current time.
    pub fn cur_time(&self) -> Instant {
        self.time
    }

    /// Get timeout value (if any).
    pub fn timeout(&self) -> Option<Instant> {
        self.timeout
    }

    /// Advance time.
    pub fn advance_time(&mut self, dur: Duration) {
        self.time += dur;
    }

    /// Get reference to send stream.
    ///
    /// Stream is [`Read`] by controller.
    pub fn send_stream(&mut self) -> &mut VecDeque<u8> {
        &mut self.stream.send
    }

    /// Get reference to receive stream.
    ///
    /// Stream is [`Write`] by controller.
    pub fn recv_stream(&mut self) -> &mut VecDeque<u8> {
        &mut self.stream.recv
    }

    /// Close sending half of pipe.
    pub fn close_send(&mut self) {
        self.stream.send_eof = true;
    }

    /// Close receiving half of pipe.
    pub fn close_recv(&mut self) {
        self.stream.recv_eof = true;
    }

    /// Submit control message.
    pub fn submit_msg(&mut self, msg: C::ControlMsg) {
        self.ctrl_msgs.push(msg);
    }

    /// Run controller handler.
    pub fn process(&mut self) -> Result<ProcessedChannelOutput, C::Error> {
        let mut ret = if self.timeout.as_ref().is_some_and(|t| *t <= self.time) {
            self.timeout = None;
            // Event: timeout
            self.controller.handle((
                Timeout,
                ChannelInput::new(&mut self.stream, None, &mut self.circ_map, self.time),
            ))
        } else {
            // No particular event
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

            // Event: control message
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

/// Wrapper type for [`ChannelOutput`](`crate::channel::ChannelOutput`).
#[non_exhaustive]
pub struct ProcessedChannelOutput {
    /// [`true`] if controller request for shutdown.
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
