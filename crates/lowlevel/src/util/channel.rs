use std::borrow::Cow;
use std::collections::VecDeque;
use std::io::{ErrorKind, IoSlice, IoSliceMut, Read, Result as IoResult, Write};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use crate::channel::controller::ChannelController;
use crate::channel::{CellMsg, ChannelInput, CircuitMap, ControlMsg, Stream, Timeout};

/// Test controller.
///
/// Useful for testing [`ChannelController`].
pub struct TestController<C: ChannelController> {
    stream: TestStream,
    time: Instant,
    timeout: Option<Instant>,
    controller: C,
    circ_map: CircuitMap<C::Cell, C::CircMeta>,
    cell_msg_pause: bool,
    ctrl_msgs: Vec<C::ControlMsg>,
}

impl<C: ChannelController> TestController<C> {
    /// Create new [`TestController`].
    ///
    /// # Parameters
    /// - `controller` : Channel controller to be tested.
    /// - `link_cert` : Link certificate.
    pub fn new(
        config: Arc<impl 'static + Send + Sync + AsRef<C::Config>>,
        peer_addr: SocketAddr,
        link_cert: impl Into<Cow<'static, [u8]>>,
    ) -> Self {
        let cfg = (*config).as_ref();
        let circ_map = CircuitMap::new(C::channel_cap(cfg), C::channel_aggregate_cap(cfg));

        Self {
            stream: TestStream {
                peer_addr,
                link_cert: link_cert.into(),
                send: VecDeque::new(),
                recv: VecDeque::new(),
                send_eof: false,
                recv_eof: false,
            },
            controller: C::new(config),
            circ_map,
            cell_msg_pause: false,
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
        let mut empty_handle = false;

        loop {
            let mut has_event = false;

            if self.timeout.as_ref().is_some_and(|t| *t <= self.time) {
                self.timeout = None;
                // Event: timeout
                self.controller.handle(Timeout)?;
                has_event = true;
            }

            for m in self.ctrl_msgs.drain(..) {
                // Event: control message
                self.controller.handle(ControlMsg(m))?;
                has_event = true;
            }

            while !self.cell_msg_pause {
                let Ok(m) = self.circ_map.try_recv() else {
                    break;
                };

                // Event: cell message
                self.cell_msg_pause = self.controller.handle(CellMsg(m))?.0;
                has_event = true;
            }

            if has_event || !empty_handle {
                let ret = self.controller.handle((
                    ChannelInput::new(&mut self.stream, self.time),
                    &mut self.circ_map,
                ))?;
                empty_handle = true;
                let old_pause = self.cell_msg_pause;
                self.cell_msg_pause = ret.cell_msg_pause;
                self.timeout = ret.timeout;

                if ret.shutdown {
                    return Ok(ProcessedChannelOutput {
                        shutdown: true,
                        cell_msg_pause: self.cell_msg_pause,
                    });
                } else if self.timeout.is_some() || (old_pause && !self.cell_msg_pause) {
                    // Repoll
                    continue;
                }
            }

            return Ok(ProcessedChannelOutput {
                shutdown: false,
                cell_msg_pause: self.cell_msg_pause,
            });
        }
    }
}

/// Wrapper type for [`ChannelOutput`].
#[non_exhaustive]
pub struct ProcessedChannelOutput {
    /// [`true`] if controller request for shutdown.
    pub shutdown: bool,

    /// [`true`] if cell messages should not be send while controller is processing.
    pub cell_msg_pause: bool,
}

struct TestStream {
    send: VecDeque<u8>,
    recv: VecDeque<u8>,
    send_eof: bool,
    recv_eof: bool,
    link_cert: Cow<'static, [u8]>,
    peer_addr: SocketAddr,
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

    fn peer_addr(&self) -> &SocketAddr {
        &self.peer_addr
    }
}
