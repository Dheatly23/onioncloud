//! Channel handle trait definition.

use std::error::Error;
use std::fmt::{Debug, Formatter, Result as FmtResult};
use std::io::{Error as IoError, ErrorKind, IoSlice, IoSliceMut, Read, Result as IoResult, Write};
use std::marker::PhantomData;
use std::net::SocketAddr;
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::Instant;

use crate::stream::Stream;

/// Channel handler trait.
pub trait ChannelHandle<R> {
    /// Error type.
    type Error: Error + From<IoError>;

    /// General handle.
    ///
    /// It is guaranteed to be eventually called by channel controller after calling other methods.
    /// It will be called when channel controller is polled.
    /// It may be called multiple times within the same poll call,
    /// use [`Handle::is_same_poll`] to optimize it.
    fn handle(self: Pin<&mut Self>, args: Handle<R>) -> Result<Return, Self::Error>;

    /// Sets peer address.
    ///
    /// This will be called when setting up circuit handle for the first time.
    fn set_peer_addr(self: Pin<&mut Self>, peer_addr: SocketAddr) -> Result<(), Self::Error> {
        let _ = peer_addr;
        Ok(())
    }
}

/// Channel handle parameters.
pub struct Handle<'a, 'b, R> {
    /// Context.
    cx: &'a mut Context<'b>,

    /// Stream.
    stream: Pin<&'a mut dyn Stream>,

    /// Current time.
    time: Instant,

    /// Runtime.
    rt: &'a R,

    /// Is same poll cycle?
    is_same_poll: bool,

    /// Is timeout.
    is_timeout: bool,

    _phantom: PhantomData<*mut u8>,
}

impl<R: Debug> Debug for Handle<'_, '_, R> {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        f.debug_struct("Handle")
            .field("cx", self.cx)
            .field("runtime", self.rt)
            .field("time", &self.time)
            .field("is_same_poll", &self.is_same_poll)
            .field("is_timeout", &self.is_timeout)
            .finish_non_exhaustive()
    }
}

#[inline]
fn poll_wrap<T>(v: Poll<IoResult<T>>) -> IoResult<T> {
    match v {
        Poll::Ready(v) => v,
        Poll::Pending => Err(ErrorKind::WouldBlock.into()),
    }
}

impl<R> Read for Handle<'_, '_, R> {
    #[inline]
    fn read(&mut self, buf: &mut [u8]) -> IoResult<usize> {
        poll_wrap(self.stream.as_mut().poll_read(self.cx, buf))
    }

    #[inline]
    fn read_vectored(&mut self, bufs: &mut [IoSliceMut<'_>]) -> IoResult<usize> {
        poll_wrap(self.stream.as_mut().poll_read_vectored(self.cx, bufs))
    }
}

impl<R> Write for Handle<'_, '_, R> {
    #[inline]
    fn write(&mut self, buf: &[u8]) -> IoResult<usize> {
        poll_wrap(self.stream.as_mut().poll_write(self.cx, buf))
    }

    #[inline]
    fn write_vectored(&mut self, bufs: &[IoSlice<'_>]) -> IoResult<usize> {
        poll_wrap(self.stream.as_mut().poll_write_vectored(self.cx, bufs))
    }

    #[inline]
    fn flush(&mut self) -> IoResult<()> {
        poll_wrap(self.stream.as_mut().poll_flush(self.cx))
    }
}

impl<'a, 'b, R> Handle<'a, 'b, R> {
    /// Gets async context.
    #[inline]
    pub fn cx(&mut self) -> &mut Context<'b> {
        self.cx
    }

    /// Gets current time.
    #[inline]
    pub fn time(&self) -> Instant {
        self.time
    }

    /// Gets runtime.
    #[inline]
    pub fn runtime(&self) -> &R {
        self.rt
    }

    /// Gets peer address.
    #[inline]
    pub fn peer_addr(&self) -> SocketAddr {
        self.stream.peer_addr()
    }

    /// Checks if it's in the same poll cycle.
    #[inline]
    pub fn is_same_poll(&self) -> bool {
        self.is_same_poll
    }

    /// Checks if timeout has expired.
    #[inline]
    pub fn is_timeout(&self) -> bool {
        self.is_timeout
    }
}

/// [`Handle`] builder.
#[must_use]
pub struct HandleBuilder<'a, 'b, R> {
    /// Context.
    cx: Option<&'a mut Context<'b>>,

    /// Stream.
    stream: Option<Pin<&'a mut dyn Stream>>,

    /// Current time.
    time: Option<Instant>,

    /// Runtime.
    rt: Option<&'a R>,

    /// Is same poll cycle?
    is_same_poll: bool,

    /// Is timeout.
    is_timeout: bool,

    built: bool,

    _phantom: PhantomData<*mut u8>,
}

impl<'a, 'b, R> Default for HandleBuilder<'a, 'b, R> {
    fn default() -> Self {
        Self {
            cx: None,
            stream: None,
            time: None,
            rt: None,
            is_same_poll: false,
            is_timeout: false,
            built: false,
            _phantom: PhantomData,
        }
    }
}

impl<'a, 'b, R> HandleBuilder<'a, 'b, R> {
    /// Sets async context. **REQUIRED**
    #[inline]
    pub fn cx(&mut self, cx: &'a mut Context<'b>) -> &mut Self {
        assert!(self.cx.is_none(), "cx has already been set");
        self.cx = Some(cx);
        self
    }

    /// Sets network stream. **REQUIRED**
    #[inline]
    pub fn stream(&mut self, stream: Pin<&'a mut dyn Stream>) -> &mut Self {
        assert!(self.stream.is_none(), "stream has already been set");
        self.stream = Some(stream);
        self
    }

    /// Sets current time. **REQUIRED**
    #[inline]
    pub fn time(&mut self, time: Instant) -> &mut Self {
        assert!(self.time.is_none(), "time has already been set");
        self.time = Some(time);
        self
    }

    /// Sets runtime. **REQUIRED**
    #[inline]
    pub fn runtime(&mut self, rt: &'a mut R) -> &mut Self {
        assert!(self.rt.is_none(), "runtime has already been set");
        self.rt = Some(rt);
        self
    }

    /// Sets `is_same_poll`.
    #[inline]
    pub fn is_same_poll(&mut self, v: bool) -> &mut Self {
        self.is_same_poll = v;
        self
    }

    /// Sets `is_timeout`.
    #[inline]
    pub fn is_timeout(&mut self, v: bool) -> &mut Self {
        self.is_timeout = v;
        self
    }

    /// Builds [`Handle`].
    ///
    /// Builder **should not** be reused afterwards.
    ///
    /// # Panics
    ///
    /// Panics if any of the required fields is not set.
    #[inline]
    #[must_use]
    pub fn build(&mut self) -> Handle<'a, 'b, R> {
        assert!(!self.built, "builder must not be reused");
        self.built = true;

        const REQ_MSG: &str = "required field is not set";
        Handle {
            cx: self.cx.take().expect(REQ_MSG),
            stream: self.stream.take().expect(REQ_MSG),
            time: self.time.take().expect(REQ_MSG),
            rt: self.rt.take().expect(REQ_MSG),
            is_same_poll: self.is_same_poll,
            is_timeout: self.is_timeout,
            _phantom: PhantomData,
        }
    }
}

/// Channel handler return value.
#[derive(Debug)]
#[must_use]
pub struct Return {
    /// Set to `true` to initiate shutdown sequence.
    ///
    /// Once shutdown is signalled, the handler will be dropped.
    pub is_shutdown: bool,

    /// Timeout epoch.
    ///
    /// If set to [`None`], timeout will be reset and never expires.
    pub timeout: Option<Instant>,

    _phantom: PhantomData<*mut u8>,
}

impl Return {
    /// Creates new [`Return`].
    #[inline]
    pub fn new<R>(handle: &Handle<R>) -> Self {
        let _ = handle;
        Self {
            is_shutdown: false,
            timeout: None,
            _phantom: PhantomData,
        }
    }

    /// Sets shutdown flag.
    #[inline]
    pub fn with_shutdown(mut self) -> Self {
        self.is_shutdown = true;
        self
    }

    /// Sets timeout.
    #[inline]
    pub fn with_timeout(mut self, timeout: Option<Instant>) -> Self {
        self.timeout = timeout;
        self
    }
}
