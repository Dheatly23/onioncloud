//! Channel handle trait definition.

use std::error::Error;
use std::fmt::{Debug, Formatter, Result as FmtResult};
use std::io::{IoSlice, IoSliceMut, Read, Result as IoResult, Write};
use std::marker::PhantomData;
use std::net::SocketAddr;
use std::pin::Pin;
use std::task::Context;
use std::time::Instant;

use crate::error::ChannelError;
use crate::stream::Stream;

/// Channel handler trait.
pub trait ChannelHandle<R> {
    /// Error type.
    type Error: Error + From<ChannelError>;

    /// General handle.
    ///
    /// It is guaranteed to be eventually called by channel controller after calling other methods.
    /// It will be called when channel controller is polled.
    /// It may be called multiple times within the same poll call,
    /// use [`Handle::is_same_poll`] to optimize it.
    fn handle(self: Pin<&mut Self>, args: Handle<R>) -> Result<Return, Self::Error>;

    /// Shutdown handle.
    fn shutdown(self: Pin<&mut Self>, args: ShutdownHandle<R, Self::Error>) {
        let _ = args;
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

impl<R> Read for Handle<'_, '_, R> {
    #[inline]
    fn read(&mut self, buf: &mut [u8]) -> IoResult<usize> {
        // SAFETY: Stream is not moved.
        let stream = unsafe { Pin::into_inner_unchecked(self.stream.as_mut()) };
        stream.read(buf)
    }

    #[inline]
    fn read_vectored(&mut self, bufs: &mut [IoSliceMut<'_>]) -> IoResult<usize> {
        // SAFETY: Stream is not moved.
        let stream = unsafe { Pin::into_inner_unchecked(self.stream.as_mut()) };
        stream.read_vectored(bufs)
    }
}

impl<R> Write for Handle<'_, '_, R> {
    #[inline]
    fn write(&mut self, buf: &[u8]) -> IoResult<usize> {
        // SAFETY: Stream is not moved.
        let stream = unsafe { Pin::into_inner_unchecked(self.stream.as_mut()) };
        stream.write(buf)
    }

    #[inline]
    fn write_vectored(&mut self, bufs: &[IoSlice<'_>]) -> IoResult<usize> {
        // SAFETY: Stream is not moved.
        let stream = unsafe { Pin::into_inner_unchecked(self.stream.as_mut()) };
        stream.write_vectored(bufs)
    }

    #[inline]
    fn flush(&mut self) -> IoResult<()> {
        // SAFETY: Stream is not moved.
        let stream = unsafe { Pin::into_inner_unchecked(self.stream.as_mut()) };
        stream.flush()
    }
}

impl<'b, R> Handle<'_, 'b, R> {
    /// Gets async context.
    #[inline]
    #[must_use]
    pub fn cx(&mut self) -> &mut Context<'b> {
        self.cx
    }

    /// Gets current time.
    #[inline]
    #[must_use]
    pub fn time(&self) -> Instant {
        self.time
    }

    /// Gets runtime.
    #[inline]
    #[must_use]
    pub fn runtime(&self) -> &R {
        self.rt
    }

    /// Gets peer address.
    #[inline]
    #[must_use]
    pub fn peer_addr(&self) -> SocketAddr {
        self.stream.peer_addr()
    }

    /// Checks if it's in the same poll cycle.
    #[inline]
    #[must_use]
    pub fn is_same_poll(&self) -> bool {
        self.is_same_poll
    }

    /// Checks if timeout has expired.
    #[inline]
    #[must_use]
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

impl<R> Default for HandleBuilder<'_, '_, R> {
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
    ///
    /// # Panics
    ///
    /// Panics if it has been set.
    #[inline]
    pub fn cx(&mut self, cx: &'a mut Context<'b>) -> &mut Self {
        assert!(self.cx.is_none(), "cx has already been set");
        self.cx = Some(cx);
        self
    }

    /// Sets network stream. **REQUIRED**
    ///
    /// # Panics
    ///
    /// Panics if it has been set.
    #[inline]
    pub fn stream(&mut self, stream: Pin<&'a mut dyn Stream>) -> &mut Self {
        assert!(self.stream.is_none(), "stream has already been set");
        self.stream = Some(stream);
        self
    }

    /// Sets current time. **REQUIRED**
    ///
    /// # Panics
    ///
    /// Panics if it has been set.
    #[inline]
    pub fn time(&mut self, time: Instant) -> &mut Self {
        assert!(self.time.is_none(), "time has already been set");
        self.time = Some(time);
        self
    }

    /// Sets runtime. **REQUIRED**
    ///
    /// # Panics
    ///
    /// Panics if it has been set.
    #[inline]
    pub fn runtime(&mut self, rt: &'a R) -> &mut Self {
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

/// Shutdown handle arguments.
///
/// Used as argument of [`ChannelHandle::shutdown`].
pub struct ShutdownHandle<'a, 'b, R, E> {
    /// Context.
    cx: &'a mut Context<'b>,

    /// Current time.
    time: Instant,

    /// Runtime.
    rt: &'a R,

    /// Shutdown cause.
    ty: ShutdownCause<&'a E>,

    _phantom: PhantomData<*mut u8>,
}

/// Shutdown cause.
#[derive(Debug)]
#[non_exhaustive]
pub enum ShutdownCause<E> {
    /// Error happened.
    Error(E),
    /// Socket unexpectedly closed.
    SocketClosed,
    /// Graceful shutdown requested.
    GracefulShutdown,
}

impl<'a, 'b, R, E> ShutdownHandle<'a, 'b, R, E> {
    /// Gets async context.
    #[inline]
    #[must_use]
    pub fn cx(&mut self) -> &mut Context<'b> {
        self.cx
    }

    /// Gets current time.
    #[inline]
    #[must_use]
    pub fn time(&self) -> Instant {
        self.time
    }

    /// Gets runtime.
    #[inline]
    #[must_use]
    pub fn runtime(&self) -> &R {
        self.rt
    }

    /// Gets shutdown cause.
    #[inline]
    #[must_use]
    pub fn cause(&self) -> &ShutdownCause<&'a E> {
        &self.ty
    }
}

/// [`ShutdownHandle`] builder.
#[must_use]
pub struct ShutdownHandleBuilder<'a, 'b, R, E> {
    /// Context.
    cx: Option<&'a mut Context<'b>>,

    /// Current time.
    time: Option<Instant>,

    /// Runtime.
    rt: Option<&'a R>,

    /// Shutdown type.
    ty: Option<ShutdownCause<&'a E>>,

    built: bool,

    _phantom: PhantomData<*mut u8>,
}

impl<R, E> Default for ShutdownHandleBuilder<'_, '_, R, E> {
    fn default() -> Self {
        Self {
            cx: None,
            time: None,
            rt: None,
            ty: None,
            built: false,
            _phantom: PhantomData,
        }
    }
}

impl<'a, 'b, R, E> ShutdownHandleBuilder<'a, 'b, R, E> {
    /// Sets async context. **REQUIRED**
    ///
    /// # Panics
    ///
    /// Panics if it has been set.
    #[inline]
    pub fn cx(&mut self, cx: &'a mut Context<'b>) -> &mut Self {
        assert!(self.cx.is_none(), "cx has already been set");
        self.cx = Some(cx);
        self
    }

    /// Sets current time. **REQUIRED**
    ///
    /// # Panics
    ///
    /// Panics if it has been set.
    #[inline]
    pub fn time(&mut self, time: Instant) -> &mut Self {
        assert!(self.time.is_none(), "time has already been set");
        self.time = Some(time);
        self
    }

    /// Sets runtime. **REQUIRED**
    ///
    /// # Panics
    ///
    /// Panics if it has been set.
    #[inline]
    pub fn runtime(&mut self, rt: &'a R) -> &mut Self {
        assert!(self.rt.is_none(), "runtime has already been set");
        self.rt = Some(rt);
        self
    }

    /// Sets shutdown cause. **REQUIRED**
    ///
    /// # Panics
    ///
    /// Panics if it has been set.
    #[inline]
    pub fn cause(&mut self, ty: ShutdownCause<&'a E>) -> &mut Self {
        assert!(self.ty.is_none(), "shutdown causehas already been set");
        self.ty = Some(ty);
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
    pub fn build(&mut self) -> ShutdownHandle<'a, 'b, R, E> {
        assert!(!self.built, "builder must not be reused");
        self.built = true;

        ShutdownHandle {
            cx: self.cx.take().expect(REQ_MSG),
            time: self.time.take().expect(REQ_MSG),
            rt: self.rt.take().expect(REQ_MSG),
            ty: self.ty.take().expect(REQ_MSG),
            _phantom: PhantomData,
        }
    }
}

static REQ_MSG: &str = "required field is not set";
