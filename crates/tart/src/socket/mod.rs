//! Network Socket Emulation.
//!
//! Contains generic traits defining network socket handler.

pub mod emulation;

use std::future::Future;
use std::io::{ErrorKind, Result as IoResult};
use std::net::SocketAddr;
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::Instant;

use futures_io::{AsyncRead, AsyncWrite};

use crate::rt::Runtime;

/// Handler trait for network socket.
pub trait SocketHandler {
    /// Opens new socket.
    ///
    /// Using dynamic dispatch because type must be wrapped dynamically anyways.
    fn open(&mut self, args: OpenOpt<'_>) -> SocketOpener {
        let _ = args;
        Box::pin(Offline)
    }
}

/// Helper auto impl trait for socket.
pub trait SocketTrait: AsyncRead + AsyncWrite {}
impl<T: AsyncRead + AsyncWrite> SocketTrait for T {}

/// Socket connector future.
pub type SocketOpener = Pin<Box<dyn Send + Sync + Future<Output = IoResult<(SocketAddr, Socket)>>>>;
/// Socket type.
pub type Socket = Pin<Box<dyn Send + Sync + SocketTrait>>;

/// Arguments for [`SocketHandler::open`].
#[derive(Debug)]
#[non_exhaustive]
pub struct OpenOpt<'a> {
    /// Addresses to connect to.
    pub addrs: &'a [SocketAddr],
    /// Runtime that calls into.
    pub rt: &'a Runtime,
    /// Current time.
    pub time: Instant,
}

struct Offline;

impl Future for Offline {
    type Output = IoResult<(SocketAddr, Socket)>;

    fn poll(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<Self::Output> {
        Poll::Ready(Err(ErrorKind::NotConnected.into()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::cell::UnsafeCell;
    use std::cmp::Ordering;
    use std::collections::VecDeque;
    use std::io::{Error as IoError, IoSlice, IoSliceMut, Read, Write};
    use std::ops::{Deref, DerefMut};
    use std::pin::pin;
    use std::sync::atomic::{AtomicU8, Ordering::*};
    use std::task::{Waker, ready};
    use std::time::Duration;

    use futures_util::{AsyncReadExt, AsyncWriteExt, select_biased};
    use pin_project::pin_project;
    use test_log::test;
    use tracing::{info, instrument};

    use crate::rt::Executor;
    use crate::timer::Timer;
    use crate::utils::{ArcLike, run_test};

    #[test]
    fn test_socket_open() {
        #[instrument]
        fn test() {
            let mut executor = Executor::builder().build();
            let rt = executor.runtime();

            let rt_ = rt.clone();
            rt_.spawn(async move {
                let e = rt
                    .connect(&[([127, 0, 0, 1u8], 8000).into()])
                    .await
                    .expect_err("network should be offline");
                info!(error = %e, "connection error");
                assert_eq!(
                    e.kind(),
                    ErrorKind::NotConnected,
                    "error kind mismatch: {e}"
                );
            });

            executor.run();
        }

        run_test(test);
    }

    struct NetworkEchoEmulator;

    impl SocketHandler for NetworkEchoEmulator {
        fn open(&mut self, args: OpenOpt<'_>) -> SocketOpener {
            let rt = args.rt.clone();
            let addr = args.addrs.last().copied();
            Box::pin(async move {
                Timer::with_duration(rt.clone(), Duration::from_secs(285031)).await;
                let addr = addr.ok_or(ErrorKind::InvalidInput)?;
                Ok((addr, Box::pin(Echo::new(rt)) as Socket))
            })
        }
    }

    #[pin_project]
    struct Echo {
        buf: VecDeque<u8>,
        #[pin]
        timer: Timer,
    }

    fn timed_out(mut timer: Pin<&mut Timer>, cx: &mut Context<'_>) -> Poll<()> {
        let ret = timer.as_mut().poll(cx);
        if ret.is_ready() {
            timer.set_duration(Duration::from_secs(6 * 60 + 7));
        }
        ret
    }

    impl Echo {
        fn new(rt: Runtime) -> Self {
            Self {
                buf: VecDeque::new(),
                timer: Timer::with_duration(rt, Duration::from_secs(6 * 60 + 7)),
            }
        }
    }

    impl AsyncRead for Echo {
        fn poll_read(
            self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &mut [u8],
        ) -> Poll<IoResult<usize>> {
            let this = self.project();
            ready!(timed_out(this.timer, cx));

            Poll::Ready(match this.buf.read(buf) {
                Ok(0) if !buf.is_empty() => Err(IoError::new(
                    ErrorKind::UnexpectedEof,
                    "server does not have more data",
                )),
                v => v,
            })
        }

        fn poll_read_vectored(
            self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            bufs: &mut [IoSliceMut<'_>],
        ) -> Poll<IoResult<usize>> {
            let this = self.project();
            ready!(timed_out(this.timer, cx));

            let is_empty = bufs.iter().all(|v| v.is_empty());
            Poll::Ready(match this.buf.read_vectored(bufs) {
                Ok(0) if !is_empty => Err(IoError::new(
                    ErrorKind::UnexpectedEof,
                    "server does not have more data",
                )),
                v => v,
            })
        }
    }

    impl AsyncWrite for Echo {
        fn poll_write(
            self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<IoResult<usize>> {
            let this = self.project();
            ready!(timed_out(this.timer, cx));

            Poll::Ready(this.buf.write(buf))
        }

        fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<IoResult<()>> {
            let this = self.project();
            ready!(timed_out(this.timer, cx));

            Poll::Ready(Ok(()))
        }

        fn poll_close(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<IoResult<()>> {
            let this = self.project();
            ready!(timed_out(this.timer, cx));

            Poll::Ready(Ok(()))
        }

        fn poll_write_vectored(
            self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            bufs: &[IoSlice<'_>],
        ) -> Poll<IoResult<usize>> {
            let this = self.project();
            ready!(timed_out(this.timer, cx));

            Poll::Ready(this.buf.write_vectored(bufs))
        }
    }

    #[test]
    fn test_socket_echo() {
        #[instrument]
        fn test() {
            let mut executor = Executor::builder()
                .with_network(NetworkEchoEmulator)
                .build();
            let rt = executor.runtime();

            let rt_ = rt.clone();
            rt_.spawn(async move {
                let mut socket = {
                    select_biased! {
                        v = rt.connect(&[([127, 0, 0, 1u8], 8000).into()]) => pin!(v.unwrap()),
                        _ = Timer::with_duration(rt.clone(), Duration::from_secs(384146)) => panic!("socket opening timed out"),
                    }
                };

                let msg = b"Streng dich an, Nana!";

                for _ in 0..2 {
                    info!("writing into socket");
                    socket.as_mut().write_all(msg).await.unwrap();

                    info!("reading from socket");
                    let mut buf = vec![0; msg.len()];
                    socket.as_mut().read_exact(&mut buf).await.unwrap();
                    assert_eq!(buf, msg);
                }

                info!("done");
            });

            executor.run();
        }

        run_test(test);
    }

    #[test]
    fn test_socket_open_timeout() {
        #[instrument]
        fn test() {
            let mut executor = Executor::builder()
                .with_network(NetworkEchoEmulator)
                .build();
            let rt = executor.runtime();

            let rt_ = rt.clone();
            rt_.spawn(async move {
                let mut fut = pin!(rt.connect(&[([127, 0, 0, 1u8], 8000).into()]));
                select_biased! {
                    r = fut => panic!("opening socket should timeout, got {r:?} instead"),
                    _ = Timer::with_duration(rt.clone(), Duration::from_secs(269835)) => panic!("later timer fires before earlier timer"),
                    _ = Timer::with_duration(rt.clone(), Duration::from_secs(256895)) => panic!("later timer fires before earlier timer"),
                    _ = Timer::with_duration(rt.clone(), Duration::from_secs(225475)) => {}
                }
            });

            executor.run();
        }

        run_test(test);
    }

    #[test]
    fn test_socket_addr() {
        #[instrument]
        fn test() {
            let mut executor = Executor::builder()
                .with_network(NetworkEchoEmulator)
                .build();
            let rt = executor.runtime();

            let rt_ = rt.clone();
            rt_.spawn(async move {
                let addr = SocketAddr::from(([127, 0, 0, 1u8], 10000));
                let socket = rt
                    .connect(&[
                        ([127, 0, 0, 1u8], 8000).into(),
                        ([127, 0, 0, 1u8], 9000).into(),
                        addr,
                    ])
                    .await
                    .unwrap();
                assert_eq!(socket.addr(), addr);
            });

            executor.run();
        }

        run_test(test);
    }

    struct NetworkPingPongEmulator<F>(F);

    impl<
        Fut: 'static + Send + Sync + Future<Output = ()>,
        F: FnMut(Runtime, ServerHalfRead, ServerHalfWrite) -> Fut,
    > SocketHandler for NetworkPingPongEmulator<F>
    {
        fn open(&mut self, args: OpenOpt<'_>) -> SocketOpener {
            let Some(&addr) = args.addrs.last() else {
                return Box::pin(async { Err(ErrorKind::NotConnected.into()) });
            };

            let outer = ArcLike::new(PingPongOuter {
                lock: AtomicU8::new(0),
                inner: Default::default(),
            });
            let read = ServerHalfRead(outer.clone());
            let write = ServerHalfWrite(outer.clone());
            let client = ClientHalf(outer);

            let fut = (self.0)(args.rt.clone(), read, write);
            let rt = args.rt.clone();
            Box::pin(async move {
                rt.spawn(fut);
                Ok((addr, Box::pin(client) as Socket))
            })
        }
    }

    struct PingPongHalf {
        buf: [u8; 256],
        start: u8,
        end: u8,
        closed: bool,

        read_waker: Option<Waker>,
        write_waker: Option<Waker>,
        flush_waker: Option<Waker>,
    }

    impl Default for PingPongHalf {
        fn default() -> Self {
            Self {
                buf: [0; 256],
                start: 0,
                end: 0,
                closed: false,

                read_waker: None,
                write_waker: None,
                flush_waker: None,
            }
        }
    }

    fn register_waker(waker: &mut Option<Waker>, cx: &mut Context<'_>) {
        match waker {
            Some(w) => w.clone_from(cx.waker()),
            None => *waker = Some(cx.waker().clone()),
        }
    }

    impl PingPongHalf {
        fn read(&mut self, cx: &mut Context<'_>, buf: &mut [u8]) -> Poll<usize> {
            let n = match self.start.cmp(&self.end) {
                Ordering::Equal if self.closed => return Poll::Ready(0),
                Ordering::Equal => {
                    register_waker(&mut self.read_waker, cx);
                    return Poll::Pending;
                }
                Ordering::Less => {
                    let l = usize::from(self.end - self.start).min(buf.len());
                    buf[..l]
                        .copy_from_slice(&self.buf[self.start as usize..self.start as usize + l]);
                    self.start += l as u8;
                    l
                }
                Ordering::Greater => {
                    let l1 = self.buf.len() - self.start as usize;
                    if l1 >= buf.len() {
                        buf.copy_from_slice(
                            &self.buf[self.start as usize..self.start as usize + buf.len()],
                        );
                        self.start = self.start.wrapping_add(buf.len() as u8);
                        buf.len()
                    } else {
                        let (a, b) = buf.split_at_mut(l1);
                        a.copy_from_slice(&self.buf[self.start as usize..]);
                        let l2 = usize::from(self.end).min(b.len());
                        b[..l2].copy_from_slice(&self.buf[..l2]);
                        self.start = l2 as u8;
                        l1 + l2
                    }
                }
            };

            if n > 0 {
                if let Some(w) = self.write_waker.take() {
                    w.wake();
                }
                if self.start == self.end
                    && let Some(w) = self.flush_waker.take()
                {
                    w.wake();
                }
            }

            Poll::Ready(n)
        }

        fn poll_read(&mut self, cx: &mut Context<'_>, buf: &mut [u8]) -> Poll<IoResult<usize>> {
            match self.read(cx, buf) {
                Poll::Pending => Poll::Pending,
                Poll::Ready(v) => Poll::Ready(Ok(v)),
            }
        }

        fn poll_read_vectored(
            &mut self,
            cx: &mut Context<'_>,
            bufs: &mut [IoSliceMut<'_>],
        ) -> Poll<IoResult<usize>> {
            let mut n = 0;
            for b in bufs {
                if b.len() == 0 {
                    continue;
                }
                n += ready!(self.read(cx, b));
                if self.start == self.end {
                    break;
                }
            }
            Poll::Ready(Ok(n))
        }

        fn write(&mut self, cx: &mut Context<'_>, buf: &[u8]) -> Poll<usize> {
            if self.end.wrapping_add(1) == self.start {
                register_waker(&mut self.write_waker, cx);
                return Poll::Pending;
            }

            let n = match self.start.cmp(&self.end) {
                Ordering::Equal => {
                    let l = buf.len().min(self.buf.len() - 1);
                    self.buf[..l].copy_from_slice(&buf[..l]);
                    self.start = 0;
                    self.end = l as u8;
                    l
                }
                Ordering::Greater => {
                    let l = usize::from(self.start - self.end - 1).min(buf.len());
                    self.buf[self.end as usize..self.end as usize + l].copy_from_slice(&buf[..l]);
                    self.end += l as u8;
                    l
                }
                Ordering::Less if self.start == 0 => {
                    let l = (self.buf.len() - self.end as usize - 1).min(buf.len());
                    self.buf[self.end as usize..self.end as usize + l].copy_from_slice(&buf[..l]);
                    self.end += l as u8;
                    l
                }
                Ordering::Less => {
                    let l1 = self.buf.len() - self.end as usize;
                    if l1 > buf.len() {
                        self.buf[self.end as usize..self.end as usize + buf.len()]
                            .copy_from_slice(buf);
                        self.end += buf.len() as u8;
                        buf.len()
                    } else {
                        let (a, b) = buf.split_at(l1);
                        self.buf[self.end as usize..].copy_from_slice(a);
                        let l2 = usize::from(self.start - 1).min(b.len());
                        self.buf[..l2].copy_from_slice(&b[..l2]);
                        self.end = l2 as u8;
                        l1 + l2
                    }
                }
            };

            if n > 0 {
                if let Some(w) = self.read_waker.take() {
                    w.wake();
                }
            }

            Poll::Ready(n)
        }

        fn poll_write(&mut self, cx: &mut Context<'_>, buf: &[u8]) -> Poll<IoResult<usize>> {
            if self.closed {
                return Poll::Ready(Err(ErrorKind::BrokenPipe.into()));
            }
            match self.write(cx, buf) {
                Poll::Pending => Poll::Pending,
                Poll::Ready(v) => Poll::Ready(Ok(v)),
            }
        }

        fn poll_flush(&mut self, cx: &mut Context<'_>) -> Poll<IoResult<()>> {
            if self.closed {
                Poll::Ready(Err(ErrorKind::BrokenPipe.into()))
            } else if self.end == self.start {
                Poll::Ready(Ok(()))
            } else {
                register_waker(&mut self.flush_waker, cx);
                Poll::Pending
            }
        }

        fn poll_close(&mut self, _: &mut Context<'_>) -> Poll<IoResult<()>> {
            self.closed = true;
            if let Some(w) = self.read_waker.take() {
                w.wake();
            }
            Poll::Ready(Ok(()))
        }

        fn poll_write_vectored(
            &mut self,
            cx: &mut Context<'_>,
            bufs: &[IoSlice<'_>],
        ) -> Poll<IoResult<usize>> {
            if self.closed {
                return Poll::Ready(Err(ErrorKind::BrokenPipe.into()));
            }
            let mut n = 0;
            for b in bufs {
                if b.len() == 0 {
                    continue;
                }
                n += ready!(self.write(cx, b));
                if self.end.wrapping_add(1) == self.start {
                    break;
                }
            }
            Poll::Ready(Ok(n))
        }
    }

    #[derive(Default)]
    struct PingPongInner {
        client_server: PingPongHalf,
        server_client: PingPongHalf,
    }

    struct PingPongOuter {
        lock: AtomicU8,
        inner: UnsafeCell<PingPongInner>,
    }

    // SAFETY: PingPongOuter is send and sync.
    unsafe impl Send for PingPongOuter {}
    // SAFETY: PingPongOuter is send and sync.
    unsafe impl Sync for PingPongOuter {}

    impl PingPongOuter {
        fn lock(&self) -> Guard<'_> {
            if self.lock.compare_exchange(0, 1, Acquire, Relaxed).is_err() {
                panic!("acquiring ping pong twice");
            }

            Guard {
                lock: &self.lock,
                // SAFETY: We locked the value.
                inner: unsafe { &mut *self.inner.get() },
            }
        }
    }

    struct Guard<'a> {
        lock: &'a AtomicU8,
        inner: &'a mut PingPongInner,
    }

    impl Drop for Guard<'_> {
        fn drop(&mut self) {
            self.lock.store(0, Release);
        }
    }

    impl Deref for Guard<'_> {
        type Target = PingPongInner;

        fn deref(&self) -> &PingPongInner {
            self.inner
        }
    }

    impl DerefMut for Guard<'_> {
        fn deref_mut(&mut self) -> &mut PingPongInner {
            self.inner
        }
    }

    struct ServerHalfRead(ArcLike<PingPongOuter>);

    impl AsyncRead for ServerHalfRead {
        fn poll_read(
            self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &mut [u8],
        ) -> Poll<IoResult<usize>> {
            Pin::into_inner(self)
                .0
                .lock()
                .client_server
                .poll_read(cx, buf)
        }

        fn poll_read_vectored(
            self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            bufs: &mut [IoSliceMut<'_>],
        ) -> Poll<IoResult<usize>> {
            Pin::into_inner(self)
                .0
                .lock()
                .client_server
                .poll_read_vectored(cx, bufs)
        }
    }

    struct ServerHalfWrite(ArcLike<PingPongOuter>);

    impl AsyncWrite for ServerHalfWrite {
        fn poll_write(
            self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<IoResult<usize>> {
            Pin::into_inner(self)
                .0
                .lock()
                .server_client
                .poll_write(cx, buf)
        }

        fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<IoResult<()>> {
            Pin::into_inner(self).0.lock().server_client.poll_flush(cx)
        }

        fn poll_close(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<IoResult<()>> {
            Pin::into_inner(self).0.lock().server_client.poll_close(cx)
        }

        fn poll_write_vectored(
            self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            bufs: &[IoSlice<'_>],
        ) -> Poll<IoResult<usize>> {
            Pin::into_inner(self)
                .0
                .lock()
                .server_client
                .poll_write_vectored(cx, bufs)
        }
    }

    struct ClientHalf(ArcLike<PingPongOuter>);

    impl AsyncRead for ClientHalf {
        fn poll_read(
            self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &mut [u8],
        ) -> Poll<IoResult<usize>> {
            Pin::into_inner(self)
                .0
                .lock()
                .server_client
                .poll_read(cx, buf)
        }

        fn poll_read_vectored(
            self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            bufs: &mut [IoSliceMut<'_>],
        ) -> Poll<IoResult<usize>> {
            Pin::into_inner(self)
                .0
                .lock()
                .server_client
                .poll_read_vectored(cx, bufs)
        }
    }

    impl AsyncWrite for ClientHalf {
        fn poll_write(
            self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<IoResult<usize>> {
            Pin::into_inner(self)
                .0
                .lock()
                .client_server
                .poll_write(cx, buf)
        }

        fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<IoResult<()>> {
            Pin::into_inner(self).0.lock().client_server.poll_flush(cx)
        }

        fn poll_close(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<IoResult<()>> {
            Pin::into_inner(self).0.lock().client_server.poll_close(cx)
        }

        fn poll_write_vectored(
            self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            bufs: &[IoSlice<'_>],
        ) -> Poll<IoResult<usize>> {
            Pin::into_inner(self)
                .0
                .lock()
                .client_server
                .poll_write_vectored(cx, bufs)
        }
    }

    #[test]
    fn test_socket_ping_pong() {
        #[instrument]
        fn test() {
            static CLIENT_MSG: &[u8] = b"Nyon from the client!\n";
            static SERVER_MSG: &[u8] = b"Nyon back from the server!\n";

            let network = NetworkPingPongEmulator(
                |rt: Runtime, read: ServerHalfRead, write: ServerHalfWrite| async move {
                    let mut read = pin!(read);
                    let mut write = pin!(write);
                    let mut timer = pin!(Timer::always_resolve(rt));

                    {
                        info!("receiving client message");
                        let mut buf = vec![0; CLIENT_MSG.len()];
                        for _ in 0..10 {
                            read.as_mut().read_exact(&mut buf).await.unwrap();
                            assert_eq!(buf, CLIENT_MSG);
                            timer.as_mut().set_duration(Duration::from_secs(454309));
                            timer.as_mut().await;
                        }
                    }

                    info!("sending server message");
                    for _ in 0..10 {
                        write.as_mut().write_all(SERVER_MSG).await.unwrap();
                        timer.as_mut().set_duration(Duration::from_secs(539298));
                        timer.as_mut().await;
                    }

                    info!("closing server");
                    write.as_mut().close().await.unwrap();

                    info!("waiting for client to close");
                    assert_eq!(read.read(&mut [0]).await.unwrap(), 0);

                    info!("server done");
                },
            );
            let mut executor = Executor::builder().with_network(network).build();
            let rt = executor.runtime();

            let rt_ = rt.clone();
            rt_.spawn(async move {
                let mut socket = pin!(
                    rt.connect(&[([127, 0, 0, 1u8], 8000).into()])
                        .await
                        .unwrap()
                );

                info!("sending client message");
                for _ in 0..10 {
                    socket.as_mut().write_all(CLIENT_MSG).await.unwrap();
                }

                {
                    info!("receiving server message");
                    let mut buf = vec![0; SERVER_MSG.len()];
                    for _ in 0..10 {
                        socket.as_mut().read_exact(&mut buf).await.unwrap();
                        assert_eq!(buf, SERVER_MSG);
                    }
                }

                info!("closing client");
                socket.as_mut().close().await.unwrap();

                info!("waiting for server to close");
                assert_eq!(socket.read(&mut [0]).await.unwrap(), 0);

                info!("client done");
            });

            executor.run();
        }

        run_test(test);
    }
}
