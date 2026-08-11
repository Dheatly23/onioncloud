//! Network Socket Emulation.
//!
//! Contains generic traits defining network socket handler.

pub mod emulation;

use std::future::Future;
use std::io::{ErrorKind, Result as IoResult};
use std::net::SocketAddr;
use std::pin::Pin;
use std::task::{Context, Poll};

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

    use std::collections::VecDeque;
    use std::io::{Error as IoError, IoSlice, IoSliceMut, Read, Write};
    use std::pin::pin;
    use std::task::ready;
    use std::time::Duration;

    use futures_util::{AsyncReadExt, AsyncWriteExt, select_biased};
    use pin_project::pin_project;
    use test_log::test;
    use tracing::{info, instrument};

    use crate::rt::Executor;
    use crate::timer::Timer;
    use crate::utils::run_test;

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
}
