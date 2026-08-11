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
}
