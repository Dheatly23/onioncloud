//! Network Socket Emulation.
//!
//! Contains generic traits defining network socket handler.

pub mod emulation;

use std::future::Future;
use std::io::Result as IoResult;
use std::net::SocketAddr;
use std::pin::Pin;

use futures_io::{AsyncRead, AsyncWrite};

/// Handler trait for network socket.
pub trait SocketHandler {
    /// Opens new socket.
    ///
    /// Using dynamic dispatch because type must be wrapped dynamically anyways.
    fn open(&mut self, addrs: &[SocketAddr]) -> SocketOpener;
}

/// Helper auto impl trait for socket.
pub trait SocketTrait: AsyncRead + AsyncWrite {}
impl<T: AsyncRead + AsyncWrite> SocketTrait for T {}

/// Socket connector future.
pub type SocketOpener = Pin<Box<dyn Send + Sync + Future<Output = IoResult<(SocketAddr, Socket)>>>>;
/// Socket type.
pub type Socket = Pin<Box<dyn Send + Sync + SocketTrait>>;
