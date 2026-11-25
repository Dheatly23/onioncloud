//! Tokio runtime.

use std::future::Future;
use std::io::Result as IoResult;
use std::net::SocketAddr;
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::Instant;

use flume::r#async::{RecvStream, SendSink};
use flume::bounded;
use futures_core::FusedFuture;
use pin_project::pin_project;
use tokio::net::TcpStream;
use tokio::task::{JoinHandle, spawn};
use tokio::time::{Instant as TokioInstant, Sleep, sleep_until};
use tokio_util::compat::{Compat, TokioAsyncReadCompatExt as _};

use crate::{CanSpawn, HasMpsc, HasNetwork, HasSpsc, HasTimer, Socket, Timer as TimerTrait};

/// A tokio runtime.
#[derive(Debug, Default, Clone)]
#[non_exhaustive]
pub struct Runtime;

impl HasTimer for Runtime {
    type Timer = Timer;

    #[inline]
    fn make_timer(&self, time: Option<Instant>) -> Self::Timer {
        Timer(time.map(TokioInstant::from_std).map(sleep_until))
    }

    #[inline]
    fn current_time(&self) -> Instant {
        TokioInstant::now().into_std()
    }
}

impl HasSpsc for Runtime {
    type Sender<T: 'static + Send + Sync> = SendSink<'static, T>;
    type Receiver<T: 'static + Send + Sync> = RecvStream<'static, T>;

    #[inline]
    fn make_spsc<T: 'static + Send + Sync>(
        &self,
        cap: usize,
    ) -> (Self::Sender<T>, Self::Receiver<T>) {
        self.make_mpsc(cap)
    }
}

impl HasMpsc for Runtime {
    type Sender<T: 'static + Send + Sync> = SendSink<'static, T>;
    type Receiver<T: 'static + Send + Sync> = RecvStream<'static, T>;

    #[inline]
    fn make_mpsc<T: 'static + Send + Sync>(
        &self,
        cap: usize,
    ) -> (Self::Sender<T>, Self::Receiver<T>) {
        let (send, recv) = bounded(cap);
        (send.into_sink(), recv.into_stream())
    }
}

impl Socket for Compat<TcpStream> {
    #[inline]
    fn peer_addr(&self) -> IoResult<SocketAddr> {
        self.get_ref().peer_addr()
    }
}

impl HasNetwork for Runtime {
    type Socket = Compat<TcpStream>;

    #[inline]
    async fn connect(&self, addrs: &[SocketAddr]) -> IoResult<Self::Socket> {
        Ok(TcpStream::connect(addrs).await?.compat())
    }
}

impl CanSpawn for Runtime {
    type Handle<T: 'static + Send> = Handle<T>;

    #[inline]
    fn spawn<T: 'static + Send>(
        &self,
        task: impl 'static + Send + Sync + Future<Output = T>,
    ) -> Self::Handle<T> {
        Handle(spawn(task))
    }
}

/// A handle.
#[derive(Debug)]
#[pin_project]
pub struct Handle<T>(#[pin] JoinHandle<T>);

impl<T> Future for Handle<T> {
    type Output = T;

    #[inline]
    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<T> {
        match self.project().0.poll(cx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(v) => Poll::Ready(v.unwrap()),
        }
    }
}

/// A timer.
#[derive(Debug)]
#[pin_project]
pub struct Timer(#[pin] Option<Sleep>);

impl Future for Timer {
    type Output = ();

    #[inline]
    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<()> {
        match self.project().0.as_pin_mut() {
            Some(f) => f.poll(cx),
            None => Poll::Ready(()),
        }
    }
}

impl FusedFuture for Timer {
    #[inline]
    fn is_terminated(&self) -> bool {
        false
    }
}

impl TimerTrait for Timer {
    #[inline]
    fn reset(mut self: Pin<&mut Self>) {
        Pin::set(&mut self, Self(None));
    }

    #[inline]
    fn set(self: Pin<&mut Self>, time: Instant) {
        let time = TokioInstant::from_std(time);
        let mut t = self.project().0;
        let Some(f) = t.as_mut().as_pin_mut() else {
            t.set(Some(sleep_until(time)));
            return;
        };
        f.reset(time);
    }

    #[inline]
    fn get_timeout(&self) -> Option<Instant> {
        Some(self.0.as_ref()?.deadline().into_std())
    }
}
