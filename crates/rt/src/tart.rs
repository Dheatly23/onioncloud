//! `onioncloud-tart` runtime.

use std::future::Future;
use std::io::Result as IoResult;
use std::net::SocketAddr;
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::Instant;

use futures_core::FusedFuture;
use onioncloud_tart::mpsc::{
    Receiver as MpscReceiver, Sender as MpscSender, make_channel as make_mpsc,
};
use onioncloud_tart::rt::{Socket, TaskHandle};
use onioncloud_tart::spsc::{
    Receiver as SpscReceiver, Sender as SpscSender, make_channel as make_spsc,
};
use onioncloud_tart::timer::Timer as TartTimer;
use pin_project::pin_project;

use crate::{
    CanSpawn, HasMpsc, HasNetwork, HasSpsc, HasTimer, Socket as SocketTrait, Timer as TimerTrait,
};

#[doc(no_inline)]
pub use onioncloud_tart::rt::{Executor, Runtime};

impl HasTimer for Runtime {
    type Timer = Timer;

    #[inline]
    fn make_timer(&self, time: Option<Instant>) -> Self::Timer {
        Timer {
            timer: match time {
                Some(t) => TartTimer::with_instant(self.clone(), t),
                None => TartTimer::always_resolve(self.clone()),
            },
            timeout: time,
        }
    }

    #[inline]
    fn current_time(&self) -> Instant {
        Runtime::get_time(self)
    }
}

impl HasSpsc for Runtime {
    type Sender<T: 'static + Send + Sync> = SpscSender<T>;
    type Receiver<T: 'static + Send + Sync> = SpscReceiver<T>;

    #[inline]
    fn make_spsc<T: 'static + Send + Sync>(
        &self,
        cap: usize,
    ) -> (Self::Sender<T>, Self::Receiver<T>) {
        make_spsc(cap)
    }
}

impl HasMpsc for Runtime {
    type Sender<T: 'static + Send + Sync> = MpscSender<T>;
    type Receiver<T: 'static + Send + Sync> = MpscReceiver<T>;

    #[inline]
    fn make_mpsc<T: 'static + Send + Sync>(
        &self,
        cap: usize,
    ) -> (Self::Sender<T>, Self::Receiver<T>) {
        make_mpsc(cap)
    }
}

impl SocketTrait for Socket {
    #[inline]
    fn peer_addr(&self) -> IoResult<SocketAddr> {
        Ok(self.addr())
    }
}

impl HasNetwork for Runtime {
    type Socket = Socket;

    #[inline]
    fn connect<'a>(
        &'a self,
        addrs: &'a [SocketAddr],
    ) -> impl 'a + Send + Sync + Future<Output = IoResult<Self::Socket>> {
        Runtime::connect(self, addrs)
    }
}

impl CanSpawn for Runtime {
    type Handle<T: 'static + Send> = TaskHandle<T>;

    #[inline]
    fn spawn<T: 'static + Send>(
        &self,
        task: impl 'static + Send + Sync + Future<Output = T>,
    ) -> Self::Handle<T> {
        Runtime::spawn(self, task)
    }
}

/// A timer.
#[derive(Debug)]
#[pin_project]
pub struct Timer {
    #[pin]
    timer: TartTimer,
    timeout: Option<Instant>,
}

impl Future for Timer {
    type Output = ();

    #[inline]
    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<()> {
        self.project().timer.poll(cx)
    }
}

impl FusedFuture for Timer {
    #[inline]
    fn is_terminated(&self) -> bool {
        self.timer.is_terminated()
    }
}

impl TimerTrait for Timer {
    #[inline]
    fn reset(self: Pin<&mut Self>) {
        let this = self.project();
        this.timer.reset();
        *this.timeout = None;
    }

    #[inline]
    fn set(self: Pin<&mut Self>, time: Instant) {
        let this = self.project();
        this.timer.set_instant(time);
        *this.timeout = Some(time);
    }

    #[inline]
    fn get_timeout(&self) -> Option<Instant> {
        self.timeout
    }
}
