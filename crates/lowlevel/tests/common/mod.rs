use std::any::type_name;
use std::env::var;
use std::net::SocketAddr;
use std::pin::pin;
use std::task::{Context, Poll, Waker};

use futures_channel::oneshot::Receiver;

use onioncloud_lowlevel::cache::{Cachable, Cached, CellCache, CellCacheExt, cast};
use onioncloud_lowlevel::cell::relay::{Relay, RelayLike, TryFromRelay, cast as cast_relay};
use onioncloud_lowlevel::cell::{Cell, TryFromCell};
use onioncloud_lowlevel::crypto::relay::{RelayId, from_str as relay_from_str};

pub(crate) fn get_relay_data() -> (RelayId, Vec<SocketAddr>) {
    (
        relay_from_str(&var("RELAY_ID").unwrap()).unwrap(),
        var("RELAY_ADDRS")
            .unwrap()
            .split(',')
            .map(|s| s.parse::<SocketAddr>().unwrap())
            .collect::<Vec<_>>(),
    )
}

#[allow(dead_code)]
pub(crate) fn assert_cast<T: Cachable + TryFromCell, C: CellCache + Clone>(
    cell: Cached<Cell, C>,
) -> Cached<T, C> {
    let mut cell = Cached::map(cell, Some);
    let Some(ret) = cast::<T>(&mut cell).unwrap() else {
        let cell = Cached::transpose(cell).expect("cell must not be dropped");
        panic!(
            "expected {}, got unknown cell with command {}",
            type_name::<T>(),
            cell.command
        );
    };
    Cached::cache(&cell).cache(ret)
}

#[allow(dead_code)]
pub(crate) fn assert_cast_relay<T: Cachable + TryFromRelay, C: CellCache + Clone>(
    cell: Cached<impl Cachable + Into<Relay>, C>,
) -> Cached<T, C> {
    let mut cell = Cached::map(cell, |v| Some(v.into()));
    let Some(ret) = cast_relay::<T>(&mut cell).unwrap() else {
        let cell = Cached::transpose(cell).expect("cell must not be dropped");
        panic!(
            "expected {}, got unknown cell with command {}",
            type_name::<T>(),
            cell.command()
        );
    };
    Cached::cache(&cell).cache(ret)
}

#[allow(dead_code)]
pub(crate) fn receive_oneshot<T>(recv: Receiver<T>) -> T {
    let Poll::Ready(v) = pin!(recv).poll(&mut Context::from_waker(&Waker::noop())) else {
        panic!("receive must succeed");
    };
    v.expect("receiver is cancelled")
}
