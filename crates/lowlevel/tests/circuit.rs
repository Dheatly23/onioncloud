mod common;

use std::borrow::Cow;
use std::net::SocketAddr;
use std::num::NonZeroU32;
use std::pin::pin;
use std::sync::Arc;

use futures_util::{SinkExt as _, StreamExt as _};
use test_log::test;
use tracing::{info, instrument};

use onioncloud_lowlevel::cache::{Cached, CellCache, CellCacheExt, StandardCellCache};
use onioncloud_lowlevel::cell::FIXED_CELL_SIZE;
use onioncloud_lowlevel::cell::destroy::{Destroy, DestroyReason};
use onioncloud_lowlevel::cell::relay::data::RelayData;
use onioncloud_lowlevel::cell::relay::{IntoRelay, Relay, RelayEarly, RelayVersion};
use onioncloud_lowlevel::channel::controller::{UserConfig, UserControlMsg, UserController};
use onioncloud_lowlevel::channel::manager::SingleManager as ChannelManager;
use onioncloud_lowlevel::channel::{ChannelConfig, NewCircuit};
use onioncloud_lowlevel::circuit::NewStream;
use onioncloud_lowlevel::circuit::controller::dir::{DirConfig, DirControlMsg, DirController};
use onioncloud_lowlevel::circuit::manager::SingleManager as CircuitManager;
use onioncloud_lowlevel::crypto::onion::{
    OnionLayer as _, OnionLayerData, OnionLayerFast, RelayDigest as _,
};
use onioncloud_lowlevel::crypto::relay::RelayId;
use onioncloud_lowlevel::runtime::Runtime as _;
use onioncloud_lowlevel::runtime::test::TestExecutor;
use onioncloud_lowlevel::runtime::tokio::TokioRuntime;
use onioncloud_lowlevel::util::GenerationalData;
use onioncloud_lowlevel::util::cell_map::NewHandler;

use crate::common::{assert_cast, assert_cast_relay, get_relay_data, spawn};

struct Config {
    id: RelayId,
    addrs: Cow<'static, [SocketAddr]>,
    cache: Arc<StandardCellCache>,
}

impl ChannelConfig for Config {
    fn peer_id(&self) -> &RelayId {
        &self.id
    }

    fn peer_addrs(&self) -> Cow<'_, [SocketAddr]> {
        Cow::Borrowed(&self.addrs)
    }
}

impl UserConfig for Config {
    type Cache = Arc<StandardCellCache>;

    fn get_cache(&self) -> &Self::Cache {
        &self.cache
    }
}

#[test(tokio::test)]
#[ignore = "requires network access"]
#[instrument]
async fn test_circuit_create_fast() {
    let (id, addrs) = get_relay_data();

    let cache = Arc::<StandardCellCache>::default();

    let cfg = Config {
        id,
        addrs: addrs.into(),
        cache: cache.clone(),
    };
    let mut channel = pin!(ChannelManager::<UserController<_, _>>::new(
        &TokioRuntime,
        cfg
    ));

    let (recv, msg) = UserControlMsg::new_circuit();
    channel.as_mut().as_ref().send_control(msg).await.unwrap();

    {
        let NewCircuit {
            inner:
                NewHandler {
                    id:
                        GenerationalData {
                            inner: id,
                            generation,
                        },
                    receiver: recv,
                    sender: send,
                    ..
                },
            ..
        } = recv.await.unwrap().unwrap();
        let mut send = pin!(send);
        let mut recv = pin!(recv);

        let client = OnionLayerFast::new();
        send.send(cache.cache(GenerationalData::new(
            client.create_cell(id, &cache).into(),
            generation,
        )))
        .await
        .unwrap();
        let cell = Cached::map(recv.next().await.unwrap(), |v| v.into_inner());
        info!(command = cell.command, "recv cell");
        let OnionLayerData {
            mut encrypt,
            mut digest,
            ..
        } = client.derive_client(&assert_cast(cell)).unwrap();

        info!("circuit creation success");

        let mut cell = cache.cache(Relay::new(cache.get_cached(), id, 13, 1, &[]));
        digest.wrap_digest_forward((*cell).as_mut());
        encrypt.encrypt_forward((*cell).as_mut()).unwrap();
        send.send(Cached::map(cell, |c| {
            GenerationalData::new(c.into(), generation)
        }))
        .await
        .unwrap();

        let cell = Cached::map(recv.next().await.unwrap(), |v| v.into_inner());
        info!(command = cell.command, "recv cell");
        let mut cell = assert_cast::<Relay, _>(cell);
        encrypt.decrypt_backward((*cell).as_mut()).unwrap();
        digest.unwrap_digest_backward((*cell).as_mut()).unwrap();
        drop(cell);

        info!("stream creation success");

        send.send(cache.cache(GenerationalData::new(
            Destroy::new(cache.get_cached(), id, DestroyReason::None).into(),
            generation,
        )))
        .await
        .unwrap();

        while recv.next().await.is_some() {}
    }

    info!("channel shutdown success");

    channel
        .as_ref()
        .send_and_completion(UserControlMsg::Shutdown)
        .await
        .unwrap();
}

#[track_caller]
fn forward(layer: &mut OnionLayerData, cell: &mut impl AsMut<[u8; FIXED_CELL_SIZE]>) {
    let v = cell.as_mut();
    layer.encrypt.decrypt_forward(v).unwrap();
    layer.digest.unwrap_digest_forward(v).unwrap();
}

#[track_caller]
fn backward(layer: &mut OnionLayerData, cell: &mut impl AsMut<[u8; FIXED_CELL_SIZE]>) {
    let v = cell.as_mut();
    layer.digest.wrap_digest_backward(v);
    layer.encrypt.encrypt_backward(v).unwrap();
}

struct ConfigDir {
    cache: Arc<StandardCellCache>,
}

impl AsRef<Self> for ConfigDir {
    fn as_ref(&self) -> &Self {
        self
    }
}

impl DirConfig for ConfigDir {
    type Cache = Arc<StandardCellCache>;

    fn get_cache(&self) -> &Self::Cache {
        &self.cache
    }
}

#[test]
fn test_circuit_dir() {
    let cache = Arc::<StandardCellCache>::default();
    let mut exec = TestExecutor::default();

    let c = cache.clone();
    spawn(exec.runtime(), |rt| async move {
        let (send, recv_) = rt.spsc_make(8);
        let (send_, recv) = rt.mpsc_make(8);

        let circ_id = NonZeroU32::new(1).unwrap();
        let generation = 493226u64;
        let mut circ = pin!(CircuitManager::<DirController<_, _>>::with_params(
            &rt,
            ConfigDir { cache: c.clone() },
            4,
            GenerationalData::new(circ_id, generation),
            send_,
            recv_,
        ));

        let mut send = pin!(send);
        let mut recv = pin!(recv);

        let cell = Cached::map(recv.next().await.unwrap(), |c| c.into_inner());
        info!("received CREATE_FAST");
        let (mut layer, cell) = OnionLayerFast::derive_server_cached(&assert_cast(cell)).unwrap();
        send.send(Cached::map(cell, |c| {
            GenerationalData::new(c.into(), generation)
        }))
        .await
        .unwrap();

        info!("handshake finished!");

        let NewStream {
            inner:
                NewHandler {
                    id: sid,
                    receiver: recv_s,
                    sender: send_s,
                    ..
                },
            circ_id: cid,
            ..
        } = {
            let (recv, msg) = DirControlMsg::new_stream();
            circ.as_mut().as_ref().send_control(msg).await.unwrap();
            info!("new stream request sent");
            recv.await.unwrap().unwrap()
        };
        assert_eq!(circ_id, cid);

        let mut send_s = pin!(send_s);
        let mut recv_s = pin!(recv_s);

        {
            info!("sending data to server");
            static DATA: &[u8] = b"test123";
            let cell = <_>::try_into_relay_cached(
                cache.cache(RelayData::new(cache.get_cached(), sid.inner, DATA).unwrap()),
                circ_id,
                RelayVersion::V0,
            )
            .unwrap();
            send_s
                .send(Cached::map(cell, |c| {
                    GenerationalData::new(c.into(), sid.generation)
                }))
                .await
                .unwrap();

            let cell = Cached::map(recv.next().await.unwrap(), |c| c.into_inner());
            let mut cell = Cached::map_into::<Relay>(assert_cast::<RelayEarly, _>(cell));
            forward(&mut layer, &mut *cell);
            let cell = assert_cast_relay::<RelayData, _>(cell, RelayVersion::V0);
            assert_eq!(cell.stream, sid.inner);
            assert_eq!(cell.data(), DATA);
        }

        {
            info!("sending data to client");
            static DATA: &[u8] = b"test123";
            let mut cell = <_>::try_into_relay_cached(
                cache.cache(RelayData::new(cache.get_cached(), sid.inner, DATA).unwrap()),
                circ_id,
                RelayVersion::V0,
            )
            .unwrap();
            backward(&mut layer, &mut *cell);
            send.send(Cached::map(cell, |c| {
                GenerationalData::new(c.into(), generation)
            }))
            .await
            .unwrap();

            let cell = assert_cast_relay::<RelayData, _>(
                Cached::map(recv_s.next().await.unwrap(), |c| c.into_inner()),
                RelayVersion::V0,
            );
            assert_eq!(cell.stream, sid.inner);
            assert_eq!(cell.data(), DATA);
        }

        info!("waiting for DESTROY cell");
        recv.next().await.unwrap();
        info!("done!");
        send.close().await.unwrap();

        circ.as_ref().completion().await.unwrap();
    });

    exec.run_tasks_until_finished();
}
