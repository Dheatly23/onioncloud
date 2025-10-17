mod common;

use std::borrow::Cow;
use std::net::SocketAddr;
use std::num::NonZeroU32;
use std::sync::Arc;
use std::time::Duration;

use test_log::test;
use tracing::{info, instrument};

use onioncloud_lowlevel::cache::{Cachable, Cached, CellCache, CellCacheExt, StandardCellCache};
use onioncloud_lowlevel::cell::FIXED_CELL_SIZE;
use onioncloud_lowlevel::cell::destroy::{Destroy, DestroyReason};
use onioncloud_lowlevel::cell::relay::begin_dir::RelayBeginDir;
use onioncloud_lowlevel::cell::relay::connected::RelayConnected;
use onioncloud_lowlevel::cell::relay::data::RelayData;
use onioncloud_lowlevel::cell::relay::{IntoRelay, Relay, RelayEarly, RelayVersion};
use onioncloud_lowlevel::channel::controller::{UserConfig, UserControlMsg, UserController};
use onioncloud_lowlevel::channel::manager::ChannelManager;
use onioncloud_lowlevel::channel::{ChannelConfig, NewCircuit};
use onioncloud_lowlevel::circuit::NewStream;
use onioncloud_lowlevel::circuit::controller::dir::{DirConfig, DirControlMsg, DirController};
use onioncloud_lowlevel::crypto::onion::{
    OnionLayer as _, OnionLayerData, OnionLayerFast, RelayDigest as _,
};
use onioncloud_lowlevel::crypto::relay::RelayId;
use onioncloud_lowlevel::runtime::tokio::TokioRuntime;
use onioncloud_lowlevel::util::cell_map::NewHandler;
use onioncloud_lowlevel::util::circuit::TestController;

use crate::common::{assert_cast, assert_cast_relay, get_relay_data, receive_oneshot};

struct Config {
    id: RelayId,
    addrs: Vec<SocketAddr>,
    cache: Arc<dyn Send + Sync + CellCache>,
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
    fn get_cache(&self) -> Arc<dyn Send + Sync + CellCache> {
        self.cache.clone()
    }
}

#[test(tokio::test)]
#[ignore = "requires network access"]
#[instrument]
async fn test_circuit_create_fast() {
    let (id, addrs) = get_relay_data();

    let cache: Arc<dyn Send + Sync + CellCache> = Arc::<StandardCellCache>::default();

    let mut v = ChannelManager::<_, UserController<Config>>::new(TokioRuntime);

    let cfg = Config {
        id,
        addrs,
        cache: cache.clone(),
    };
    let mut channel = v.create(cfg, ());

    let (recv, msg) = UserControlMsg::new_circuit();
    channel.send_control(msg).await.unwrap();

    {
        let NewCircuit {
            inner:
                NewHandler {
                    id,
                    receiver: recv,
                    sender: send,
                    ..
                },
            ..
        } = recv.await.unwrap().unwrap();

        let client = OnionLayerFast::new();
        send.send_async(Cached::map_into(client.create_cell(id, &cache)))
            .await
            .unwrap();
        let cell = recv.recv_async().await.unwrap();
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
        send.send_async(Cached::map_into(cell)).await.unwrap();

        let cell = recv.recv_async().await.unwrap();
        info!(command = cell.command, "recv cell");
        let mut cell = assert_cast::<Relay, _>(cell);
        encrypt.decrypt_backward((*cell).as_mut()).unwrap();
        digest.unwrap_digest_backward((*cell).as_mut()).unwrap();
        drop(cell);

        info!("stream creation success");

        let cell = cache.cache(Destroy::new(cache.get_cached(), id, DestroyReason::None));
        send.send_async(Cached::map_into(cell)).await.unwrap();

        while recv.recv_async().await.is_ok() {}
    }

    info!("channel shutdown success");

    channel
        .send_and_completion(UserControlMsg::Shutdown)
        .await
        .unwrap();
}

#[track_caller]
fn forward(
    layer: &mut OnionLayerData,
    cell: &mut Cached<impl Cachable + AsMut<[u8; FIXED_CELL_SIZE]>, impl CellCache>,
) {
    let v = (**cell).as_mut();
    layer.encrypt.decrypt_forward(v).unwrap();
    layer.digest.unwrap_digest_forward(v).unwrap();
}

#[track_caller]
fn backward(
    layer: &mut OnionLayerData,
    cell: &mut Cached<impl Cachable + AsMut<[u8; FIXED_CELL_SIZE]>, impl CellCache>,
) {
    let v = (**cell).as_mut();
    layer.digest.wrap_digest_backward(v);
    layer.encrypt.encrypt_backward(v).unwrap();
}

struct ConfigDir {
    cache: Arc<dyn Send + Sync + CellCache>,
}

impl AsRef<Self> for ConfigDir {
    fn as_ref(&self) -> &Self {
        self
    }
}

impl DirConfig for ConfigDir {
    fn get_cache(&self) -> Arc<dyn Send + Sync + CellCache> {
        self.cache.clone()
    }
}

#[test]
fn test_circuit_dir() {
    let cache: Arc<dyn Send + Sync + CellCache> = Arc::<StandardCellCache>::default();

    let circ_id = NonZeroU32::new(1).unwrap();
    let mut v = TestController::<DirController<ConfigDir>>::new(
        ConfigDir {
            cache: cache.clone(),
        }
        .into(),
        circ_id,
        4,
    );

    let ret = v.process().unwrap();
    assert_eq!(ret.shutdown, None);
    info!("time: {:?} timeout: {:?}", v.cur_time(), v.timeout());
    info!(
        "parent pause: {} child pause: {}",
        ret.parent_cell_msg_pause, ret.child_cell_msg_pause
    );

    let (mut layer, cell) =
        OnionLayerFast::derive_server_cached(&assert_cast(v.recv_cell().unwrap())).unwrap();
    v.send_cell(Cached::map_into(cell));

    let ret = v.process().unwrap();
    assert_eq!(ret.shutdown, None);
    info!("time: {:?} timeout: {:?}", v.cur_time(), v.timeout());
    info!(
        "parent pause: {} child pause: {}",
        ret.parent_cell_msg_pause, ret.child_cell_msg_pause
    );

    assert!(
        !v.controller().is_init(),
        "circuit initialization is not finished"
    );
    info!("handshake finished!");

    let (recv, msg) = DirControlMsg::new_stream();
    v.submit_msg(msg);

    let ret = v.process().unwrap();
    assert_eq!(ret.shutdown, None);
    info!("time: {:?} timeout: {:?}", v.cur_time(), v.timeout());
    info!(
        "parent pause: {} child pause: {}",
        ret.parent_cell_msg_pause, ret.child_cell_msg_pause
    );

    let mut cell = Cached::map_into::<Relay>(assert_cast::<RelayEarly, _>(v.recv_cell().unwrap()));
    forward(&mut layer, &mut cell);
    let stream_id = assert_cast_relay::<RelayBeginDir, _>(cell, RelayVersion::V0).stream;
    info!(stream_id, "opening directory stream");

    let mut cell = cache.cache(
        RelayConnected::new_empty(cache.get_cached(), stream_id)
            .try_into_relay(circ_id, RelayVersion::V0)
            .unwrap(),
    );
    backward(&mut layer, &mut cell);
    v.send_cell(Cached::map_into(cell));

    let ret = v.process().unwrap();
    assert_eq!(ret.shutdown, None);
    info!("time: {:?} timeout: {:?}", v.cur_time(), v.timeout());
    info!(
        "parent pause: {} child pause: {}",
        ret.parent_cell_msg_pause, ret.child_cell_msg_pause
    );

    let NewStream {
        inner:
            NewHandler {
                id: sid,
                receiver: recv,
                sender: send,
                ..
            },
        circ_id: cid,
        ..
    } = receive_oneshot(recv).unwrap();
    assert_eq!(circ_id, cid);
    assert_eq!(NonZeroU32::from(stream_id), sid);

    {
        info!("sending data to server");
        static DATA: &[u8] = b"test123";
        send.try_send(
            cache.cache(
                RelayData::new(cache.get_cached(), stream_id, DATA)
                    .unwrap()
                    .try_into_relay(circ_id, RelayVersion::V0)
                    .unwrap()
                    .into(),
            ),
        )
        .unwrap();

        let ret = v.process().unwrap();
        assert_eq!(ret.shutdown, None);
        info!("time: {:?} timeout: {:?}", v.cur_time(), v.timeout());
        info!(
            "parent pause: {} child pause: {}",
            ret.parent_cell_msg_pause, ret.child_cell_msg_pause
        );

        let mut cell =
            Cached::map_into::<Relay>(assert_cast::<RelayEarly, _>(v.recv_cell().unwrap()));
        forward(&mut layer, &mut cell);
        let cell = assert_cast_relay::<RelayData, _>(cell, RelayVersion::V0);
        assert_eq!(cell.stream, stream_id);
        assert_eq!(cell.data(), DATA);
    }

    {
        info!("sending data to client");
        static DATA: &[u8] = b"test123";
        let mut cell = cache.cache(
            RelayData::new(cache.get_cached(), stream_id, DATA)
                .unwrap()
                .try_into_relay(circ_id, RelayVersion::V0)
                .unwrap(),
        );
        backward(&mut layer, &mut cell);
        v.send_cell(Cached::map_into(cell));

        let ret = v.process().unwrap();
        assert_eq!(ret.shutdown, None);
        info!("time: {:?} timeout: {:?}", v.cur_time(), v.timeout());
        info!(
            "parent pause: {} child pause: {}",
            ret.parent_cell_msg_pause, ret.child_cell_msg_pause
        );

        let cell = assert_cast_relay::<RelayData, _>(recv.try_recv().unwrap(), RelayVersion::V0);
        assert_eq!(cell.stream, stream_id);
        assert_eq!(cell.data(), DATA);
    }

    v.advance_time(Duration::from_secs(60));
    let ret = v.process().unwrap();
    assert_eq!(ret.shutdown, Some(DestroyReason::Finished));
}
