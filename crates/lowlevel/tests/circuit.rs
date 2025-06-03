mod common;

use std::borrow::Cow;
use std::net::SocketAddr;
use std::sync::Arc;

use test_log::test;
use tracing::{info, instrument};

use onioncloud_lowlevel::cache::{Cached, CellCache, StandardCellCache, cast};
use onioncloud_lowlevel::cell::destroy::{Destroy, DestroyReason};
use onioncloud_lowlevel::cell::relay::Relay;
use onioncloud_lowlevel::channel::controller::{UserConfig, UserControlMsg, UserController};
use onioncloud_lowlevel::channel::manager::ChannelManager;
use onioncloud_lowlevel::channel::{ChannelConfig, NewCircuit};
use onioncloud_lowlevel::crypto::onion::{
    OnionLayer as _, OnionLayerData, OnionLayerFast, RelayDigest as _,
};
use onioncloud_lowlevel::crypto::relay::RelayId;
use onioncloud_lowlevel::runtime::tokio::TokioRuntime;

use crate::common::get_relay_data;

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
            id,
            receiver: recv,
            sender: send,
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
        } = client
            .derive_client(&cache.cache(cast(&mut Cached::map(cell, Some)).unwrap().unwrap()))
            .unwrap();

        info!("circuit creation success");

        let mut cell = cache.cache(Relay::new(cache.get_cached(), id, 13, 1, &[]));
        digest.wrap_digest_forward(&mut *cell);
        encrypt.encrypt_forward(cell.as_mut()).unwrap();
        send.send_async(Cached::map_into(cell)).await.unwrap();

        let cell = recv.recv_async().await.unwrap();
        info!(command = cell.command, "recv cell");
        let mut cell = cache.cache(
            cast::<Relay>(&mut Cached::map(cell, Some))
                .unwrap()
                .unwrap(),
        );
        encrypt.decrypt_backward(cell.as_mut()).unwrap();
        digest.unwrap_digest_backward(&mut *cell).unwrap();
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
