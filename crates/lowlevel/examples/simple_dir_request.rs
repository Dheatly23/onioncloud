use std::borrow::Cow;
use std::env::{VarError, var};
use std::net::SocketAddr;
use std::pin::pin;
use std::sync::Arc;
use std::time::Duration;

use futures_util::{AsyncReadExt, AsyncWriteExt};
use tracing::{info, warn};

use onioncloud_lowlevel::cache::{CellCache, StandardCellCache};
use onioncloud_lowlevel::channel::ChannelConfig;
use onioncloud_lowlevel::channel::controller::{UserConfig, UserControlMsg, UserController};
use onioncloud_lowlevel::channel::manager::ChannelManager;
use onioncloud_lowlevel::circuit::controller::dir::{DirConfig, DirControlMsg, DirController};
use onioncloud_lowlevel::circuit::manager::SingleManager;
use onioncloud_lowlevel::crypto::relay::{RelayId, from_str as relay_from_str};
use onioncloud_lowlevel::runtime::tokio::TokioRuntime;
use onioncloud_lowlevel::stream::DirStream;

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt::init();

    let id = match var("RELAY_ID") {
        Ok(v) => relay_from_str(&v).unwrap(),
        Err(VarError::NotPresent) => {
            warn!("skipping test: environment variable RELAY_ID not set");
            return;
        }
        Err(e) => panic!("{e}"),
    };
    let addrs = match var("RELAY_ADDRS") {
        Ok(v) => v
            .split(',')
            .map(|s| s.parse::<SocketAddr>().unwrap())
            .collect::<Vec<_>>(),
        Err(VarError::NotPresent) => {
            warn!("skipping test: environment variable RELAY_ADDRS not set");
            return;
        }
        Err(e) => panic!("{e}"),
    };

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
        fn get_cache(&self) -> Arc<dyn Send + Sync + CellCache> {
            self.cache.clone()
        }
    }

    let cache = Arc::<StandardCellCache>::default();

    let mut v = ChannelManager::<_, UserController<Config>>::new(TokioRuntime);

    info!("creating channel");

    let cfg = Config {
        id,
        addrs: addrs.into(),
        cache: cache.clone(),
    };
    let mut channel = v.create(cfg, ());

    struct ConfigDir {
        cache: Arc<dyn Send + Sync + CellCache>,
    }

    impl DirConfig for ConfigDir {
        fn get_cache(&self) -> Arc<dyn Send + Sync + CellCache> {
            self.cache.clone()
        }
    }

    info!("opening circuit");

    let cfg = ConfigDir {
        cache: cache.clone(),
    };
    let (new_circ, mut circuit) =
        SingleManager::<_, DirController<ConfigDir>>::new(TokioRuntime, cfg, ());
    channel
        .send_control(UserControlMsg::NewCircuit(new_circ))
        .await
        .unwrap();

    info!("opening directory stream");

    let new_stream = {
        let (recv, msg) = DirControlMsg::new_stream();
        circuit.into_ref().send_control(msg).await.unwrap();
        recv.await.expect("new stream result should exist").unwrap()
    };
    let mut stream = pin!(DirStream::new(cache.clone(), new_stream));

    info!("sending request");

    // NOTE: Change request here.
    stream
        .write_all("GET /tor/keys/all HTTP/1.0\r\nContent-Encoding: identity\r\n\r\n".as_bytes())
        .await
        .unwrap();
    stream.flush().await.unwrap();

    info!("reading response");

    let mut s = Vec::new();
    if tokio::time::timeout(Duration::from_secs(5), async {
        stream.read_to_end(&mut s).await.unwrap();
    })
    .await
    .is_err()
    {
        warn!("timed out");
    }
    info!("read response: {}", String::from_utf8_lossy(&s));
    drop(s);

    info!("starting graceful shutdown");

    stream.close().await.unwrap();
    drop(stream);
    circuit
        .into_ref()
        .send_and_completion(DirControlMsg::Shutdown)
        .await
        .unwrap();
    drop(circuit);
    channel
        .send_and_completion(UserControlMsg::Shutdown)
        .await
        .unwrap();
    drop(channel);

    info!("shutdown successful");
}
