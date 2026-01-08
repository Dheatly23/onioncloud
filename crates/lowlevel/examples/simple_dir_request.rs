use std::borrow::Cow;
use std::env::{VarError, var};
use std::net::SocketAddr;
use std::pin::pin;
use std::sync::Arc;
use std::time::Duration;

use futures_util::{AsyncReadExt, AsyncWriteExt};
use tokio::time::{sleep, timeout};
use tracing::{error, info, warn};

use onioncloud_lowlevel::cache::StandardCellCache;
use onioncloud_lowlevel::cell::padding::{NegotiateCommand, NegotiateCommandV0};
use onioncloud_lowlevel::channel::ChannelConfig;
use onioncloud_lowlevel::channel::controller::{UserConfig, UserControlMsg, UserController};
use onioncloud_lowlevel::channel::manager::SingleManager as ChannelManager;
use onioncloud_lowlevel::circuit::controller::dir::{DirConfig, DirControlMsg, DirController};
use onioncloud_lowlevel::circuit::manager::SingleManager as CircuitManager;
use onioncloud_lowlevel::crypto::relay::{RelayId, from_str as relay_from_str};
use onioncloud_lowlevel::runtime::tokio::TokioRuntime;
use onioncloud_lowlevel::stream::from_new_stream;

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::builder()
                .with_default_directive(tracing::level_filters::LevelFilter::INFO.into())
                .from_env_lossy(),
        )
        .with_writer(std::io::stderr)
        .init();

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
        type Cache = Arc<StandardCellCache>;

        fn get_cache(&self) -> &Self::Cache {
            &self.cache
        }

        fn get_padding_param(&self, _: u16) -> NegotiateCommand {
            NegotiateCommand::V0(NegotiateCommandV0::Start {
                low: 1500,
                high: 2000,
            })
        }
    }

    let cache = Arc::<StandardCellCache>::default();
    let rt = TokioRuntime;

    info!("creating channel");

    let cfg = Config {
        id,
        addrs: addrs.into(),
        cache: cache.clone(),
    };
    let mut channel = pin!(ChannelManager::<UserController<_, _>>::new(&rt, cfg));

    struct ConfigDir {
        cache: Arc<StandardCellCache>,
    }

    impl DirConfig for ConfigDir {
        type Cache = Arc<StandardCellCache>;

        fn get_cache(&self) -> &Self::Cache {
            &self.cache
        }
    }

    info!("opening circuit");

    let cfg = ConfigDir {
        cache: cache.clone(),
    };
    let (new_circ, circuit) = CircuitManager::<DirController<_, _>>::new(&rt, cfg);
    let mut circuit = pin!(circuit);
    channel
        .as_mut()
        .as_ref()
        .send_control(UserControlMsg::NewCircuit(new_circ))
        .await
        .unwrap();

    info!("opening directory stream");

    let new_stream = {
        let (recv, msg) = DirControlMsg::new_stream();
        circuit.as_mut().as_ref().send_control(msg).await.unwrap();
        recv.await.expect("new stream result should exist").unwrap()
    };
    let mut stream = pin!(from_new_stream(cache.clone(), new_stream));

    info!("sleeping for 5 seconds");
    sleep(Duration::from_secs(5)).await;

    info!("sending request");

    // NOTE: Change request here.
    stream
        .write_all("GET /tor/keys/all HTTP/1.0\r\nContent-Encoding: identity\r\n\r\n".as_bytes())
        .await
        .unwrap();
    stream.flush().await.unwrap();

    info!("sleeping for 5 seconds");
    sleep(Duration::from_secs(5)).await;

    info!("reading response");

    let mut s = Vec::new();
    if timeout(Duration::from_secs(5), async {
        stream.read_to_end(&mut s).await.unwrap();
    })
    .await
    .is_err()
    {
        warn!("timed out");
    }

    let s = match String::from_utf8(s) {
        Ok(v) => v,
        Err(e) => {
            error!("UTF8 conversion error: {e}");
            String::new()
        }
    };

    info!("sleeping for 5 seconds");
    sleep(Duration::from_secs(5)).await;

    info!("starting graceful shutdown");

    stream.close().await.unwrap();
    circuit
        .as_ref()
        .send_and_completion(DirControlMsg::Shutdown)
        .await
        .unwrap();
    channel
        .as_ref()
        .send_and_completion(UserControlMsg::Shutdown)
        .await
        .unwrap();

    info!("shutdown successful");

    println!("{s}");
}
