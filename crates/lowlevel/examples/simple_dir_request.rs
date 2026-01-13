use std::borrow::Cow;
use std::io::{IoSlice, Result as IoResult};
use std::net::SocketAddr;
use std::pin::{Pin, pin};
use std::ptr::from_mut;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;

use clap::{ArgAction, Parser};
use futures_io::{AsyncRead, AsyncWrite};
use futures_util::{FutureExt, select_biased};
use http_body_util::{BodyExt, Empty};
use hyper::body::Bytes;
use hyper::client::conn::http1::Builder;
use hyper::rt::{Read as HyperRead, ReadBufCursor, Write as HyperWrite};
use hyper::{Request, Uri, Version};
use pin_project::pin_project;
use tokio::spawn;
use tokio::time::{sleep, timeout};
use tracing::{debug, error, info, warn};

use onioncloud_lowlevel::cache::StandardCellCache;
use onioncloud_lowlevel::cell::padding::{NegotiateCommand, NegotiateCommandV0};
use onioncloud_lowlevel::channel::ChannelConfig;
use onioncloud_lowlevel::channel::controller::{UserConfig, UserControlMsg, UserController};
use onioncloud_lowlevel::channel::manager::SingleManager as ChannelManager;
use onioncloud_lowlevel::circuit::controller::dir::{DirConfig, DirControlMsg, DirController};
use onioncloud_lowlevel::circuit::manager::SingleManager as CircuitManager;
use onioncloud_lowlevel::crypto::relay::{RelayId, from_str as relay_from_str};
use onioncloud_lowlevel::runtime::tokio::TokioRuntime;
use onioncloud_lowlevel::stream::{DirStreamTy, from_new_stream};

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

struct ConfigDir {
    cache: Arc<StandardCellCache>,
}

impl DirConfig for ConfigDir {
    type Cache = Arc<StandardCellCache>;

    fn get_cache(&self) -> &Self::Cache {
        &self.cache
    }
}

/// Connect to directory cache and fetch HTTP request.
#[derive(Parser)]
#[command(about)]
struct Args {
    /// Relay ID.
    #[arg(long, env = "RELAY_ID", value_parser = relay_from_str)]
    relay_id: RelayId,

    /// Relay socket addresses.
    ///
    /// Value is comma separated addresses.
    #[arg(long, env = "RELAY_ADDRS", required(true), value_delimiter(','))]
    relay_addrs: Vec<SocketAddr>,

    /// URL to be fetched.
    #[arg(default_value = "/tor/keys/all")]
    url: Uri,
}

#[tokio::main]
async fn main() {
    let Args {
        relay_id: id,
        relay_addrs: addrs,
        url,
    } = Args::parse();

    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::builder()
                .with_default_directive(tracing::level_filters::LevelFilter::INFO.into())
                .from_env_lossy(),
        )
        .with_writer(std::io::stderr)
        .init();

    let cache = Arc::<StandardCellCache>::default();
    let rt = TokioRuntime;

    info!("creating channel");

    let cfg = Config {
        id,
        addrs: addrs.into(),
        cache: cache.clone(),
    };
    let mut channel = pin!(ChannelManager::<UserController<_, _>>::new(&rt, cfg));

    info!("opening circuit");

    let cfg = ConfigDir {
        cache: cache.clone(),
    };
    let (new_circ, circuit) = CircuitManager::<DirController<_, _>>::new(&rt, cfg);
    channel
        .as_mut()
        .as_ref()
        .send_control(UserControlMsg::NewCircuit(new_circ))
        .await
        .unwrap();

    let s = {
        let mut r = channel.as_mut().as_ref();
        select_biased! {
            res = r.completion().fuse() => {
                res.unwrap();
                panic!("channel unexpectedly closed");
            },
            s = handle_circ(&cache, circuit, url).fuse() => s,
        }
    };

    channel
        .as_ref()
        .send_and_completion(UserControlMsg::Shutdown)
        .await
        .unwrap();

    info!("shutdown successful");

    println!("{s}");
}

async fn handle_circ(
    cache: &Arc<StandardCellCache>,
    circuit: CircuitManager<DirController<TokioRuntime, ConfigDir>>,
    url: Uri,
) -> String {
    let mut circuit = pin!(circuit);

    info!("opening directory stream");

    let new_stream = {
        let (recv, msg) = DirControlMsg::new_stream();
        circuit.as_mut().as_ref().send_control(msg).await.unwrap();
        recv.await.expect("new stream result should exist").unwrap()
    };
    let stream = from_new_stream(cache.clone(), new_stream);

    let s = {
        let mut r = circuit.as_mut().as_ref();
        select_biased! {
            res = r.completion().fuse() => {
                res.unwrap();
                panic!("circuit unexpectedly closed");
            },
            s = handle_stream(stream, url).fuse() => s,
        }
    };

    circuit
        .as_ref()
        .send_and_completion(DirControlMsg::Shutdown)
        .await
        .unwrap();

    s
}

async fn handle_stream(
    stream: DirStreamTy<TokioRuntime, Arc<StandardCellCache>>,
    url: Uri,
) -> String {
    info!("sleeping for 5 seconds");
    sleep(Duration::from_secs(5)).await;

    info!("sending request");

    let (mut send_req, conn) = Builder::new()
        .writev(true)
        .handshake(Box::pin(Wrapper(stream)))
        .await
        .unwrap();

    spawn(async move {
        if let Err(e) = conn.await {
            error!("error in HTTP connection: {e}");
        }
    });

    let mut body = Vec::new();
    let fut = async {
        send_req.ready().await.unwrap();
        let req = Request::builder()
            .version(Version::HTTP_10)
            .method("GET")
            .uri(url)
            .header("Content-Encoding", "identity")
            .body(Empty::<Bytes>::new())
            .unwrap();
        let res = send_req.send_request(req).await.unwrap();

        info!(version = ?res.version(), status = res.status().as_u16(), "response read");
        for (k, v) in res.headers().iter() {
            let k = AsRef::<str>::as_ref(k);
            if let Ok(v) = v.to_str() {
                info!("response header: {k}: {v:?}");
            } else {
                info!("response header: {k}: {:?}", AsRef::<[u8]>::as_ref(v));
            }
        }

        info!("reading response body");

        let mut b = res.into_body();
        while let Some(v) = b.frame().await {
            let v = v.unwrap();
            if let Some(v) = v.data_ref() {
                debug!("read {} bytes", v.len());
                body.extend_from_slice(&v);
            }
        }

        info!("done reading response body");
    };
    if timeout(Duration::from_secs(30), fut).await.is_err() {
        warn!("timed out");
    }

    let s = match String::from_utf8(body) {
        Ok(v) => v,
        Err(e) => {
            error!("UTF8 conversion error: {e}");
            String::new()
        }
    };

    info!("sleeping for 5 seconds");
    sleep(Duration::from_secs(5)).await;

    info!("starting graceful shutdown");

    s
}

#[pin_project]
struct Wrapper<T>(#[pin] T);

impl<T: AsyncRead> HyperRead for Wrapper<T> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        mut buf: ReadBufCursor<'_>,
    ) -> Poll<IoResult<()>> {
        // SAFETY: poll_read should not read buffer content.
        let b = unsafe { &mut *(from_mut(buf.as_mut()) as *mut [u8]) };
        let n = match self.project().0.poll_read(cx, b)? {
            Poll::Pending => return Poll::Pending,
            Poll::Ready(n) => n,
        };
        // SAFETY: n bytes has been written.
        unsafe {
            buf.advance(n);
        }
        Poll::Ready(Ok(()))
    }
}

impl<T: AsyncWrite> HyperWrite for Wrapper<T> {
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<IoResult<usize>> {
        self.project().0.poll_write(cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<IoResult<()>> {
        self.project().0.poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<IoResult<()>> {
        self.project().0.poll_close(cx)
    }

    fn poll_write_vectored(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[IoSlice<'_>],
    ) -> Poll<IoResult<usize>> {
        self.project().0.poll_write_vectored(cx, bufs)
    }
}
