mod common;

use std::borrow::Cow;
use std::convert::Infallible;
use std::io::ErrorKind;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{Error as AnyError, Result as AnyResult};
use test_log::test;
use tokio::time::sleep;
use tracing::{debug, info, instrument, warn};

use onioncloud_lowlevel::cache::{CellCache, StandardCellCache};
use onioncloud_lowlevel::cell::dispatch::{CellReader, CellType, WithCellConfig};
use onioncloud_lowlevel::cell::versions::Versions;
use onioncloud_lowlevel::cell::writer::CellWriter;
use onioncloud_lowlevel::cell::{Cell, CellHeader, FixedCell, cast};
use onioncloud_lowlevel::channel::controller::{
    ChannelController, UserConfig, UserControlMsg, UserController,
};
use onioncloud_lowlevel::channel::manager::ChannelManager;
use onioncloud_lowlevel::channel::{
    CellMsg, CellMsgPause, ChannelConfig, ChannelInput, ChannelOutput, CircuitMap, ControlMsg,
    Timeout,
};
use onioncloud_lowlevel::crypto::relay::RelayId;
use onioncloud_lowlevel::errors;
use onioncloud_lowlevel::linkver::StandardLinkver;
use onioncloud_lowlevel::runtime::tokio::TokioRuntime;
use onioncloud_lowlevel::util::TestController;
use onioncloud_lowlevel::util::sans_io::Handle;

use crate::common::get_relay_data;

#[derive(Default)]
struct LinkCfg {
    linkver: StandardLinkver,
    cache: StandardCellCache,
}

impl WithCellConfig for LinkCfg {
    fn is_circ_id_4bytes(&self) -> bool {
        self.linkver.is_circ_id_4bytes()
    }

    fn cell_type(&self, header: &CellHeader) -> Result<CellType, errors::InvalidCellHeader> {
        self.linkver.cell_type(header)
    }
}

impl CellCache for LinkCfg {
    fn get_cached(&self) -> FixedCell {
        self.cache.get_cached()
    }

    fn cache_cell(&self, cell: FixedCell) {
        self.cache.cache_cell(cell);
    }
}

struct SimpleConfig {
    id: RelayId,
    addrs: Cow<'static, [SocketAddr]>,
}

impl ChannelConfig for SimpleConfig {
    fn peer_id(&self) -> &RelayId {
        &self.id
    }

    fn peer_addrs(&self) -> Cow<'_, [SocketAddr]> {
        Cow::Borrowed(&self.addrs)
    }
}

struct VersionOnlyConfig {
    cfg: SimpleConfig,
    delay: bool,
}

impl AsRef<Self> for VersionOnlyConfig {
    fn as_ref(&self) -> &Self {
        self
    }
}

impl ChannelConfig for VersionOnlyConfig {
    fn peer_id(&self) -> &RelayId {
        self.cfg.peer_id()
    }

    fn peer_addrs(&self) -> Cow<'_, [SocketAddr]> {
        self.cfg.peer_addrs()
    }
}

struct VersionOnlyController {
    cell_read: CellReader<Arc<LinkCfg>>,
    cell_write: Option<CellWriter<Cell>>,
    link_cfg: Arc<LinkCfg>,
    delay: bool,
    target_time: Option<Instant>,
    finished: bool,
}

impl ChannelController for VersionOnlyController {
    type Error = AnyError;
    type Config = VersionOnlyConfig;
    type ControlMsg = Infallible;
    type Cell = Cell;
    type CircMeta = ();

    fn new(cfg: Arc<dyn Send + Sync + AsRef<Self::Config>>) -> Self {
        let cfg = (*cfg).as_ref();
        let link_cfg = Arc::new(LinkCfg::default());

        Self {
            cell_read: CellReader::new(link_cfg.clone()),
            cell_write: Some(CellWriter::new(
                link_cfg.linkver.as_ref().versions_cell().into(),
                link_cfg.linkver.is_circ_id_4bytes(),
            )),
            link_cfg,
            finished: false,
            target_time: None,
            delay: cfg.delay,
        }
    }
}

// NOTE: Cannot use Self:: syntax here because of cycles.
impl<'a> Handle<(ChannelInput<'a>, &'a mut CircuitMap<Cell, ()>)> for VersionOnlyController {
    type Return = AnyResult<ChannelOutput>;

    #[instrument(name = "handle_normal", skip_all)]
    fn handle(
        &mut self,
        (mut input, _): (ChannelInput<'a>, &'a mut CircuitMap<Cell, ()>),
    ) -> Self::Return {
        if let Some(h) = &mut self.cell_write {
            match h.handle(input.writer()) {
                Ok(()) => {
                    info!("writing version cell finished");
                    self.cell_write = None;
                }
                Err(e) if e.kind() == ErrorKind::WouldBlock => (),
                Err(e) => return Err(e.into()),
            }
        }

        if self.delay {
            info!("delay active: setting timeout");
            let mut ret = ChannelOutput::new();
            let time = *self
                .target_time
                .get_or_insert_with(|| input.time() + Duration::from_secs(5));
            ret.timeout(time);
            return Ok(ret);
        }

        let mut cell = match self.cell_read.handle(input.reader()) {
            Ok(v) => Some(v),
            Err(errors::CellError::Io(e)) if e.kind() == ErrorKind::WouldBlock => None,
            Err(e) => return Err(e.into()),
        };
        if let Some(cell) = cast::<Versions>(&mut cell)? {
            info!("received VERSIONS: {:?}", cell.data());
            self.link_cfg.linkver.as_ref().versions_negotiate(cell)?;
            info!(
                "version negotiated: {}",
                self.link_cfg.linkver.as_ref().version()
            );
            self.finished = true;
        }

        let mut ret = ChannelOutput::new();
        ret.shutdown(self.finished);
        Ok(ret)
    }
}

impl Handle<Timeout> for VersionOnlyController {
    type Return = AnyResult<()>;

    #[instrument(name = "handle_timeout", skip_all)]
    fn handle(&mut self, _: Timeout) -> Self::Return {
        debug!("handling timeout");
        if !self.delay || self.target_time.is_none() {
            panic!("controller does not set timeout");
        }
        self.delay = false;
        Ok(())
    }
}

impl Handle<ControlMsg<Infallible>> for VersionOnlyController {
    type Return = AnyResult<()>;

    #[instrument(name = "handle_control", skip_all)]
    fn handle(&mut self, _: ControlMsg<Infallible>) -> Self::Return {
        panic!("controller should never get any control message");
    }
}

impl Handle<CellMsg<Cell>> for VersionOnlyController {
    type Return = AnyResult<CellMsgPause>;

    #[instrument(name = "handle_cell", skip_all)]
    fn handle(&mut self, _: CellMsg<Cell>) -> Self::Return {
        panic!("controller should never get any cell message");
    }
}

#[test]
fn test_versions_controller() {
    let mut v = TestController::<VersionOnlyController>::new(
        VersionOnlyConfig {
            cfg: SimpleConfig {
                id: RelayId::default(),
                addrs: Cow::Borrowed(&[]),
            },
            delay: false,
        }
        .into(),
        ([127, 0, 0, 1], 443).into(),
        vec![],
    );

    v.send_stream().extend([0, 0, 7, 0, 2, 0, 4]);

    let ret = v.process().unwrap();
    assert!(ret.shutdown);

    assert_eq!(v.controller().link_cfg.linkver.as_ref().version(), 4);
}

#[test]
fn test_versions_controller_timeout() {
    let mut v = TestController::<VersionOnlyController>::new(
        VersionOnlyConfig {
            cfg: SimpleConfig {
                id: RelayId::default(),
                addrs: Cow::Borrowed(&[]),
            },
            delay: true,
        }
        .into(),
        ([127, 0, 0, 1], 443).into(),
        vec![],
    );

    v.send_stream().extend([0, 0, 7, 0, 2, 0, 5]);

    let ret = v.process().unwrap();
    assert!(!ret.shutdown);
    info!("time: {:?} timeout: {:?}", v.cur_time(), v.timeout());

    v.advance_time(Duration::from_secs(1));
    info!("advancing time. Time: {:?}", v.cur_time());
    let ret = v.process().unwrap();
    assert!(!ret.shutdown);
    info!("time: {:?} timeout: {:?}", v.cur_time(), v.timeout());

    v.advance_time(Duration::from_secs(4));
    info!("advancing time. Time: {:?}", v.cur_time());
    let ret = v.process().unwrap();
    assert!(ret.shutdown);
    info!("time: {:?} timeout: {:?}", v.cur_time(), v.timeout());

    assert_eq!(v.controller().link_cfg.linkver.as_ref().version(), 5);
}

#[test(tokio::test)]
#[ignore = "requires network access"]
async fn test_versions_controller_async() {
    let (id, addrs) = get_relay_data();

    let mut v = ChannelManager::<_, VersionOnlyController>::new(TokioRuntime);

    let cfg = VersionOnlyConfig {
        cfg: SimpleConfig {
            id,
            addrs: addrs.into(),
        },
        delay: true,
    };
    v.create(cfg, ()).completion().await.unwrap();
}

#[test(tokio::test)]
#[ignore = "requires network access"]
async fn test_user_controller_async() {
    let (id, addrs) = get_relay_data();

    struct Config {
        cfg: SimpleConfig,
        cache: Arc<StandardCellCache>,
    }

    impl ChannelConfig for Config {
        fn peer_id(&self) -> &RelayId {
            self.cfg.peer_id()
        }

        fn peer_addrs(&self) -> Cow<'_, [SocketAddr]> {
            self.cfg.peer_addrs()
        }
    }

    impl UserConfig for Config {
        fn get_cache(&self) -> Arc<dyn Send + Sync + CellCache> {
            self.cache.clone()
        }
    }

    let cache = Arc::<StandardCellCache>::default();

    let mut v = ChannelManager::<_, UserController<Config>>::new(TokioRuntime);

    let cfg = Config {
        cfg: SimpleConfig {
            id,
            addrs: addrs.into(),
        },
        cache: cache.clone(),
    };
    let mut channel = v.create(cfg, ());

    info!("sleeping for 5 second");

    sleep(Duration::from_secs(5)).await;

    info!("done sleeping, starting graceful shutdown");

    channel
        .send_and_completion(UserControlMsg::Shutdown)
        .await
        .unwrap();

    info!("shutdown successful");
}
