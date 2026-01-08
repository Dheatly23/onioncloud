mod common;

use std::borrow::Cow;
use std::convert::Infallible;
use std::io::ErrorKind;
use std::marker::PhantomData;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::num::NonZeroU32;
use std::pin::pin;
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{Error as AnyError, Result as AnyResult};
use test_log::test;
use tokio::time::sleep;
use tracing::{debug, error, info, instrument, warn};

use onioncloud_lowlevel::cache::{CellCache, StandardCellCache};
use onioncloud_lowlevel::cell::dispatch::{CellReader, CellType, WithCellConfig};
use onioncloud_lowlevel::cell::versions::Versions;
use onioncloud_lowlevel::cell::writer::CellWriter;
use onioncloud_lowlevel::cell::{Cell, CellHeader, FixedCell, cast};
use onioncloud_lowlevel::channel::controller::{
    ChannelController, UserConfig, UserControlMsg, UserController,
};
use onioncloud_lowlevel::channel::manager::SingleManager;
use onioncloud_lowlevel::channel::{ChannelConfig, ChannelInput, ChannelOutput};
use onioncloud_lowlevel::crypto::relay::RelayId;
use onioncloud_lowlevel::errors;
use onioncloud_lowlevel::linkver::StandardLinkver;
use onioncloud_lowlevel::runtime::Runtime;
use onioncloud_lowlevel::runtime::test::{OpenSocket, TestExecutor};
use onioncloud_lowlevel::runtime::tokio::TokioRuntime;
use onioncloud_lowlevel::util::sans_io::event::{ChannelClosed, ChildCellMsg, ControlMsg, Timeout};
use onioncloud_lowlevel::util::sans_io::{CellMsgPause, Handle};

use crate::common::{get_relay_data, spawn};

#[derive(Default)]
struct LinkCfg {
    linkver: StandardLinkver,
    cache: Arc<StandardCellCache>,
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
    cache: Arc<StandardCellCache>,
}

impl ChannelConfig for SimpleConfig {
    fn peer_id(&self) -> &RelayId {
        &self.id
    }

    fn peer_addrs(&self) -> Cow<'_, [SocketAddr]> {
        Cow::Borrowed(&self.addrs)
    }
}

impl UserConfig for SimpleConfig {
    type Cache = Arc<StandardCellCache>;

    fn get_cache(&self) -> &Self::Cache {
        &self.cache
    }
}

struct VersionOnlyConfig {
    cfg: SimpleConfig,
    delay: bool,
    expect_version: Option<u16>,
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

struct VersionOnlyController<R> {
    cell_read: CellReader,
    cell_write: CellWriter<Cell>,
    link_cfg: LinkCfg,
    delay: bool,
    expect_version: Option<u16>,
    target_time: Option<Instant>,
    finished: bool,
    _p: PhantomData<R>,
}

impl<R: 'static + Runtime> ChannelController for VersionOnlyController<R> {
    type Runtime = R;
    type Error = AnyError;
    type Config = VersionOnlyConfig;
    type ControlMsg = Infallible;
    type Cell = Cell;
    type CircMeta = ();

    fn new(
        _: &R,
        VersionOnlyConfig {
            delay,
            expect_version,
            cfg: SimpleConfig { cache, .. },
        }: Self::Config,
    ) -> Self {
        let link_cfg = LinkCfg {
            linkver: StandardLinkver::new(),
            cache,
        };

        Self {
            cell_read: CellReader::new(),
            cell_write: CellWriter::with_cell_config(
                link_cfg.linkver.inner.versions_cell().into(),
                &link_cfg,
            )
            .unwrap(),
            link_cfg,
            finished: false,
            target_time: None,
            delay,
            expect_version,
            _p: PhantomData,
        }
    }
}

// NOTE: Cannot use Self:: syntax here because of cycles.
impl<'a, 'b, R: 'static + Runtime> Handle<(&'a R, ChannelInput<'a, 'b, R, Cell, ()>)>
    for VersionOnlyController<R>
{
    type Return = AnyResult<ChannelOutput>;

    #[instrument(name = "handle_normal", skip_all)]
    fn handle(
        &mut self,
        (_, mut input): (&'a R, ChannelInput<'a, 'b, R, Cell, ()>),
    ) -> Self::Return {
        if !self.cell_write.is_finished() {
            match self.cell_write.handle((input.writer(), &self.link_cfg)) {
                Ok(()) => info!("writing version cell finished"),
                Err(e) if e.kind() == ErrorKind::WouldBlock => (),
                Err(e) => {
                    error!("error writing cell: {e}");
                    return Err(e.into());
                }
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

        let mut cell = match self.cell_read.handle((input.reader(), &self.link_cfg)) {
            Ok(v) => Some(v),
            Err(errors::CellError::Io(e)) if e.kind() == ErrorKind::WouldBlock => None,
            Err(e) => {
                error!("error reading cell: {e}");
                return Err(e.into());
            }
        };
        if let Some(cell) = cast::<Versions>(&mut cell)? {
            info!("received VERSIONS: {:?}", cell.data());
            self.link_cfg.linkver.as_ref().versions_negotiate(cell)?;

            let version = self.link_cfg.linkver.as_ref().version();
            info!("version negotiated: {version}");

            if let Some(exp) = self.expect_version {
                assert_eq!(version, exp, "expected negotiated version mismatch");
            }

            self.finished = true;
        }

        let mut ret = ChannelOutput::new();
        ret.shutdown(self.finished);
        Ok(ret)
    }
}

impl<R: 'static + Runtime> Handle<Timeout> for VersionOnlyController<R> {
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

impl<R: 'static + Runtime> Handle<ControlMsg<Infallible>> for VersionOnlyController<R> {
    type Return = AnyResult<()>;

    #[instrument(name = "handle_control", skip_all)]
    fn handle(&mut self, _: ControlMsg<Infallible>) -> Self::Return {
        panic!("controller should never get any control message");
    }
}

impl<R: 'static + Runtime> Handle<ChildCellMsg<Cell>> for VersionOnlyController<R> {
    type Return = AnyResult<CellMsgPause>;

    #[instrument(name = "handle_cell", skip_all)]
    fn handle(&mut self, _: ChildCellMsg<Cell>) -> Self::Return {
        panic!("controller should never get any cell message");
    }
}

impl<'a, R: 'static + Runtime> Handle<ChannelClosed<'a, NonZeroU32, Cell, ()>>
    for VersionOnlyController<R>
{
    type Return = AnyResult<()>;

    #[instrument(name = "handle_close", skip_all, fields(id = msg.id))]
    fn handle(&mut self, msg: ChannelClosed<'a, NonZeroU32, Cell, ()>) -> Self::Return {
        panic!("controller should never get channel closed message");
    }
}

#[test]
fn test_versions_controller() {
    let cache = Arc::<StandardCellCache>::default();
    let mut exec = TestExecutor::default();

    exec.sockets().set_handle(Box::new(|addrs| {
        let addr = *addrs
            .iter()
            .find(|a| a.ip().is_loopback() && a.port() == 443)
            .ok_or(ErrorKind::HostUnreachable)?;

        let mut length = None::<u16>;

        Ok(OpenSocket::new(
            addr,
            Box::new(move |s| {
                let v = s.recv_stream();
                if length.is_none() && v.len() >= 5 {
                    for (i, s) in [0, 0, 7].into_iter().enumerate() {
                        assert_eq!(
                            v.pop_front().expect("value must exist"),
                            s,
                            "mismatch at index {i}"
                        );
                    }

                    let v0 = v.pop_front().expect("value must exist");
                    let v1 = v.pop_front().expect("value must exist");
                    let l = u16::from_be_bytes([v0, v1]);

                    assert!(l % 2 == 0, "VERSIONS cell length is odd (length is {l})");
                    info!("host parsing VERSIONS cell with length {l}");
                    length = Some(l);
                }

                while let Some(l @ 2..) = length.as_mut() {
                    if v.len() < 2 {
                        break;
                    }

                    let v0 = v.pop_front().expect("value must exist");
                    let v1 = v.pop_front().expect("value must exist");
                    let v = u16::from_be_bytes([v0, v1]);
                    assert!((4..=5).contains(&v), "version {v} is not valid");

                    *l -= 2;
                }

                if matches!(length, Some(0)) {
                    // Discard everything after
                    v.clear();
                } else if s.is_recv_closed() {
                    panic!("controller closed without sending full VERSIONS cell");
                }

                Ok(())
            }),
        )
        .with_send([0, 0, 7, 0, 2, 0, 4].into())
        .with_send_eof(true))
    }));

    static ADDRS: &[SocketAddr] = &[SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 443)];

    let rt = exec.runtime();
    let c = cache.clone();
    spawn(rt, |rt| async move {
        let cfg = VersionOnlyConfig {
            cfg: SimpleConfig {
                id: RelayId::default(),
                addrs: ADDRS.into(),
                cache: c,
            },
            delay: false,
            expect_version: Some(4),
        };
        // SAFETY: We are in integration test
        let cont = unsafe {
            pin!(SingleManager::<VersionOnlyController<_>>::new_test(
                &rt,
                cfg,
                |_| None
            ))
        };

        cont.as_ref().completion().await.unwrap();
    });

    spawn(rt, |rt| async move {
        let cfg = VersionOnlyConfig {
            cfg: SimpleConfig {
                id: RelayId::default(),
                addrs: ADDRS.into(),
                cache,
            },
            delay: true,
            expect_version: Some(4),
        };
        // SAFETY: We are in integration test
        let cont = unsafe {
            pin!(SingleManager::<VersionOnlyController<_>>::new_test(
                &rt,
                cfg,
                |_| None
            ))
        };

        cont.as_ref().completion().await.unwrap();
    });

    exec.run_tasks_until_finished();
}

#[test(tokio::test)]
#[ignore = "requires network access"]
async fn test_versions_controller_async() {
    let (id, addrs) = get_relay_data();

    let cfg = VersionOnlyConfig {
        cfg: SimpleConfig {
            id,
            addrs: addrs.into(),
            cache: Default::default(),
        },
        delay: true,
        expect_version: None,
    };

    let cont = pin!(SingleManager::<VersionOnlyController<_>>::new(
        &TokioRuntime,
        cfg
    ));
    cont.completion().await.unwrap();
}

#[test(tokio::test)]
#[ignore = "requires network access"]
async fn test_user_controller_async() {
    let (id, addrs) = get_relay_data();

    let cfg = SimpleConfig {
        id,
        addrs: addrs.into(),
        cache: Default::default(),
    };
    let cont = pin!(SingleManager::<UserController<_, _>>::new(
        &TokioRuntime,
        cfg
    ));

    info!("sleeping for 5 second");

    sleep(Duration::from_secs(5)).await;

    info!("done sleeping, starting graceful shutdown");

    cont.as_ref()
        .send_and_completion(UserControlMsg::Shutdown)
        .await
        .unwrap();

    info!("shutdown successful");
}
