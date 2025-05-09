use std::fmt::{Debug, Display};
use std::io::Error as IoError;

use rustls::Error as RustlsError;

use super::circ_map::CircuitMap;
use super::{CellMsgPause, ChannelConfig, ChannelInput, ChannelOutput};
use crate::util::sans_io::Handle;

/// Marker type for channel timeout.
#[derive(Debug, PartialEq, Eq)]
pub struct Timeout;

/// Wrapper type for signalling a control message.
#[derive(Debug)]
pub struct ControlMsg<M>(pub M);

impl<M> ControlMsg<M> {
    /// Unwraps into inner value.
    pub fn into_inner(self) -> M {
        self.0
    }
}

/// Wrapper type for signalling a cell message.
#[derive(Debug)]
pub struct CellMsg<M>(pub M);

impl<M> CellMsg<M> {
    /// Unwraps into inner value.
    pub fn into_inner(self) -> M {
        self.0
    }
}

/// Trait for a channel controller.
///
/// # Implementers Note
///
/// Implementers _must_ implement [`Handle`]rs to handle incoming events. Values to be handled are:
/// - [`(ChannelInput<'a>, &'a mut CircuitMap<Self::Cell, Self::CircMeta>)`]
///
///   Universal handler for channel inputs and circuit map. Will be called after all the other events.
///   Returns [`ChannelOutput`] to control things like shutdown, timer, and cell message handling.
///
/// - [`Timeout`]
///
///   Timeout handler.
///
/// - [`ControlMsg<Self::ControlMsg>`]
///
///   Control message handler.
///
/// - [`CellMsg<Self::Cell>`]
///
///   Cell message handler. Returns [`CellMsgPause`] to pause next cell message handling.
pub trait ChannelController:
    Send
    + for<'a> Handle<
        (
            ChannelInput<'a>,
            &'a mut CircuitMap<Self::Cell, Self::CircMeta>,
        ),
        Return = Result<ChannelOutput, Self::Error>,
    > + Handle<ControlMsg<Self::ControlMsg>, Return = Result<(), Self::Error>>
    + Handle<CellMsg<Self::Cell>, Return = Result<CellMsgPause, Self::Error>>
    + Handle<Timeout, Return = Result<(), Self::Error>>
{
    /// Error type.
    type Error: 'static + Debug + Display + Send + Sync + From<IoError> + From<RustlsError>;
    /// Channel configuration.
    type Config: 'static + ChannelConfig + Send + Sync;
    /// Control message.
    type ControlMsg: 'static + Send;
    /// Cell type.
    type Cell: 'static + Send;
    /// Circuit metadata.
    type CircMeta: 'static + Send;

    /// Get circuit channel capacity.
    fn channel_cap(_config: &Self::Config) -> usize {
        256
    }
    /// Get circuit aggregation channel capacity.
    fn channel_aggregate_cap(_config: &Self::Config) -> usize {
        256
    }

    fn new(config: &Self::Config) -> Self;
}

#[cfg(test)]
pub(crate) use tests::*;

#[cfg(test)]
mod tests {
    use super::*;

    use std::borrow::Cow;
    use std::convert::Infallible;
    use std::env::{VarError, var};
    use std::net::SocketAddr;
    use std::sync::Arc;
    use std::time::{Duration, Instant};

    use anyhow::{Error as AnyError, Result as AnyResult};
    use test_log::test;
    use tracing::{debug, info, instrument, warn};

    use crate::cache::{CellCache, StandardCellCache};
    use crate::cell::dispatch::{CellReader, CellType, WithCellConfig};
    use crate::cell::versions::Versions;
    use crate::cell::writer::CellWriter;
    use crate::cell::{Cell, CellHeader, FixedCell, cast};
    use crate::channel::manager::ChannelManager;
    use crate::crypto::relay::{RelayId, from_str as relay_from_str};
    use crate::errors;
    use crate::linkver::StandardLinkver;
    use crate::runtime::tokio::TokioRuntime;
    use crate::util::{TestController, err_is_would_block, print_list};

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

    pub(crate) struct SimpleConfig {
        pub(crate) id: RelayId,
        pub(crate) addrs: Cow<'static, [SocketAddr]>,
    }

    impl ChannelConfig for SimpleConfig {
        fn peer_id(&self) -> &RelayId {
            &self.id
        }

        fn peer_addrs(&self) -> Cow<'_, [SocketAddr]> {
            Cow::Borrowed(&self.addrs)
        }
    }

    pub(crate) struct VersionOnlyConfig {
        pub(crate) cfg: SimpleConfig,
        pub(crate) delay: bool,
    }

    impl ChannelConfig for VersionOnlyConfig {
        fn peer_id(&self) -> &RelayId {
            self.cfg.peer_id()
        }

        fn peer_addrs(&self) -> Cow<'_, [SocketAddr]> {
            self.cfg.peer_addrs()
        }
    }

    pub(crate) struct VersionOnlyController {
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

        fn new(cfg: &Self::Config) -> Self {
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
                    Err(e) if err_is_would_block(&e) => (),
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
                Err(e) if err_is_would_block(&e) => None,
                Err(e) => return Err(e.into()),
            };
            if let Some(cell) = cast::<Versions>(&mut cell)? {
                info!("received VERSIONS: {}", print_list(cell.data()));
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
            &VersionOnlyConfig {
                cfg: SimpleConfig {
                    id: RelayId::default(),
                    addrs: Cow::Borrowed(&[]),
                },
                delay: false,
            },
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
            &VersionOnlyConfig {
                cfg: SimpleConfig {
                    id: RelayId::default(),
                    addrs: Cow::Borrowed(&[]),
                },
                delay: true,
            },
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
}
