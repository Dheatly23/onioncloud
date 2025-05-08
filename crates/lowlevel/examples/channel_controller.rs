//! Example of channel controller.

use std::borrow::Cow;
use std::convert::Infallible;
use std::env::{VarError, var};
use std::fmt::{Display, Formatter, Result as FmtResult};
use std::io::ErrorKind;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{Error as AnyError, Result as AnyResult};
use onioncloud_lowlevel::cache::{Cached, CellCache, StandardCellCache, cast};
use onioncloud_lowlevel::cell::certs::Certs;
use onioncloud_lowlevel::cell::dispatch::{CellReader, CellType, WithCellConfig};
use onioncloud_lowlevel::cell::netinfo::Netinfo;
use onioncloud_lowlevel::cell::versions::Versions;
use onioncloud_lowlevel::cell::writer::CellWriter;
use onioncloud_lowlevel::cell::{Cell, CellHeader, FixedCell};
use onioncloud_lowlevel::channel::circ_map::CircuitMap;
use onioncloud_lowlevel::channel::controller::{CellMsg, ChannelController, ControlMsg, Timeout};
use onioncloud_lowlevel::channel::manager::ChannelManager;
use onioncloud_lowlevel::channel::{ChannelConfig, ChannelInput, ChannelOutput};
use onioncloud_lowlevel::crypto::cert::{UnverifiedRsaCert, extract_rsa_from_x509};
use onioncloud_lowlevel::crypto::relay::{RelayId, from_str as relay_from_str};
use onioncloud_lowlevel::errors;
use onioncloud_lowlevel::errors::CellError;
use onioncloud_lowlevel::linkver::StandardLinkver;
use onioncloud_lowlevel::runtime::tokio::TokioRuntime;
use onioncloud_lowlevel::util::sans_io::Handle;
use tracing::{debug, info, instrument, warn};

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

struct Config {
    id: RelayId,
    addrs: Cow<'static, [SocketAddr]>,
}

impl ChannelConfig for Config {
    fn peer_id(&self) -> &RelayId {
        &self.id
    }

    fn peer_addrs(&self) -> Cow<'_, [SocketAddr]> {
        Cow::Borrowed(&self.addrs)
    }
}

struct Controller {
    cell_read: CellReader<Arc<LinkCfg>>,
    cell_write: Option<CellWriter<Cell>>,
    link_cfg: Arc<LinkCfg>,

    timer: TimerState,
}

enum TimerState {
    Init,
    Wait(Instant),
    Finished,
}

impl ChannelController for Controller {
    type Error = AnyError;
    type Config = Config;
    type ControlMsg = Infallible;
    type Cell = Cached<Cell, Arc<LinkCfg>>;
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

            timer: TimerState::Init,
        }
    }
}

// NOTE: Cannot use Self:: syntax here because of cycles.
impl<'a>
    Handle<(
        ChannelInput<'a>,
        &'a mut CircuitMap<Cached<Cell, Arc<LinkCfg>>, ()>,
    )> for Controller
{
    type Return = AnyResult<ChannelOutput>;

    #[instrument(name = "handle_normal", skip_all)]
    fn handle(
        &mut self,
        (mut input, _): (
            ChannelInput<'a>,
            &'a mut CircuitMap<Cached<Cell, Arc<LinkCfg>>, ()>,
        ),
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

        loop {
            let mut cell = match self.cell_read.handle(input.reader()) {
                Ok(v) => Cached::new(self.link_cfg.clone(), Some(v)),
                Err(CellError::Io(e)) if e.kind() == ErrorKind::WouldBlock => break,
                Err(e) => return Err(e.into()),
            };

            if let Some(cell) = cast::<Versions>(&mut cell)? {
                info!("received VERSIONS: {:?}", cell.data());
                self.link_cfg.linkver.as_ref().versions_negotiate(cell)?;
                info!(
                    "version negotiated: {}",
                    self.link_cfg.linkver.as_ref().version()
                );
            } else if let Some(cell) = cast::<Certs>(&mut cell)? {
                info!("received CERTS");

                let mut cert_2 = None;
                let mut cert_4 = None;
                let mut cert_5 = None;
                let mut cert_7 = None;

                for c in &cell {
                    info!(
                        "get cert ty: {} data:\n{}",
                        c.ty,
                        print_hex_multiline(c.data)
                    );

                    match c.ty {
                        2 if cert_2.is_none() => cert_2 = Some(c.data),
                        4 if cert_4.is_none() => cert_4 = Some(c.data),
                        5 if cert_5.is_none() => cert_5 = Some(c.data),
                        7 if cert_7.is_none() => cert_7 = Some(c.data),
                        _ => (),
                    }
                }

                let mut pk = None;
                if let Some(data) = cert_2 {
                    let (k, id) = extract_rsa_from_x509(data)?;

                    info!(
                        "found relay RSA public key with fingerprint {}",
                        print_hex(&id)
                    );

                    pk = Some(k);
                }

                if let Some(data) = cert_7 {
                    let unverified = UnverifiedRsaCert::new(data)?;

                    info!("RSA certificate header: {:?}", unverified.header);

                    if let Some(pk) = &pk {
                        unverified.verify(pk)?;
                        info!("RSA certificate verification success");
                    }
                }
            }
        }

        let mut ret = ChannelOutput::new();
        loop {
            match self.timer {
                TimerState::Init => {
                    self.timer = TimerState::Wait(input.time() + Duration::from_secs(5));
                    continue;
                }
                TimerState::Wait(t) => {
                    ret.timeout(t);
                }
                TimerState::Finished => {
                    ret.shutdown(true);
                }
            }
            break;
        }
        Ok(ret)
    }
}

impl Handle<Timeout> for Controller {
    type Return = AnyResult<()>;

    #[instrument(name = "handle_timeout", skip_all)]
    fn handle(&mut self, _: Timeout) -> Self::Return {
        debug!("handling timeout");
        if !matches!(self.timer, TimerState::Wait(_)) {
            panic!("controller does not set timeout");
        }
        self.timer = TimerState::Finished;
        Ok(())
    }
}

impl Handle<ControlMsg<Infallible>> for Controller {
    type Return = AnyResult<()>;

    #[instrument(name = "handle_control", skip_all)]
    fn handle(&mut self, _: ControlMsg<Infallible>) -> Self::Return {
        panic!("controller should never get any control message");
    }
}

impl Handle<CellMsg<Cached<Cell, Arc<LinkCfg>>>> for Controller {
    type Return = AnyResult<()>;

    #[instrument(name = "handle_cell", skip_all)]
    fn handle(&mut self, _: CellMsg<Cached<Cell, Arc<LinkCfg>>>) -> Self::Return {
        panic!("controller should never get any cell message");
    }
}

fn print_hex(data: &[u8]) -> impl '_ + Display {
    struct S<'a>(&'a [u8]);

    impl Display for S<'_> {
        fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
            for v in self.0.iter() {
                write!(f, "{v:02X}")?;
            }

            Ok(())
        }
    }

    S(data)
}

fn print_hex_multiline(data: &[u8]) -> impl '_ + Display {
    struct S<'a>(&'a [u8]);

    impl Display for S<'_> {
        fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
            let mut s = self.0;

            while !s.is_empty() {
                let (a, b) = s.split_at_checked(16).unwrap_or((s, &[]));
                s = b;

                for (i, v) in a.iter().enumerate() {
                    if i != 0 {
                        write!(f, " ")?;
                    }
                    write!(f, "{v:02X}")?;
                }

                if !s.is_empty() {
                    write!(f, "\n")?;
                }
            }

            Ok(())
        }
    }

    S(data)
}

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

    let mut v = ChannelManager::<_, Controller>::new(TokioRuntime);

    let cfg = Config {
        id,
        addrs: addrs.into(),
    };
    v.create(cfg, ()).completion().await.unwrap();
}
