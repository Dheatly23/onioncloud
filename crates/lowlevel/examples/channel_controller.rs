//! Example of channel controller.

use std::borrow::Cow;
use std::convert::Infallible;
use std::env::{VarError, var};
use std::fmt::{Display, Formatter, Result as FmtResult};
use std::io::ErrorKind;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{Error as AnyError, Result as AnyResult, bail};
use digest::Digest;
use onioncloud_lowlevel::cache::{Cached, CellCache, StandardCellCache, cast};
use onioncloud_lowlevel::cell::auth::AuthChallenge;
use onioncloud_lowlevel::cell::certs::Certs;
use onioncloud_lowlevel::cell::dispatch::{CellReader, CellType, WithCellConfig};
use onioncloud_lowlevel::cell::netinfo::Netinfo;
use onioncloud_lowlevel::cell::versions::Versions;
use onioncloud_lowlevel::cell::writer::CellWriter;
use onioncloud_lowlevel::cell::{Cell, CellHeader, CellLike, FixedCell};
use onioncloud_lowlevel::channel::circ_map::CircuitMap;
use onioncloud_lowlevel::channel::controller::{CellMsg, ChannelController, ControlMsg, Timeout};
use onioncloud_lowlevel::channel::manager::ChannelManager;
use onioncloud_lowlevel::channel::{CellMsgPause, ChannelConfig, ChannelInput, ChannelOutput};
use onioncloud_lowlevel::crypto::cert::{
    UnverifiedEdCert, UnverifiedRsaCert, extract_rsa_from_x509,
};
use onioncloud_lowlevel::crypto::relay::{RelayId, from_str as relay_from_str};
use onioncloud_lowlevel::crypto::{EdPublicKey, Sha256Output};
use onioncloud_lowlevel::errors;
use onioncloud_lowlevel::errors::CellError;
use onioncloud_lowlevel::linkver::StandardLinkver;
use onioncloud_lowlevel::runtime::tokio::TokioRuntime;
use onioncloud_lowlevel::util::sans_io::Handle;
use sha2::Sha256;
use subtle::ConstantTimeEq;
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
    link_cfg: Arc<LinkCfg>,
    cfg: Arc<dyn Send + Sync + AsRef<Config>>,

    state: ControllerState,

    timer: TimerState,
}

type Writer<T = Cell> = CellWriter<Cached<T, Arc<LinkCfg>>>;
type Reader = CellReader<Arc<LinkCfg>>;

enum ControllerState {
    Init,
    VersionsWrite(CellWriter<Versions>),
    ConfigRead {
        reader: Reader,
        state: ConfigReadState,
    },
    NetinfoWrite(Writer<Netinfo>),
    Finished,
}

enum ConfigReadState {
    NeedVersions,
    NeedCerts,
    NeedAuthChallenge,
    NeedNetinfo,
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

    fn new(cfg: Arc<dyn Send + Sync + AsRef<Self::Config>>) -> Self {
        let link_cfg = Arc::new(LinkCfg::default());

        Self {
            state: ControllerState::Init,

            cfg,
            link_cfg,

            timer: TimerState::Init,
        }
    }
}

#[instrument(level = "debug", skip_all)]
fn write_cell<T: CellLike>(
    handler: &mut CellWriter<T>,
    input: &mut ChannelInput<'_>,
) -> AnyResult<bool> {
    match handler.handle(input.writer()) {
        Ok(()) => {
            debug!("writing cell finished");
            Ok(true)
        }
        Err(e) if e.kind() == ErrorKind::WouldBlock => Ok(false),
        Err(e) => Err(e.into()),
    }
}

fn read_cell(handler: &mut Reader, input: &mut ChannelInput<'_>) -> AnyResult<Option<Cell>> {
    match handler.handle(input.reader()) {
        Ok(v) => Ok(Some(v)),
        Err(CellError::Io(e)) if e.kind() == ErrorKind::WouldBlock => Ok(None),
        Err(e) => Err(e.into()),
    }
}

fn check_cert(
    mut unverified: UnverifiedEdCert<'_>,
    cert_ty: u8,
    key_ty: u8,
    pk: &EdPublicKey,
    needs_signed_by: bool,
) -> AnyResult<()> {
    unverified.header.check_type(cert_ty, key_ty)?;

    let mut signed_with = None;
    while let Some(v) = unverified.next_ext() {
        let (header, data) = v?;

        match header.ty {
            4 => signed_with = Some(data),
            _ => (),
        }
    }

    if needs_signed_by && signed_with.is_none() {
        bail!("certificate does not contain signed-by key extension");
    }

    unverified.verify(pk)?;

    if let Some(k) = signed_with {
        if k != pk {
            bail!("signed-by key does not match signing key");
        }
    }

    Ok(())
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
        loop {
            self.state = match &mut self.state {
                ControllerState::Init => {
                    let peer_addr = input.peer_addr();
                    let addrs = &(*self.cfg).as_ref().addrs;
                    if !addrs.contains(peer_addr) {
                        bail!("peer address {peer_addr} is not in {addrs:?}")
                    }

                    ControllerState::VersionsWrite(CellWriter::new(
                        self.link_cfg.linkver.as_ref().versions_cell(),
                        self.link_cfg.is_circ_id_4bytes(),
                    ))
                }
                ControllerState::VersionsWrite(w) => match write_cell(w, &mut input)? {
                    false => break,
                    true => ControllerState::ConfigRead {
                        reader: Reader::new(self.link_cfg.clone()),
                        state: ConfigReadState::NeedVersions,
                    },
                },
                ControllerState::ConfigRead { reader, state } => {
                    let Some(cell) = read_cell(reader, &mut input)? else {
                        break;
                    };
                    let mut cell = self.link_cfg.cache(Some(cell));

                    match state {
                        ConfigReadState::NeedVersions => {
                            if let Some(cell) = cast::<Versions>(&mut cell)? {
                                info!("received VERSIONS: {:?}", cell.data());
                                self.link_cfg.linkver.as_ref().versions_negotiate(cell)?;
                                info!(
                                    "version negotiated: {}",
                                    self.link_cfg.linkver.as_ref().version()
                                );

                                *state = ConfigReadState::NeedCerts;
                            }
                        }
                        ConfigReadState::NeedCerts => {
                            if let Some(cell) = cast::<Certs>(&mut cell)? {
                                info!(len = cell.len(), "received CERTS");

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

                                let mut pk_rsa = None;
                                if let Some(data) = cert_2 {
                                    let (k, id) = extract_rsa_from_x509(data)?;

                                    info!(
                                        "found relay RSA public key with fingerprint {}",
                                        print_hex(&id)
                                    );
                                    let relay_id = &(*self.cfg).as_ref().id;
                                    if id.ct_ne(relay_id).into() {
                                        bail!(
                                            "relay ID mismatch (expect {}, got {})",
                                            print_hex(relay_id),
                                            print_hex(&id)
                                        )
                                    }

                                    pk_rsa = Some(k);
                                }

                                let mut pk_id = None;
                                if let Some(data) = cert_7 {
                                    let unverified = UnverifiedRsaCert::new(data)?;

                                    info!("RSA certificate header: {:?}", unverified.header);

                                    if let Some(pk) = &pk_rsa {
                                        pk_id = Some(unverified.verify(pk)?.key);
                                        info!("RSA certificate verification success");
                                    }
                                }

                                let mut pk_sign = None;
                                if let Some(data) = cert_4 {
                                    info!("got certificate ID 4 ID->sign");
                                    let unverified = UnverifiedEdCert::new(data)?;
                                    pk_sign = Some(unverified.header.key);

                                    let Some(k) = &pk_id else {
                                        bail!("ed25519 relay identity key not provided")
                                    };
                                    check_cert(unverified, 4, 1, k, true)?;
                                    info!("ed25519 signing certificate verified");
                                }

                                let mut link_verified = false;
                                if let Some(data) = cert_5 {
                                    info!("got certificate ID 5 sign->link");
                                    let unverified = UnverifiedEdCert::new(data)?;
                                    let subject = unverified.header.key;

                                    let Some(k) = &pk_sign else {
                                        bail!("ed25519 relay signing key not provided")
                                    };
                                    check_cert(unverified, 5, 3, k, false)?;
                                    info!("ed25519 link certificate verified");

                                    let Some(link_cert) = input.link_cert() else {
                                        bail!("link certificate not provided")
                                    };
                                    let hash = Sha256Output::from(Sha256::digest(link_cert));
                                    if subject.ct_ne(&hash).into() {
                                        bail!("link certificate hash does not match")
                                    }

                                    link_verified = true;
                                    info!("link certificate verified");
                                }

                                if !link_verified {
                                    bail!("link certificate verification failed");
                                }

                                *state = ConfigReadState::NeedAuthChallenge;
                            }
                        }
                        ConfigReadState::NeedAuthChallenge => {
                            if let Some(_) = cast::<AuthChallenge>(&mut cell)? {
                                info!("get AUTH_CHALLENGE cell");
                                *state = ConfigReadState::NeedNetinfo;
                            }
                        }
                        ConfigReadState::NeedNetinfo => {
                            if let Some(cell) = cast::<Netinfo>(&mut cell)? {
                                let peer_addr = cell.peer_addr();
                                info!(
                                    time = cell.time(),
                                    peer_addr =
                                        peer_addr.map_or_else(String::new, |v| v.to_string()),
                                    "get NETINFO cell"
                                );

                                let Some(peer_addr) = peer_addr else {
                                    bail!("invalid peer address")
                                };
                                let addrs = &(*self.cfg).as_ref().addrs;
                                for a in cell.this_addrs() {
                                    info!("found this address: {a}");
                                    if addrs.iter().all(|b| b.ip() != a) {
                                        bail!("address {a} is not found in {addrs:?}")
                                    }
                                }

                                self.state = ControllerState::NetinfoWrite(
                                    self.link_cfg
                                        .cache(Netinfo::new(
                                            self.link_cfg.get_cached(),
                                            0,
                                            input.peer_addr().ip(),
                                            [peer_addr],
                                        ))
                                        .try_into()?,
                                );
                                continue;
                            }
                        }
                    }

                    if let Some(cell) = &*cell {
                        bail!("cannot handle cell with command {}", cell.command)
                    }
                    continue;
                }
                ControllerState::NetinfoWrite(w) => match write_cell(w, &mut input)? {
                    false => break,
                    true => ControllerState::Finished,
                },
                ControllerState::Finished => break,
            };
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
    type Return = AnyResult<CellMsgPause>;

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
