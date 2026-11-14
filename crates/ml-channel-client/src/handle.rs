use std::io::{Read, Write};
use std::pin::Pin;
use std::io::Arc;
use std::time::Instant;

use anyhow::Error as AnyError;
use onioncloud_ll::channel::handle::{ChannelHandle, Handle, Return};
use onioncloud_ll::channel::error::{ChannelError, IoError, RustlsError};
use onioncloud_ll::utils::{LinkVersion, LinkVersionNegotiateError, Config as RWConfig};
use onioncloud_ll::cell::write::Writer;
use onioncloud_ll::cell::read::Reader;
use onioncloud_ll::cell::cache::CellCache;
use onioncloud_ll::cell::error::{CellReadError, CellWriteError, CellFormatError, CellCastError, NonZeroCircID, ZeroCircID, CellIsFixed, CellIsVariable};
//use onioncloud_runtime::{HasNetwork, HasTimer, Timer as _};
use pin_project::pin_project;
use tracing::{instrument, info};

/// Channel handle for client.
#[pin_project]
#[derive(Debug)]
pub struct ClientHandle<R, C> {
    inner: Inner<R, C>,
}

#[derive(Debug)]
struct Inner<R, C> {
    timeout: Option<Instant>,
    state: State,
    reader: Reader<RWConfig<C>>,
    writer: Writer<RWConfig<C>>,
}

#[derive(Debug, Clone, Copy)]
enum State {
    Init,
    WriteVersions,
    ReadVersions,
}

impl<R, C: CellCache> ChannelHandle<R> for ClientHandle<R, C> {
    type Error = ClientError;

    #[instrument(name = "ClientHandle::handle", skip_all)]
    fn handle(self: Pin<&mut Self>, mut args: Handle<R>) -> Result<Return, Self::Error> {
        let this = self.project();
        loop {
            if args.is_timeout() {
                info!("Channel handshake timeouts, shutting down");
                return Ok(Return::new(&args).with_shutdown());
            }

            match this.inner.state {
                State::Init => {
                    if !this.inner.writer.maybe_receive(|| Some(LinkVersion::make_versions(LinkVersion::MIN, LinkVersion::MAX).into())) {
                        unreachable!("receive must succeed!");
                    }
                    this.inner.state = State::WriteVersions;
                    this.inner.timeout = Some(args.time());
                }
                State::WriteVersions => {
                    if this.inner.writer.write(&mut args)? {
                        this.inner.state = State::ReadVersions;
                    } else {
                        break;
                    }
                }
                State::ReadVersions => {
                    this.inner.reader.read(&mut args)?
                }
            }
        }

        Ok(Return::new(&args).with_timeout(this.inner.timeout)
    }
}

/// Error type for [`ClientHandle`].
#[derive(Error, Debug)]
#[error(transparent)]
#[non_exhaustive]
pub enum ClientError {
    Any(#[from] AnyError),
    Io(#[from] IoError),
    Rustls(#[from] RustlsError),
    LinkVersionNegotiate(#[from] LinkVersionNegotiateError),
    CellFormat(#[from] CellFormatError),
    NonZeroCircID(#[from] NonZeroCircID),
    ZeroCircID(#[from] ZeroCircID),
    CellIsFixed(#[from] CellIsFixed),
    CellIsVariable(#[from] CellIsVariable),
}

impl From<ChannelError> for ClientError {
    fn from(v: ChannelError) -> Self {
        match v {
            ChannelError::Io(v) => v.into(),
            ChannelError::Rustls(v) => v.into(),
            v => Self::Any(v.into()),
        }
    }
}

impl From<CellReadError> for ClientError {
    fn from(v: CellReadError) -> Self {
        match v {
            CellReadError::Io(v) => v.into(),
            CellReadError::CellFormatError(v) => v.into(),
            v => Self::Any(v.into()),
        }
    }
}

impl From<CellWriteError> for ClientError {
    fn from(v: CellWriteError) -> Self {
        match v {
            CellWriteError::Io(v) => v.into(),
            CellWriteError::CellFormatError(v) => v.into(),
            v => Self::Any(v.into()),
        }
    }
}

impl From<CellCastError> for ClientError {
    fn from(v: CellCastError) -> Self {
        match v {
            CellCastError::CellFormatError(v) => v.into(),
            CellCastError::NonZeroCircID(v) => v.into(),
            CellCastError::ZeroCircID(v) => v.into(),
            CellCastError::CellIsFixed(v) => v.into(),
            CellCastError::CellIsVariable(v) => v.into(),
            v => Self::Any(v.into()),
        }
    }
}
