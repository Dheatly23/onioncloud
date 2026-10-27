use std::borrow::Cow;
use std::future::poll_fn;
use std::io::{Error as IoError, ErrorKind, IoSlice, IoSliceMut, Read, Result as IoResult, Write};
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::task::Poll::*;
use std::task::{Context, Poll};

use futures_io::{AsyncRead, AsyncWrite};
use once_cell::sync::OnceCell;
use onioncloud_runtime::Socket;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::client::{ClientConfig, ClientConnection};
use rustls::crypto::ring::default_provider;
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{DigitallySignedStruct, Error as RustlsError, SignatureScheme};

use super::Stream;
use crate::error::ChannelError;

/// Wrapper for [`Socket`] with TLS.
#[derive(Debug)]
pub struct StreamTLS<S> {
    stream: S,
    peer_addr: SocketAddr,
    tls: ClientConnection,
    close_state: CloseState,
    flags: u8,
}

#[derive(Debug)]
enum CloseState {
    None,
    TlsClose,
    SocketClose,
    Closed,
}

const FLAG_READ: u8 = 1 << 0;
const FLAG_WRITE: u8 = 1 << 1;

impl<S: Socket + Unpin> AsyncRead for StreamTLS<S> {
    #[inline]
    fn poll_read(
        self: Pin<&mut Self>,
        _: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<IoResult<usize>> {
        let this = Pin::into_inner(self);
        match this.tls.reader().read(buf) {
            Ok(0) => Pending,
            v => Ready(v),
        }
    }

    #[inline]
    fn poll_read_vectored(
        self: Pin<&mut Self>,
        _: &mut Context<'_>,
        bufs: &mut [IoSliceMut<'_>],
    ) -> Poll<IoResult<usize>> {
        let this = Pin::into_inner(self);
        match this.tls.reader().read_vectored(bufs) {
            Ok(0) => Pending,
            v => Ready(v),
        }
    }
}

impl<S: Socket + Unpin> AsyncWrite for StreamTLS<S> {
    #[inline]
    fn poll_write(self: Pin<&mut Self>, _: &mut Context<'_>, buf: &[u8]) -> Poll<IoResult<usize>> {
        let this = Pin::into_inner(self);
        match this.close_state {
            CloseState::None => (),
            CloseState::Closed => return Ready(Ok(0)),
            _ => return Pending,
        }
        match this.tls.writer().write(buf) {
            Ok(0) => Pending,
            v => Ready(v),
        }
    }

    #[inline]
    fn poll_write_vectored(
        self: Pin<&mut Self>,
        _: &mut Context<'_>,
        bufs: &[IoSlice<'_>],
    ) -> Poll<IoResult<usize>> {
        let this = Pin::into_inner(self);
        match this.close_state {
            CloseState::None => (),
            CloseState::Closed => return Ready(Ok(0)),
            _ => return Pending,
        }
        match this.tls.writer().write_vectored(bufs) {
            Ok(0) => Pending,
            v => Ready(v),
        }
    }

    #[inline]
    fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<IoResult<()>> {
        let this = Pin::into_inner(self);
        match this.close_state {
            CloseState::None => (),
            CloseState::Closed => return Ready(Ok(())),
            _ => return Pending,
        }
        this.tls.writer().flush()?;
        if this.tls.wants_write() {
            Pending
        } else {
            Ready(Ok(()))
        }
    }

    #[inline]
    fn poll_close(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<IoResult<()>> {
        let this = Pin::into_inner(self);
        match &mut this.close_state {
            CloseState::None => {
                this.tls.send_close_notify();
                this.close_state = CloseState::TlsClose;
            }
            CloseState::Closed => return Ready(Ok(())),
            _ => (),
        }

        Pending
    }
}

impl<S: Socket + Unpin> Stream for StreamTLS<S> {
    fn peer_addr(&self) -> SocketAddr {
        self.peer_addr
    }

    fn leaf_cert(&self) -> Option<Cow<'_, [u8]>> {
        self.tls
            .peer_certificates()?
            .first()
            .map(|v| (&v[..]).into())
    }

    fn wants_poll(&self) -> bool {
        matches!(
            self.close_state,
            CloseState::SocketClose | CloseState::Closed
        ) || self.tls.wants_read()
            || self.tls.wants_write()
    }

    fn poll_inner(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        is_same_poll: bool,
    ) -> Poll<Result<(), ChannelError>> {
        let this = Pin::into_inner(self);

        if !is_same_poll {
            this.flags = 0;
        }

        loop {
            match this.close_state {
                CloseState::None | CloseState::TlsClose => (),
                CloseState::SocketClose => match Pin::new(&mut this.stream).poll_close(cx) {
                    Ready(Ok(())) => {
                        this.close_state = CloseState::Closed;
                        return Ready(Ok(()));
                    }
                    r => return r.map_err(ChannelError::from),
                },
                CloseState::Closed => return Ready(Ok(())),
            }

            let mut w = WrapAsync {
                cx,
                p: Pin::new(&mut this.stream),
            };

            let wants_write = this.tls.wants_write();
            let wants_read = this.tls.wants_read();
            if !wants_write && !wants_read {
                return Pending;
            } else if this.flags & FLAG_WRITE == 0 && wants_write {
                match poll_io_unwrap(this.tls.write_tls(&mut w)) {
                    Pending => this.flags |= FLAG_WRITE,
                    Ready(Err(e)) => return Ready(Err(e.into())),
                    Ready(Ok(0)) => this.close_state = CloseState::SocketClose,
                    Ready(Ok(_)) => (),
                }
            } else if this.flags & FLAG_READ == 0 && wants_read {
                match poll_io_unwrap(this.tls.read_tls(&mut w)) {
                    Pending => this.flags |= FLAG_READ,
                    Ready(Err(e)) => return Ready(Err(e.into())),
                    Ready(Ok(0)) => this.close_state = CloseState::SocketClose,
                    Ready(Ok(_)) => (),
                }

                this.tls.process_new_packets()?;
            } else {
                return Pending;
            }
        }
    }
}

impl<S: Socket + Unpin> StreamTLS<S> {
    /// Creates new stream.
    pub async fn new(mut stream: S) -> Result<Self, ChannelError> {
        let peer_addr = stream.peer_addr()?;
        let mut tls = ClientConnection::new(
            get_client_cfg()?,
            ServerName::IpAddress(peer_addr.ip().into()),
        )?;

        poll_fn(|cx| -> Poll<Result<(), ChannelError>> {
            let mut w = WrapAsync {
                cx,
                p: Pin::new(&mut stream),
            };
            let mut flags = 0;
            while tls.is_handshaking() {
                let wants_write = tls.wants_write();
                let wants_read = tls.wants_read();
                if !wants_write && !wants_read {
                    unreachable!("handshaking but TLS does not want to read nor write");
                } else if flags & FLAG_WRITE == 0 && wants_write {
                    match poll_io_unwrap(tls.write_tls(&mut w)) {
                        Pending => flags |= FLAG_WRITE,
                        Ready(Err(e)) => return Ready(Err(e.into())),
                        Ready(Ok(0)) => {
                            return Ready(Err(IoError::from(ErrorKind::ConnectionAborted).into()));
                        }
                        Ready(Ok(_)) => (),
                    }
                } else if flags & FLAG_READ == 0 && wants_read {
                    match poll_io_unwrap(tls.read_tls(&mut w)) {
                        Pending => flags |= FLAG_READ,
                        Ready(Err(e)) => return Ready(Err(e.into())),
                        Ready(Ok(0)) => {
                            return Ready(Err(IoError::from(ErrorKind::ConnectionAborted).into()));
                        }
                        Ready(Ok(_)) => (),
                    }

                    tls.process_new_packets()?;
                } else {
                    return Pending;
                }
            }

            Ready(Ok(()))
        })
        .await?;
        Ok(Self {
            peer_addr,
            tls,
            stream,
            close_state: CloseState::None,
            flags: 0,
        })
    }
}

/// Wrapper for [`AsyncRead`] and [`AsyncWrite`].
struct WrapAsync<'a, 'b, S> {
    cx: &'a mut Context<'b>,
    p: Pin<&'a mut S>,
}

impl<S: AsyncRead> Read for WrapAsync<'_, '_, S> {
    fn read(&mut self, buf: &mut [u8]) -> IoResult<usize> {
        poll_io_wrap(self.p.as_mut().poll_read(self.cx, buf))
    }

    fn read_vectored(&mut self, bufs: &mut [IoSliceMut<'_>]) -> IoResult<usize> {
        poll_io_wrap(self.p.as_mut().poll_read_vectored(self.cx, bufs))
    }
}

impl<S: AsyncWrite> Write for WrapAsync<'_, '_, S> {
    fn write(&mut self, buf: &[u8]) -> IoResult<usize> {
        poll_io_wrap(self.p.as_mut().poll_write(self.cx, buf))
    }

    fn write_vectored(&mut self, bufs: &[IoSlice<'_>]) -> IoResult<usize> {
        poll_io_wrap(self.p.as_mut().poll_write_vectored(self.cx, bufs))
    }

    fn flush(&mut self) -> IoResult<()> {
        poll_io_wrap(self.p.as_mut().poll_flush(self.cx))
    }
}

fn poll_io_wrap<R>(v: Poll<IoResult<R>>) -> IoResult<R> {
    match v {
        Ready(v) => v,
        Pending => Err(ErrorKind::WouldBlock.into()),
    }
}

fn poll_io_unwrap<R>(v: IoResult<R>) -> Poll<IoResult<R>> {
    match v {
        Err(e) if e.kind() == ErrorKind::WouldBlock => Pending,
        v => Ready(v),
    }
}

fn get_client_cfg() -> Result<Arc<ClientConfig>, RustlsError> {
    static CFG: OnceCell<Arc<ClientConfig>> = OnceCell::new();

    // TODO: Restrict ciphersuite in accordance with spec
    CFG.get_or_try_init(|| {
        Ok(Arc::new(
            ClientConfig::builder_with_provider(Arc::new(default_provider()))
                .with_safe_default_protocol_versions()?
                .dangerous()
                .with_custom_certificate_verifier(Arc::new(NullCertVerifier))
                .with_no_client_auth(),
        ))
    })
    .map(Arc::clone)
}

/// Null cerificate verifier.
#[derive(Debug)]
struct NullCertVerifier;

impl ServerCertVerifier for NullCertVerifier {
    fn verify_server_cert(
        &self,
        _: &CertificateDer<'_>,
        _: &[CertificateDer<'_>],
        _: &ServerName<'_>,
        _: &[u8],
        _: UnixTime,
    ) -> Result<ServerCertVerified, RustlsError> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _: &[u8],
        _: &CertificateDer<'_>,
        _: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, RustlsError> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _: &[u8],
        _: &CertificateDer<'_>,
        _: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, RustlsError> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        // TODO: All of them?
        vec![
            SignatureScheme::RSA_PKCS1_SHA1,
            SignatureScheme::ECDSA_SHA1_Legacy,
            SignatureScheme::RSA_PKCS1_SHA256,
            SignatureScheme::ECDSA_NISTP256_SHA256,
            SignatureScheme::RSA_PKCS1_SHA384,
            SignatureScheme::ECDSA_NISTP384_SHA384,
            SignatureScheme::RSA_PKCS1_SHA512,
            SignatureScheme::ECDSA_NISTP521_SHA512,
            SignatureScheme::RSA_PSS_SHA256,
            SignatureScheme::RSA_PSS_SHA384,
            SignatureScheme::RSA_PSS_SHA512,
            SignatureScheme::ED25519,
            SignatureScheme::ED448,
        ]
    }
}
