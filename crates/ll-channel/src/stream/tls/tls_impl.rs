use std::borrow::Cow;
use std::io::{Read, Result as IoResult, Write};
use std::net::SocketAddr;
use std::sync::Arc;

use once_cell::sync::OnceCell;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::client::{ClientConfig, ClientConnection};
use rustls::crypto::ring::default_provider;
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{DigitallySignedStruct, Error as RustlsError, SignatureScheme};

use super::{ClientTLSLike, TLSLike};
use crate::error::ChannelError;

/// Wrapper for [`ClientConnection`].
pub struct RustlsWrapper(ClientConnection);

impl TLSLike for RustlsWrapper {
    fn leaf_cert(&self) -> Option<Cow<'_, [u8]>> {
        self.0.peer_certificates()?.first().map(|v| (&v[..]).into())
    }

    fn is_handshaking(&self) -> bool {
        self.0.is_handshaking()
    }

    fn wants_read(&self) -> bool {
        self.0.wants_read()
    }

    fn wants_write(&self) -> bool {
        self.0.wants_write()
    }

    fn process_new_packets(&mut self) -> Result<(), ChannelError> {
        self.0.process_new_packets()?;
        Ok(())
    }

    fn send_close_notify(&mut self) {
        self.0.send_close_notify();
    }

    fn reader(&mut self) -> impl '_ + Read {
        self.0.reader()
    }

    fn writer(&mut self) -> impl '_ + Write {
        self.0.writer()
    }

    fn read_tls(&mut self, r: &mut dyn Read) -> IoResult<usize> {
        self.0.read_tls(r)
    }

    fn write_tls(&mut self, w: &mut dyn Write) -> IoResult<usize> {
        self.0.write_tls(w)
    }
}

impl ClientTLSLike for RustlsWrapper {
    fn new(peer_addr: SocketAddr) -> Result<Self, ChannelError> {
        Ok(Self(ClientConnection::new(
            get_client_cfg()?,
            ServerName::IpAddress(peer_addr.ip().into()),
        )?))
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
