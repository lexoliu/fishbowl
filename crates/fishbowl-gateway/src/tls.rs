//! TLS interception.
//!
//! Auditing an encrypted stream means being one of its endpoints. The gateway terminates
//! the sandbox's session with a leaf it mints on the spot and opens its own, verified
//! session to the real destination, so the record of what crossed the boundary is exact
//! rather than inferred from packet sizes.

use std::{net::SocketAddr, sync::Arc};

use fishbowl_audit::{Endpoint, TlsHandshake};
use rustls::{ClientConfig, RootCertStore, ServerConfig, pki_types::ServerName};
use sha2::{Digest, Sha256};
use tokio::{
    io::{AsyncRead, AsyncWrite},
    net::TcpStream,
};
use tokio_rustls::{TlsAcceptor, TlsConnector, client, server};

use crate::{
    ca::{CertificateAuthority, InterceptResolver},
    error::{GatewayError, Result},
};

/// The only protocol the gateway is able to audit inside TLS.
const ALPN_HTTP11: &[u8] = b"http/1.1";

/// Both halves of an intercepted TLS session plus what the handshake revealed.
pub struct InterceptedTls<S> {
    /// Session with the sandbox, terminated by the gateway's minted leaf.
    pub sandbox: server::TlsStream<S>,
    /// Session with the real destination, verified against the public roots.
    pub upstream: client::TlsStream<TcpStream>,
    /// What the two handshakes agreed on.
    pub handshake: TlsHandshake,
}

/// Terminates sandbox TLS sessions and re-originates them upstream.
#[derive(Debug)]
pub struct TlsBridge {
    authority: Arc<CertificateAuthority>,
    upstream: Arc<ClientConfig>,
}

impl TlsBridge {
    /// Builds the bridge, pinning upstream verification to the public root store.
    #[must_use]
    pub fn new(authority: Arc<CertificateAuthority>) -> Self {
        let roots = RootCertStore {
            roots: webpki_roots::TLS_SERVER_ROOTS.to_vec(),
        };
        let mut upstream = ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth();
        upstream.alpn_protocols = vec![ALPN_HTTP11.to_vec()];
        Self {
            authority,
            upstream: Arc::new(upstream),
        }
    }

    /// Terminates `sandbox`, connects to `destination`, and reports the handshake.
    ///
    /// # Errors
    /// Fails when either handshake fails, when the destination is unreachable, or when
    /// the upstream presents no certificate.
    pub async fn intercept<S>(
        &self,
        sandbox: S,
        peer: SocketAddr,
        destination: SocketAddr,
    ) -> Result<InterceptedTls<S>>
    where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        let resolver =
            InterceptResolver::new(Arc::clone(&self.authority), destination.ip().to_string());
        let mut server_config = ServerConfig::builder()
            .with_no_client_auth()
            .with_cert_resolver(Arc::new(resolver));
        server_config.alpn_protocols = vec![ALPN_HTTP11.to_vec()];

        let sandbox = TlsAcceptor::from(Arc::new(server_config))
            .accept(sandbox)
            .await
            .map_err(|source| GatewayError::Tls { peer, source })?;
        let server_name = sandbox.get_ref().1.server_name().map(str::to_owned);

        let upstream_name = match &server_name {
            Some(name) => ServerName::try_from(name.clone()).map_err(|_| GatewayError::Tls {
                peer,
                source: std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "the sandbox requested a server name that is not a valid DNS name",
                ),
            })?,
            None => ServerName::IpAddress(destination.ip().into()),
        };

        let upstream_tcp =
            TcpStream::connect(destination)
                .await
                .map_err(|source| GatewayError::Socket {
                    context: "connecting to the destination of an intercepted TLS connection",
                    source,
                })?;
        let upstream = TlsConnector::from(Arc::clone(&self.upstream))
            .connect(upstream_name, upstream_tcp)
            .await
            .map_err(|source| GatewayError::Tls { peer, source })?;

        let connection = upstream.get_ref().1;
        let upstream_cert_sha256 = connection
            .peer_certificates()
            .and_then(<[_]>::first)
            .map(|certificate| {
                let digest = Sha256::digest(certificate.as_ref());
                digest.iter().fold(String::new(), |mut hex, byte| {
                    use std::fmt::Write as _;
                    let _ = write!(hex, "{byte:02x}");
                    hex
                })
            })
            .ok_or_else(|| GatewayError::Tls {
                peer,
                source: std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "the destination presented no certificate",
                ),
            })?;
        let alpn = connection
            .alpn_protocol()
            .map(|protocol| String::from_utf8_lossy(protocol).into_owned());

        let handshake = TlsHandshake {
            destination: Endpoint {
                ip: destination.ip(),
                port: destination.port(),
            },
            server_name,
            alpn,
            upstream_cert_sha256,
        };
        Ok(InterceptedTls {
            sandbox,
            upstream,
            handshake,
        })
    }
}
