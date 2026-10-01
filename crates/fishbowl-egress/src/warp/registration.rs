//! Enrolling this gateway as a Cloudflare WARP device.
//!
//! `WARP` devices are registered through the same public endpoint the mobile client and
//! `wgcf` speak to. Two requests produce a device: a `POST /reg` that exchanges a fresh
//! `WireGuard` public key for a token, interface addresses and the tunnel's peer, and
//! a `PATCH /reg/{id}` that turns `WARP` on for it. The result is kept on disk — a device id
//! is stable across restarts, and re-registering on every boot would churn through the
//! service's rate limits.
//!
//! The endpoint pins TLS 1.2: it answers TLS 1.3 clients with an HTTP 403 (error 1020)
//! rather than a handshake failure, so a client that merely offers 1.3 gets refused
//! politely and late.

use std::{
    io,
    net::{Ipv4Addr, Ipv6Addr, SocketAddrV4},
    path::Path,
    str::FromStr,
    sync::Arc,
    time::Duration,
};

use base64::{Engine as _, engine::general_purpose::STANDARD as Base64};
use boringtun::x25519::{PublicKey, StaticSecret};
use hickory_proto::{
    op::{Message, MessageType, OpCode, Query},
    rr::{Name, RData, RecordType},
};
use http::{Method, Request, Uri, header};
use http_body_util::{BodyExt, Full};
use hyper::body::Bytes;
use hyper_util::rt::TokioIo;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use tokio::net::{TcpStream, UdpSocket};

/// Where the device API lives.
const API_HOST: &str = "api.cloudflareclient.com";

/// The API version the mobile client speaks; the path carries it.
const API_VERSION: &str = "v0a1922";

/// Longer than any one registration request is allowed to take.
const API_TIMEOUT: Duration = Duration::from_secs(15);

/// How long a direct DNS lookup may take.
const LOOKUP_TIMEOUT: Duration = Duration::from_secs(5);

/// The envelope the registry answers with; fields we do not need are ignored.
#[derive(Debug, Deserialize)]
struct Registration {
    id: String,
    token: String,
    config: DeviceConfig,
}

#[derive(Debug, Deserialize)]
struct DeviceConfig {
    peers: Vec<PeerConfig>,
    interface: InterfaceConfig,
}

#[derive(Debug, Deserialize)]
struct PeerConfig {
    public_key: PeerKey,
    endpoint: EndpointHints,
}

#[derive(Debug, Deserialize)]
struct PeerKey {
    key: String,
}

/// The peer's addresses; `v4` arrives as a `host:port` string whose port is `0` —
/// a placeholder — while `host` carries the canonical name and the real port. The `v6`
/// hint is skipped on purpose: the sandbox drops all IPv6 before it leaves.
#[derive(Debug, Deserialize)]
struct EndpointHints {
    v4: String,
    host: String,
    ports: Vec<u16>,
}

#[derive(Debug, Deserialize)]
struct InterfaceConfig {
    addresses: Addresses,
}

#[derive(Debug, Deserialize)]
struct Addresses {
    v4: Ipv4Addr,
    v6: Ipv6Addr,
}

/// What a registered device can build a tunnel from.
#[derive(Debug)]
pub struct Device {
    /// Our side of the `WireGuard` handshake.
    pub private_key: [u8; 32],
    /// The Cloudflare peer's public key.
    pub peer_public_key: [u8; 32],
    /// Where `WireGuard` datagrams are sent.
    pub endpoint: SocketAddrV4,
    /// The address the tunnel assigns our interface.
    pub address_v4: Ipv4Addr,
    /// The IPv6 address the tunnel assigns our interface.
    pub address_v6: Ipv6Addr,
}

/// The shape of `warp-device.json` — the registration between restarts.
#[derive(Debug, Serialize, Deserialize)]
struct DeviceFile {
    private_key: String,
    peer_public_key: String,
    endpoint: SocketAddrV4,
    address_v4: Ipv4Addr,
    address_v6: Ipv6Addr,
}

/// How registration can fail.
#[derive(Debug, Error)]
pub enum RegistrationError {
    /// The device file exists but cannot be read or parsed — it is kept for
    /// inspection and a fresh registration is not attempted over it.
    #[error("the WARP device file {path} is unusable: {reason}")]
    CorruptDeviceFile {
        /// Where the file lives.
        path: std::path::PathBuf,
        /// What went wrong with it.
        reason: String,
    },
    /// The bootstrap DNS lookup for the API host failed.
    #[error("resolving {API_HOST}: {0}")]
    Lookup(io::Error),
    /// The device API refused or could not be reached.
    #[error("the WARP device API answered {status}")]
    Refused {
        /// The HTTP status line's code.
        status: http::StatusCode,
    },
    /// The device API answered but not with a registration.
    #[error("the WARP device API returned a malformed response: {0}")]
    Malformed(#[from] serde_json::Error),
    /// Anything else on the wire.
    #[error(transparent)]
    Io(#[from] io::Error),
}

/// Returns a registered device, using `state_dir/warp-device.json` when it exists and
/// registering a fresh one when it does not.
///
/// `resolver` answers the bootstrap lookups — at this point no tunnel exists, so the
/// lookups and the registration itself go out directly, as gateway-originated traffic.
///
/// # Errors
/// Fails when the API cannot be reached or refuses, or when a stored device file exists
/// but cannot be read.
pub async fn load_or_register(
    state_dir: &Path,
    resolver: SocketAddrV4,
) -> Result<Device, RegistrationError> {
    let file = state_dir.join("warp-device.json");
    match tokio::fs::read(&file).await {
        Ok(bytes) => {
            let device: DeviceFile = serde_json::from_slice(&bytes).map_err(|error| {
                RegistrationError::CorruptDeviceFile {
                    path: file.clone(),
                    reason: error.to_string(),
                }
            })?;
            Ok(Device {
                private_key: decode_key(&device.private_key, &file)?,
                peer_public_key: decode_key(&device.peer_public_key, &file)?,
                endpoint: device.endpoint,
                address_v4: device.address_v4,
                address_v6: device.address_v6,
            })
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => register(&file, resolver).await,
        Err(error) => Err(RegistrationError::CorruptDeviceFile {
            path: file,
            reason: error.to_string(),
        }),
    }
}

/// A base64 `WireGuard` key, checked back into bytes.
fn decode_key(key: &str, file: &Path) -> Result<[u8; 32], RegistrationError> {
    Base64.decode(key).map_or_else(
        |_| Err(corrupt(file, "a stored key is not base64")),
        |bytes| {
            <[u8; 32]>::try_from(bytes.as_slice())
                .map_err(|_| corrupt(file, "a stored key is not 32 bytes"))
        },
    )
}

fn corrupt(file: &Path, reason: &str) -> RegistrationError {
    RegistrationError::CorruptDeviceFile {
        path: file.to_path_buf(),
        reason: reason.to_string(),
    }
}

/// Registers a fresh device and persists it.
async fn register(file: &Path, resolver: SocketAddrV4) -> Result<Device, RegistrationError> {
    let private = random_key();
    let public = PublicKey::from(&StaticSecret::from(private));
    let api = lookup_v4(API_HOST, resolver)
        .await
        .map_err(RegistrationError::Lookup)?;

    let registration: Registration = api_post(
        api,
        &format!("/{API_VERSION}/reg"),
        None,
        &serde_json::json!({
            "install_id": "",
            "tos": jiff::Timestamp::now().to_string(),
            "key": Base64.encode(public.as_bytes()),
            "fcm_token": "",
            "type": "Android",
            "model": "PC",
            "locale": "en_US",
        }),
    )
    .await?;

    // Registration leaves `warp_enabled` off; the device is not a tunnel until this lands.
    let _: serde::de::IgnoredAny = api_post(
        api,
        &format!("/{API_VERSION}/reg/{}", registration.id),
        Some(&registration.token),
        &serde_json::json!({ "warp_enabled": true }),
    )
    .await?;

    let peer = registration
        .config
        .peers
        .first()
        .ok_or_else(|| RegistrationError::Malformed(no_peers()))?;
    let endpoint = peer_endpoint(peer)?;
    let device_file = DeviceFile {
        private_key: Base64.encode(private),
        peer_public_key: peer.public_key.key.clone(),
        endpoint,
        address_v4: registration.config.interface.addresses.v4,
        address_v6: registration.config.interface.addresses.v6,
    };
    let device = Device {
        private_key: decode_key(&device_file.private_key, file)?,
        peer_public_key: decode_key(&device_file.peer_public_key, file)?,
        endpoint: device_file.endpoint,
        address_v4: device_file.address_v4,
        address_v6: device_file.address_v6,
    };

    if let Some(parent) = file.parent() {
        tokio::fs::create_dir_all(parent).await?;
    }
    tokio::fs::write(file, serde_json::to_vec_pretty(&device_file)?).await?;
    tracing::info!(%endpoint, "registered a WARP device");
    Ok(device)
}

fn no_peers() -> serde_json::Error {
    serde::de::Error::custom("the registration carried no WireGuard peers")
}

/// Where to send `WireGuard` datagrams: the API advertises the endpoint's port as `0` and
/// keeps the real one in `ports`, or implied by `host`.
fn peer_endpoint(peer: &PeerConfig) -> Result<SocketAddrV4, RegistrationError> {
    let candidate = peer
        .endpoint
        .v4
        .split(':')
        .next()
        .and_then(|address| address.parse::<Ipv4Addr>().ok())
        .or_else(|| {
            peer.endpoint
                .host
                .split(':')
                .next()
                .and_then(|address| address.parse::<Ipv4Addr>().ok())
        });
    let port = peer
        .endpoint
        .v4
        .split(':')
        .nth(1)
        .and_then(|port| port.parse::<u16>().ok())
        .filter(|port| *port != 0)
        .or_else(|| peer.endpoint.ports.first().copied())
        .or_else(|| {
            peer.endpoint
                .host
                .split(':')
                .nth(1)
                .and_then(|port| port.parse().ok())
        });
    match (candidate, port) {
        (Some(ip), Some(port)) => Ok(SocketAddrV4::new(ip, port)),
        _ => Err(RegistrationError::Malformed(serde::de::Error::custom(
            "the registration carried no usable IPv4 endpoint",
        ))),
    }
}

/// One JSON call against the device API, over TLS 1.2 by the pinned address.
async fn api_post<T: serde::de::DeserializeOwned>(
    api: Ipv4Addr,
    path: &str,
    token: Option<&str>,
    body: &serde_json::Value,
) -> Result<T, RegistrationError> {
    let bytes = serde_json::to_vec(body)?;

    let exchange = async {
        let tcp = TcpStream::connect((api, 443)).await?;
        let mut roots = rustls::RootCertStore::empty();
        roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        let config =
            rustls::ClientConfig::builder_with_protocol_versions(&[&rustls::version::TLS12])
                .with_root_certificates(roots)
                .with_no_client_auth();
        let connector = tokio_rustls::TlsConnector::from(Arc::new(config));
        let name = rustls::pki_types::ServerName::try_from(API_HOST)
            .expect("a static DNS name is a valid server name");
        let tls = connector.connect(name.to_owned(), tcp).await?;

        let (mut sender, connection) = hyper::client::conn::http1::handshake(TokioIo::new(tls))
            .await
            .map_err(io::Error::other)?;
        let driving = tokio::spawn(connection);

        let mut request = Request::builder()
            .method(Method::POST)
            .uri(Uri::from_str(path).expect("a static API path is a valid URI"))
            .header(header::HOST, API_HOST)
            .header(header::USER_AGENT, "okhttp/3.12.1")
            .header("CF-Client-Version", "a-6.3-1922")
            .header(header::ACCEPT, "application/json; charset=UTF-8")
            .header(header::CONTENT_TYPE, "application/json; charset=UTF-8");
        if let Some(token) = token {
            request = request.header(header::AUTHORIZATION, format!("Bearer {token}"));
        }
        let response = sender
            .send_request(
                request
                    .body(Full::new(Bytes::from(bytes)))
                    .expect("the registration request is well-formed"),
            )
            .await
            .map_err(io::Error::other)?;
        let status = response.status();
        let body = response
            .into_body()
            .collect()
            .await
            .map_err(io::Error::other)?
            .to_bytes();
        driving.abort();
        if !status.is_success() {
            return Err(RegistrationError::Refused { status });
        }
        Ok(body)
    };
    let body = tokio::time::timeout(API_TIMEOUT, exchange)
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "the WARP API did not answer"))??;
    Ok(serde_json::from_slice(&body)?)
}

/// A direct `A` lookup — the only name resolution that can never ride a tunnel, because
/// it is the lookup that precedes one.
async fn lookup_v4(name: &str, resolver: SocketAddrV4) -> Result<Ipv4Addr, io::Error> {
    let mut id = [0_u8; 2];
    getrandom::fill(&mut id).map_err(io::Error::other)?;
    let mut message = Message::new(u16::from_be_bytes(id), MessageType::Query, OpCode::Query);
    message.metadata.recursion_desired = true;
    message.add_query(Query::query(
        Name::from_str(name).map_err(io::Error::other)?,
        RecordType::A,
    ));
    let wire = message.to_vec().map_err(io::Error::other)?;

    let socket = UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0)).await?;
    socket.connect(resolver).await?;
    socket.send(&wire).await?;
    let mut buffer = vec![0_u8; 4096];
    let length = tokio::time::timeout(LOOKUP_TIMEOUT, socket.recv(&mut buffer)).await??;
    let answer = Message::from_vec(&buffer[..length]).map_err(io::Error::other)?;
    answer
        .answers
        .iter()
        .find_map(|record| match &record.data {
            RData::A(address) => Some(address.0),
            _ => None,
        })
        .ok_or_else(|| io::Error::other(format!("no A record for {name}")))
}

/// A fresh X25519 keypair, as its raw bytes.
fn random_key() -> [u8; 32] {
    let mut bytes = [0_u8; 32];
    getrandom::fill(&mut bytes).expect("the OS random source is available");
    bytes
}
