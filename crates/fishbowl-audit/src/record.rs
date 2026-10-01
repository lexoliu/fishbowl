use std::net::IpAddr;

use jiff::Timestamp;
use serde::{Deserialize, Serialize};

/// A single line of the audit trail.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditRecord {
    /// When the gateway observed the event.
    pub at: Timestamp,
    /// Name of the sandbox that produced the event.
    pub sandbox: String,
    /// Numeric uid inside the sandbox that owned the originating socket, when the
    /// gateway could attribute it.
    pub uid: Option<u32>,
    /// What happened.
    pub event: AuditEvent,
}

/// How much of the sandbox's traffic the gateway is asked to inspect.
///
/// This is a separate axis from the egress mode: the mode decides which network a
/// connection leaves on, the tier decides what the gateway does to it first. Every
/// packet still crosses the gateway — `off` turns the recorder down, it does not open
/// a side channel around the egress policy.
#[derive(
    Debug,
    Clone,
    Copy,
    Default,
    PartialEq,
    Eq,
    clap::ValueEnum,
    serde::Serialize,
    serde::Deserialize,
)]
#[serde(rename_all = "lowercase")]
pub enum Tier {
    /// Terminate TLS and parse everything that can be parsed; whatever cannot be
    /// audited in cleartext — QUIC, other UDP, IPv6 — is refused rather than carried.
    /// The failure mode favours completeness: a sample that insists on QUIC has no
    /// network, and the trail stays the whole story.
    Strict,
    /// Audit everything that can be audited without standing in the connection's way:
    /// DNS questions are answered and recorded, TLS client hellos are read for their
    /// SNI but never terminated, HTTP is parsed where it is plaintext, and traffic no
    /// route can carry is refused immediately rather than dropped into a timeout.
    /// Encrypted payloads pass end-to-end.
    #[default]
    Default,
    /// Relay only: connections are forwarded and nothing about them is written. The
    /// egress layer's own route reports are still recorded — they carry no user data,
    /// and they are the host's only proof that a strict egress mode is enforced.
    Off,
}

impl std::fmt::Display for Tier {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::Strict => "strict",
            Self::Default => "default",
            Self::Off => "off",
        })
    }
}

/// A string that names no audit tier.
#[derive(Debug, thiserror::Error)]
#[error("`{0}` is not an audit tier; expected one of: strict, default, off")]
pub struct NotATier(String);

impl std::str::FromStr for Tier {
    type Err = NotATier;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        for tier in [Self::Strict, Self::Default, Self::Off] {
            if tier.to_string() == value {
                return Ok(tier);
            }
        }
        Err(NotATier(value.to_owned()))
    }
}

/// The observable network events the gateway records.
///
/// Every egress path the sandbox has is represented here: anything the gateway cannot
/// classify into one of these variants is refused by the packet filter and lands as
/// [`AuditEvent::Blocked`], so an empty trail means no egress rather than lost egress.
/// Under the `default` and `off` audit tiers the refusal is a rejection the client
/// sees at once instead of a drop it waits out, and traffic a route can carry is
/// relayed rather than refused — recorded as [`AuditEvent::Forwarded`].
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum AuditEvent {
    /// A DNS question the sandbox asked, and what the gateway answered.
    Dns(DnsQuery),
    /// A TCP connection the sandbox opened through the transparent proxy.
    Connect(Connect),
    /// A TLS handshake the gateway terminated and re-originated.
    Tls(TlsHandshake),
    /// A TLS session the gateway read the client hello of and relayed untouched —
    /// the `default` tier's record of a connection it never decrypted.
    TlsSeen(TlsSeen),
    /// A complete HTTP request/response pair seen inside a proxied connection.
    Http(HttpExchange),
    /// Which network the gateway's own upstream traffic rides on, recorded when it
    /// changes — a tunnel raised, a tunnel lost, a fallback taken.
    Egress(Egress),
    /// A packet the filter forwarded without inspection, because the audit tier does
    /// not refuse what it cannot parse and the egress mode permits the route. The
    /// payload went out unaudited by design; the attempt is still part of the trail.
    Forwarded(Forwarded),
    /// Traffic the packet filter refused.
    Blocked(Blocked),
}

/// A network endpoint as seen by the gateway.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Endpoint {
    /// Address the sandbox originally targeted, recovered via `SO_ORIGINAL_DST`.
    pub ip: IpAddr,
    /// Destination port.
    pub port: u16,
}

/// Layer-4 protocol of an audited flow.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Transport {
    /// Transmission Control Protocol.
    Tcp,
    /// User Datagram Protocol.
    Udp,
    /// Anything that is neither TCP nor UDP.
    Other,
}

/// A DNS question and its resolution.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsQuery {
    /// Queried name, as sent by the sandbox.
    pub name: String,
    /// Queried record type mnemonic, e.g. `A`, `AAAA`, `HTTPS`.
    pub record_type: String,
    /// Records the gateway returned.
    pub answers: Vec<DnsAnswer>,
    /// Upstream resolver consulted, absent when the answer came from cache.
    pub upstream: Option<Endpoint>,
    /// Wall-clock time the resolution took.
    pub elapsed_ms: u64,
}

/// One resolved DNS record.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsAnswer {
    /// Record type mnemonic of the answer.
    pub record_type: String,
    /// Rendered record data.
    pub data: String,
}

/// A proxied TCP connection.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Connect {
    /// Original destination the sandbox dialled.
    pub destination: Endpoint,
    /// Hostname the destination address was most recently resolved from, when the
    /// gateway's DNS interceptor saw the lookup that produced it.
    pub resolved_from: Option<String>,
    /// Bytes the sandbox sent upstream.
    pub bytes_out: u64,
    /// Bytes the gateway relayed back to the sandbox.
    pub bytes_in: u64,
    /// How long the connection stayed open.
    pub elapsed_ms: u64,
}

/// A TLS handshake terminated by the gateway.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TlsHandshake {
    /// Original destination the sandbox dialled.
    pub destination: Endpoint,
    /// Server name the client requested, absent when the client sent no SNI.
    pub server_name: Option<String>,
    /// ALPN protocol negotiated with the upstream server.
    pub alpn: Option<String>,
    /// SHA-256 fingerprint of the upstream leaf certificate, lowercase hex.
    pub upstream_cert_sha256: String,
}

/// A TLS session observed rather than terminated: what the client hello offered.
///
/// Everything in it is what the client declared — the gateway never sees the upstream
/// certificate or the negotiated ALPN on a connection it relays end-to-end, so those
/// fields belong to [`TlsHandshake`] alone.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TlsSeen {
    /// Original destination the sandbox dialled.
    pub destination: Endpoint,
    /// Server name the client offered, absent when it offered none.
    pub server_name: Option<String>,
    /// ALPN protocols the client offered.
    pub alpn: Vec<String>,
}

/// A packet forwarded without inspection.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Forwarded {
    /// Layer-4 protocol of the passed flow.
    pub transport: Transport,
    /// Destination the sandbox sent it to.
    pub destination: Endpoint,
}

/// A full HTTP exchange observed inside a proxied connection.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HttpExchange {
    /// Request method.
    pub method: String,
    /// Absolute request URL reconstructed from the request line and `Host` header.
    pub url: String,
    /// Request header names and values the gateway retained.
    pub request_headers: Vec<(String, String)>,
    /// Request body size in bytes.
    pub request_bytes: u64,
    /// Response status code.
    pub status: u16,
    /// Response header names and values the gateway retained.
    pub response_headers: Vec<(String, String)>,
    /// Response body size in bytes.
    pub response_bytes: u64,
    /// Wall-clock time from request line to final response byte.
    pub elapsed_ms: u64,
}

/// A change in which network carries the gateway's upstream connections.
///
/// The gateway's outbound sockets are what the sandbox's traffic travels over once
/// audited, so which route they take is itself part of the trail: it is the difference
/// between a record written through a Cloudflare exit and one written through the
/// machine's own address.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Egress {
    /// What upstream traffic goes over now.
    pub route: Route,
    /// Why the route is this one, when it is a fallback or an outage rather than the
    /// transport the session asked for.
    pub reason: Option<String>,
    /// Which supervised leg this report is about, when the egress runs more than
    /// one: the `torsion` uid's dedicated Tor leg reports under `leg: "torsion"`,
    /// while the base route every other connection falls to reports without one.
    /// Readers proving enforcement read the leg-less records.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub leg: Option<String>,
}

/// The network carrying the gateway's own connections.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Route {
    /// A Cloudflare WARP tunnel.
    Warp,
    /// The Tor network.
    Tor,
    /// The plain internet, by the machine's own address.
    Direct,
    /// Nothing: a strict mode's transport is down, so egress is refused.
    Down,
}

impl std::fmt::Display for Route {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::Warp => "warp",
            Self::Tor => "tor",
            Self::Direct => "direct",
            Self::Down => "down",
        })
    }
}

/// Traffic the packet filter refused to forward.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Blocked {
    /// Layer-4 protocol of the refused flow.
    pub transport: Transport,
    /// Destination the sandbox attempted to reach.
    pub destination: Endpoint,
    /// Why the flow was refused.
    pub reason: BlockReason,
}

/// Why the gateway refused a flow.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BlockReason {
    /// The protocol cannot be audited in cleartext, so the filter drops it and forces
    /// the client onto an auditable transport. QUIC is the motivating case.
    UnauditableTransport,
    /// The destination port has no transparent handler.
    NoHandler,
    /// The upstream connection failed and the gateway reported it as refused.
    UpstreamUnreachable,
    /// The egress transport the session's policy requires is down, so the request was
    /// refused rather than let out unaudited.
    EgressUnavailable,
    /// No route the session permits can carry the packet — UDP under a Tor-only
    /// egress, or IPv6 anywhere. The packet is refused immediately; this is the
    /// audit tier's fast refusal, not the strict tier's drop.
    NoRoute,
}
