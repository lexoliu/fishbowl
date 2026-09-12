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

/// The observable network events the gateway records.
///
/// Every egress path the sandbox has is represented here: anything the gateway cannot
/// classify into one of these variants is refused by the packet filter and lands as
/// [`AuditEvent::Blocked`], so an empty trail means no egress rather than lost egress.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum AuditEvent {
    /// A DNS question the sandbox asked, and what the gateway answered.
    Dns(DnsQuery),
    /// A TCP connection the sandbox opened through the transparent proxy.
    Connect(Connect),
    /// A TLS handshake the gateway terminated and re-originated.
    Tls(TlsHandshake),
    /// A complete HTTP request/response pair seen inside a proxied connection.
    Http(HttpExchange),
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
}
