use std::{net::SocketAddr, path::PathBuf};

/// Everything that can go wrong inside the gateway.
#[derive(Debug, thiserror::Error)]
pub enum GatewayError {
    /// A socket operation failed.
    #[error("socket operation failed on {context}")]
    Socket {
        /// What the gateway was doing.
        context: &'static str,
        /// Underlying OS error.
        #[source]
        source: std::io::Error,
    },
    /// A file the gateway owns could not be read or written.
    #[error("failed to access {path}")]
    File {
        /// Path involved.
        path: PathBuf,
        /// Underlying OS error.
        #[source]
        source: std::io::Error,
    },
    /// The certificate authority could not be created or loaded.
    #[error("certificate authority error")]
    Certificate(#[from] rcgen::Error),
    /// A TLS session failed.
    #[error("TLS error while talking to {peer}")]
    Tls {
        /// Peer the session was with.
        peer: SocketAddr,
        /// Underlying rustls error.
        #[source]
        source: std::io::Error,
    },
    /// The redirected connection carried no original destination.
    #[error("the connection from {peer} has no netfilter original destination")]
    NoOriginalDestination {
        /// Peer address of the redirected connection.
        peer: SocketAddr,
    },
    /// The gateway only handles IPv4; the egress policy drops IPv6 outright.
    #[error("connection from {peer} is not IPv4, which the egress policy never permits")]
    NotIpv4 {
        /// Peer address of the redirected connection.
        peer: SocketAddr,
    },
    /// A DNS message could not be parsed.
    #[error("malformed DNS message")]
    Dns(#[from] hickory_proto::serialize::binary::DecodeError),
    /// The audit trail could not be written.
    #[error("audit trail error")]
    Audit(#[from] fishbowl_audit::AuditError),
    /// The rustls configuration was rejected.
    #[error("TLS configuration error")]
    TlsConfig(#[from] rustls::Error),
}

/// Result alias used throughout the gateway.
pub type Result<T, E = GatewayError> = std::result::Result<T, E>;
