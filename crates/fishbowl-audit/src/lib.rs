//! Schema and transport for the fishbowl network audit trail.
//!
//! The in-VM gateway is the sole writer: it appends one [`AuditRecord`] per line to a
//! JSONL file on a volume that only the gateway uid may write. The macOS host reads the
//! same file through the container mount. Keeping the schema in a shared crate means a
//! renamed or dropped field breaks both sides at compile time instead of silently
//! producing an unreadable trail.

mod record;

#[cfg(feature = "io")]
mod io;

pub use record::{
    AuditEvent, AuditRecord, BlockReason, Blocked, Connect, DnsAnswer, DnsQuery, Endpoint,
    HttpExchange, TlsHandshake, Transport,
};

#[cfg(feature = "io")]
pub use io::{AuditReader, AuditWriter};

/// Errors raised while serialising or transporting audit records.
#[derive(Debug, thiserror::Error)]
pub enum AuditError {
    /// The audit trail could not be read from or written to.
    #[error("audit trail I/O failed at {path}")]
    Io {
        /// Path of the audit trail involved.
        path: std::path::PathBuf,
        /// Underlying OS error.
        #[source]
        source: std::io::Error,
    },
    /// A line in the trail was not a valid [`AuditRecord`].
    #[error("audit trail line {line} is not a valid record")]
    Malformed {
        /// One-based line number within the trail.
        line: u64,
        /// Underlying deserialisation error.
        #[source]
        source: serde_json::Error,
    },
    /// A record could not be encoded.
    #[error("failed to encode audit record")]
    Encode(#[source] serde_json::Error),
}
