use std::path::PathBuf;

use crate::file::MAX_BYTES;

/// Failures while lending a credential to a session, or writing one down inside it.
#[derive(Debug, thiserror::Error)]
pub enum CredentialError {
    /// The credential could not be encoded.
    #[error("failed to encode the credential")]
    Encode(#[source] serde_json::Error),
    /// What arrived was not the credential it must be.
    #[error("the credential that arrived was not the JSON it must be")]
    Decode(#[source] serde_json::Error),
    /// The connection carrying the credential failed.
    #[error("the connection carrying the credential failed")]
    Stream(#[source] std::io::Error),
    /// The credentials file could not be written or removed.
    #[error("failed to access {path}")]
    Io {
        /// File involved.
        path: PathBuf,
        /// Underlying OS error.
        #[source]
        source: std::io::Error,
    },
    /// The credentials file would be larger than the reader will look at.
    ///
    /// Claude Code stops at [`MAX_BYTES`] without reading, so a file past it is not a
    /// large credential but an unreadable one, and it is refused where it is written
    /// rather than ignored where it is read.
    #[error("the credentials file would be {size} bytes, past the {MAX_BYTES} Claude Code reads")]
    TooLarge {
        /// Size the encoded file would have had.
        size: usize,
    },
}
