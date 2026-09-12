use std::path::PathBuf;

use jiff::Timestamp;

/// Failures while editing the host's agent configuration.
#[derive(Debug, thiserror::Error)]
pub enum AgentError {
    /// A configuration file could not be read or written.
    #[error("failed to access {path}")]
    Io {
        /// File involved.
        path: PathBuf,
        /// Underlying OS error.
        #[source]
        source: std::io::Error,
    },
    /// Claude Code's settings are not the JSON object they must be.
    #[error("{path} is not a JSON object")]
    NotAnObject {
        /// File involved.
        path: PathBuf,
    },
    /// Claude Code's settings could not be parsed.
    #[error("failed to parse {path} as JSON")]
    Json {
        /// File involved.
        path: PathBuf,
        /// Underlying parse error.
        #[source]
        source: serde_json::Error,
    },
    /// A configuration key the sandbox owns is present but holds the wrong kind of value.
    ///
    /// Overwriting it would destroy hand-written configuration, so registration stops.
    #[error("{key} in {path} is not the shape fishbowl expects")]
    UnexpectedShape {
        /// File involved.
        path: PathBuf,
        /// Key involved.
        key: &'static str,
    },
    /// Nothing is stored where the researcher's Claude Code keeps its login.
    #[error("no Claude Code login is stored under {service}; run claude on the host and sign in")]
    NoLogin {
        /// Keychain service name looked for.
        service: String,
    },
    /// The keychain would not hand the login over.
    #[error("the keychain refused to hand over {service}")]
    Keychain {
        /// Keychain service name looked for.
        service: String,
        /// Underlying keychain error.
        #[source]
        source: security_framework::base::Error,
    },
    /// The thread the keychain was asked from did not come back.
    #[error("the keychain read of {service} did not finish")]
    KeychainUnreachable {
        /// Keychain service name looked for.
        service: String,
        /// Underlying task error.
        #[source]
        source: tokio::task::JoinError,
    },
    /// What is stored is not what Claude Code writes there.
    #[error("the Claude Code login stored under {service} is not the shape it should be")]
    StoredLogin {
        /// Keychain service name read.
        service: String,
        /// Underlying parse error.
        #[source]
        source: serde_json::Error,
    },
    /// The login is not the subscription one a session can borrow.
    ///
    /// An API key is not lent: it does not expire on its own, so a session holding one
    /// holds it for good.
    #[error("the Claude Code login stored under {service} is not an OAuth subscription login")]
    NotOauth {
        /// Keychain service name read.
        service: String,
    },
    /// The access token has already expired.
    ///
    /// Only the researcher's own Claude Code may renew it: renewing rotates the refresh
    /// token, so a second process doing it would sign them out of their own machine.
    #[error(
        "the Claude Code access token under {service} expired at {expired_at}; run claude \
         on the host once to renew it"
    )]
    LoginExpired {
        /// Keychain service name read.
        service: String,
        /// When it stopped being accepted.
        expired_at: Timestamp,
    },
    /// Codex's environments file could not be parsed.
    #[error("failed to parse {path} as TOML")]
    Toml {
        /// File involved.
        path: PathBuf,
        /// Underlying parse error.
        #[source]
        source: toml_edit::TomlError,
    },
    /// Nothing is stored where the researcher's Devin keeps its login.
    #[error("no Devin login is stored at {}; run `devin auth login` on the host and sign in", path.display())]
    NoDevinLogin {
        /// Credentials file looked for.
        path: PathBuf,
    },
    /// What is stored there does not carry the key that makes it a login.
    #[error("{} is not the credentials file Devin writes: it carries no API key", path.display())]
    NotDevinLogin {
        /// File involved.
        path: PathBuf,
    },
}
