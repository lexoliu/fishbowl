//! Codex's side of a session, which is two files rather than one.
//!
//! Codex has no notion of a remote machine it can be pointed at from the command line.
//! What it has is `environments.toml`, where an entry whose transport is a stdio command
//! becomes a machine it runs its tool side on, and `config.toml`, where it remembers
//! which directories the researcher has said they trust. A session needs both: the entry
//! so that Codex has somewhere to execute, and the trust so that opening it does not
//! begin with a question about a directory fishbowl made moments earlier.
//!
//! They are written together and taken back out together, because either one left behind
//! is a lie about the researcher's machine — a dead session in their environment list, or
//! a trusted directory that no longer exists.

mod config;
mod environments;

pub use config::CodexConfig;
pub use environments::CodexEnvironments;

use std::path::{Path, PathBuf};

use crate::{endpoint::SandboxEndpoint, error::AgentError, work_alias_directory};

/// Codex as it is configured on the host, for the length of one session.
#[derive(Debug, Clone)]
pub struct Codex {
    environments: CodexEnvironments,
    config: CodexConfig,
    work_aliases: PathBuf,
}

impl Codex {
    /// Locates Codex's configuration under `home`.
    #[must_use]
    pub fn for_home(home: &Path) -> Self {
        let codex = home.join(".codex");
        Self {
            environments: CodexEnvironments::new(codex.join("environments.toml")),
            config: CodexConfig::new(codex.join("config.toml")),
            work_aliases: work_alias_directory(home),
        }
    }

    /// The file sessions appear in as environments.
    #[must_use]
    pub fn environments(&self) -> &CodexEnvironments {
        &self.environments
    }

    /// The file directory trust is remembered in.
    #[must_use]
    pub fn config(&self) -> &CodexConfig {
        &self.config
    }

    /// The directory Codex is pointed at for session `id`.
    #[must_use]
    pub fn work_alias(&self, id: &str) -> PathBuf {
        self.work_aliases.join(id)
    }

    /// Makes a session available to Codex, and its directory one Codex opens without
    /// asking.
    ///
    /// # Errors
    /// Fails when either file cannot be read, parsed or written.
    pub async fn register(&self, endpoint: &SandboxEndpoint) -> Result<(), AgentError> {
        self.environments.register(endpoint).await?;
        self.config.trust(&self.work_alias(&endpoint.id)).await
    }

    /// Takes session `id` back out of both files.
    ///
    /// # Errors
    /// Fails when either file cannot be read, parsed or written.
    pub async fn unregister(&self, id: &str) -> Result<(), AgentError> {
        self.environments.unregister(id).await?;
        self.config.distrust(&self.work_alias(id)).await
    }

    /// The environment Codex opens with when it is given none, if it has one.
    ///
    /// # Errors
    /// Fails when the file cannot be read or parsed.
    pub async fn selected(&self) -> Result<Option<String>, AgentError> {
        self.environments.selected().await
    }

    /// Chooses the environment Codex opens with, or leaves it choosing none.
    ///
    /// # Errors
    /// Fails when the file cannot be read, parsed or written.
    pub async fn select(&self, id: Option<&str>) -> Result<(), AgentError> {
        self.environments.select(id).await
    }
}
