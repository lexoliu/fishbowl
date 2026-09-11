//! What the host's agents need before a session can run them.
//!
//! The three agents want three different things. Codex keeps its model side — and with
//! it the credential — on the host and runs only its tool side in the session, which
//! takes an entry in its own configuration file. Claude Code and Devin have no such
//! split: they run whole inside the session and are lent the researcher's login to do
//! it, an access token for one and the credentials file for the other. So this crate
//! edits Codex's files, reads Claude's keychain entry and reads Devin's file, and no
//! agent ever needs the session to have a login of its own.
//!
//! Existing configuration is preserved: Codex's files are edited as TOML documents, so
//! hand-written entries and comments survive, and Claude's and Devin's logins are only
//! read.

mod claude;
mod codex;
mod devin;
mod endpoint;
mod error;
mod toml_file;

pub use claude::ClaudeLogin;
pub use codex::{Codex, CodexConfig, CodexEnvironments};
pub use devin::DevinLogin;
pub use endpoint::SandboxEndpoint;
pub use error::AgentError;

use std::path::{Path, PathBuf};

/// The host-side configuration a sandbox writes itself into, and the logins a session
/// can borrow from.
///
/// Only Codex has any configuration: Claude Code and Devin are run inside the session
/// rather than pointed at it, so there is nothing about a session for the host's copies
/// to remember, and nothing left behind when one ends.
#[derive(Debug, Clone)]
pub struct AgentIntegration {
    codex: Codex,
    devin: DevinLogin,
}

impl AgentIntegration {
    /// Locates the configuration under `home`.
    #[must_use]
    pub fn for_home(home: &Path) -> Self {
        Self {
            codex: Codex::for_home(home),
            devin: DevinLogin::for_home(home),
        }
    }

    /// Codex's configuration, where the sandbox appears as a stdio-over-SSH environment.
    #[must_use]
    pub fn codex(&self) -> &Codex {
        &self.codex
    }

    /// The researcher's Devin login, which a session borrows for the length of a run.
    #[must_use]
    pub fn devin(&self) -> &DevinLogin {
        &self.devin
    }

    /// Removes the entries belonging to `id`.
    ///
    /// # Errors
    /// Fails when a file cannot be read, parsed or written.
    pub async fn unregister(&self, id: &str) -> Result<(), AgentError> {
        self.codex.unregister(id).await
    }
}

/// Where the sandbox's own SSH material lives on the host.
#[must_use]
pub fn key_directory(home: &Path) -> PathBuf {
    home.join(".cyber-sandbox").join("keys")
}

/// Where the host keys sandboxes present are remembered, one file per sandbox.
#[must_use]
pub fn known_hosts_directory(home: &Path) -> PathBuf {
    home.join(".cyber-sandbox").join("known_hosts")
}

/// Where the directories agents are pointed at live, one per sandbox.
///
/// An agent whose model side runs on the host resolves the directory it is working in
/// against the host's own filesystem, then asks the sandbox to execute there. So the path
/// it is given has to exist on both sides — and the sandbox aliases its copy to the work
/// directory, which is why the host's copy stays empty. Nothing is shared through it: it
/// exists only so that the path the agent validates is a path the sandbox can honour.
#[must_use]
pub fn work_alias_directory(home: &Path) -> PathBuf {
    home.join(".cyber-sandbox").join("work")
}

/// Replaces `path` with `contents`, creating the parent directory and never leaving a
/// half-written configuration behind if the process dies mid-write.
async fn write_file(path: &Path, contents: &str) -> Result<(), AgentError> {
    if let Some(parent) = path.parent() {
        tokio::fs::create_dir_all(parent)
            .await
            .map_err(|source| AgentError::Io {
                path: parent.to_path_buf(),
                source,
            })?;
    }
    let staging = path.with_extension("cyber-sandbox-staging");
    tokio::fs::write(&staging, contents)
        .await
        .map_err(|source| AgentError::Io {
            path: staging.clone(),
            source,
        })?;
    tokio::fs::rename(&staging, path)
        .await
        .map_err(|source| AgentError::Io {
            path: path.to_path_buf(),
            source,
        })
}
