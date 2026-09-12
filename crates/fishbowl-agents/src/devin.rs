//! The researcher's own Devin login, read so a session can borrow it.
//!
//! Devin keeps its login in a credentials file, not the keychain, and the file is the
//! whole credential: the session key and the endpoints it authenticates to. There is no
//! short-lived part to lend separately the way Claude Code's access token is, so what a
//! session is handed is the file itself, verbatim — and what makes that a loan rather
//! than a copy is that the courier removes it when the agent exits, so the key exists
//! inside the machine only for as long as the agent runs.
//!
//! This module never writes the file and never logs its contents.

use std::path::{Path, PathBuf};

use crate::error::AgentError;

/// Environment variable naming the directory above `devin/` that the credentials file
/// lives in — the same one the installer resolves.
const DATA_HOME: &str = "XDG_DATA_HOME";

/// The credentials file, relative to the data directory.
const CREDENTIALS: &[&str] = &["devin", "credentials.toml"];

/// The one field a usable file must carry.
const API_KEY: &str = "windsurf_api_key";

/// The researcher's Devin credentials file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DevinLogin {
    path: PathBuf,
}

impl DevinLogin {
    /// Locates the file this machine's Devin would be reading.
    ///
    /// The resolution is the installer's: `$XDG_DATA_HOME` when it names a directory,
    /// `~/.local/share` otherwise.
    #[must_use]
    pub fn for_home(home: &Path) -> Self {
        let base = std::env::var_os(DATA_HOME)
            .filter(|value| !value.is_empty())
            .map_or_else(|| home.join(".local").join("share"), PathBuf::from);
        Self {
            path: CREDENTIALS.iter().fold(base, |path, part| path.join(part)),
        }
    }

    /// The path being read.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Reads the file and answers with its contents, verified to be a login.
    ///
    /// The contents go to the session unchanged: the endpoints Devin speaks to are part
    /// of the credential, and re-serialising what was read would be the file drifting.
    /// What is checked is only that the file is one — that it parses, and that it carries
    /// a key — so a truncated or hand-edited file fails here rather than inside the
    /// session.
    ///
    /// # Errors
    /// Fails when there is no login to borrow, when the file cannot be read, or when
    /// what is stored does not carry an API key.
    pub async fn document(&self) -> Result<String, AgentError> {
        let contents = match tokio::fs::read_to_string(&self.path).await {
            Ok(contents) => contents,
            Err(source) if source.kind() == std::io::ErrorKind::NotFound => {
                return Err(AgentError::NoDevinLogin {
                    path: self.path.clone(),
                });
            }
            Err(source) => {
                return Err(AgentError::Io {
                    path: self.path.clone(),
                    source,
                });
            }
        };
        let parsed: toml_edit::DocumentMut =
            contents.parse().map_err(|source| AgentError::Toml {
                path: self.path.clone(),
                source,
            })?;
        match parsed.get(API_KEY).and_then(|key| key.as_str()) {
            Some(key) if !key.is_empty() => Ok(contents),
            _ => Err(AgentError::NotDevinLogin {
                path: self.path.clone(),
            }),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn the_file_is_found_where_the_installer_puts_it() {
        let home = Path::new("/Users/researcher");
        assert_eq!(
            DevinLogin::for_home(home).path(),
            Path::new("/Users/researcher/.local/share/devin/credentials.toml")
        );
    }

    #[tokio::test]
    async fn a_credentials_file_is_lent_verbatim() {
        let directory = TempDir::new().unwrap();
        let path = directory.path().join("credentials.toml");
        let contents = "windsurf_api_key = \"devin-session-x\"\n\
                        api_server_url = \"https://server.example\"\n\
                        devin_webapp_host = \"https://app.example\"\n\
                        devin_api_url = \"https://api.example\"\n";
        tokio::fs::write(&path, contents).await.unwrap();
        let login = DevinLogin { path };

        assert_eq!(login.document().await.unwrap(), contents);
    }

    #[tokio::test]
    async fn a_file_without_a_key_is_not_a_login() {
        let directory = TempDir::new().unwrap();
        let path = directory.path().join("credentials.toml");
        tokio::fs::write(&path, "api_server_url = \"https://x\"\n")
            .await
            .unwrap();
        let login = DevinLogin { path: path.clone() };

        assert!(matches!(
            login.document().await,
            Err(AgentError::NotDevinLogin { .. })
        ));

        tokio::fs::write(&path, "windsurf_api_key = \"\"\n")
            .await
            .unwrap();
        assert!(
            matches!(
                login.document().await,
                Err(AgentError::NotDevinLogin { .. })
            ),
            "an empty key authenticates nothing, so the file is not a login"
        );
    }

    #[tokio::test]
    async fn a_missing_file_says_where_to_log_in() {
        let directory = TempDir::new().unwrap();
        let login = DevinLogin {
            path: directory.path().join("credentials.toml"),
        };

        let error = login.document().await.unwrap_err();
        assert!(matches!(error, AgentError::NoDevinLogin { .. }));
        assert!(
            format!("{error}").contains("devin auth login"),
            "the fix is the login command, so the error names it: {error}"
        );
    }
}
