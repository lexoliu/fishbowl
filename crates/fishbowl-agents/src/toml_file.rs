//! A TOML file belonging to somebody else, edited in place.

use std::path::{Path, PathBuf};

use toml_edit::DocumentMut;

use crate::{error::AgentError, write_file};

/// One of an agent's configuration files.
///
/// Read as a document rather than deserialized, because these files are the researcher's:
/// their comments, key order and hand-written entries have to survive an edit that only
/// means to add one session to them.
#[derive(Debug, Clone)]
pub(crate) struct TomlFile {
    path: PathBuf,
}

impl TomlFile {
    pub(crate) fn new(path: PathBuf) -> Self {
        Self { path }
    }

    pub(crate) fn path(&self) -> &Path {
        &self.path
    }

    /// The file's contents, or an empty document when the agent has never written one.
    pub(crate) async fn read(&self) -> Result<DocumentMut, AgentError> {
        let text = match tokio::fs::read_to_string(&self.path).await {
            Ok(text) => text,
            Err(source) if source.kind() == std::io::ErrorKind::NotFound => {
                return Ok(DocumentMut::new());
            }
            Err(source) => {
                return Err(AgentError::Io {
                    path: self.path.clone(),
                    source,
                });
            }
        };
        text.parse().map_err(|source| AgentError::Toml {
            path: self.path.clone(),
            source,
        })
    }

    pub(crate) async fn write(&self, document: &DocumentMut) -> Result<(), AgentError> {
        write_file(&self.path, &document.to_string()).await
    }
}
