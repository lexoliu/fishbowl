use std::{
    collections::BTreeMap,
    ffi::OsString,
    os::unix::fs::PermissionsExt as _,
    path::{Path, PathBuf},
};

use jiff::Timestamp;
use serde::{Deserialize, Serialize};
use tokio::io::AsyncWriteExt as _;

use crate::error::CredentialError;

/// Largest credentials file Claude Code will look at.
///
/// It stops on the size before reading, so a file past this is not a large credential but
/// an unreadable one.
pub const MAX_BYTES: usize = 65_536;

/// Mode the credentials file is written with.
///
/// Claude Code refuses one that is readable by group or other, and refuses one it does
/// not own. Both are the same rule from two directions: a token written where the rest of
/// the machine can read it is a token the rest of the machine has.
pub const MODE: u32 = 0o600;

/// How far the recorded start time may sit from the one the reader measures.
///
/// Claude Code asks `ps` when the process's start time it should be, and `ps` answers in
/// whole seconds, so the two are never compared for equality.
pub const START_TOLERANCE: std::time::Duration = std::time::Duration::from_secs(2);

/// The file Claude Code reads its credential out of when the host manages one for it.
///
/// The two process fields are what make it a loan rather than a copy. Claude Code checks
/// that `pid` is still alive and that it started when `proc_start` says it did, so the
/// credential stops being readable the moment the process that vouched for it is gone —
/// and a file left behind by a session that ended cannot be picked up by whatever happens
/// to be given that pid next.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Credentials {
    /// Environment Claude Code is to run with, holding the bearer token among it.
    pub env: BTreeMap<String, String>,
    /// When the token stops being accepted; the file is ignored from then on.
    #[serde(with = "jiff::fmt::serde::timestamp::millisecond::optional")]
    pub expires_at: Option<Timestamp>,
    /// Process that vouches for the file, which must be alive for it to be read.
    pub pid: u32,
    /// When that process started, to within [`START_TOLERANCE`].
    #[serde(with = "jiff::fmt::serde::timestamp::millisecond::required")]
    pub proc_start: Timestamp,
}

impl Credentials {
    /// Writes the file where Claude Code is expecting it.
    ///
    /// # Errors
    /// Fails when the file cannot be encoded, would be larger than Claude Code reads, or
    /// cannot be written.
    pub async fn write_to(&self, path: &Path) -> Result<(), CredentialError> {
        let encoded = serde_json::to_vec(self).map_err(CredentialError::Encode)?;
        if encoded.len() > MAX_BYTES {
            return Err(CredentialError::TooLarge {
                size: encoded.len(),
            });
        }
        install(path, &encoded).await
    }
}

/// Writes `contents` at `path` the way every borrowed credential is written.
///
/// The bytes land in a sibling first and are renamed over the target, so a reader that
/// arrives mid-rotation sees the old credential or the new one and never half of either.
/// The mode is asserted on the staging file rather than only at its creation, because a
/// file a crashed run left behind would otherwise carry whatever mode it already had
/// through the rename — and a credential that is briefly world-readable has briefly been
/// readable by the world.
///
/// # Errors
/// Fails when the staging file or the rename cannot be written.
pub async fn install(path: &Path, contents: &[u8]) -> Result<(), CredentialError> {
    let staging = staging_path(path);
    let mut file = tokio::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(MODE)
        .open(&staging)
        .await
        .map_err(|source| CredentialError::Io {
            path: staging.clone(),
            source,
        })?;
    file.set_permissions(std::fs::Permissions::from_mode(MODE))
        .await
        .map_err(|source| CredentialError::Io {
            path: staging.clone(),
            source,
        })?;
    file.write_all(contents)
        .await
        .map_err(|source| CredentialError::Io {
            path: staging.clone(),
            source,
        })?;
    drop(file);

    tokio::fs::rename(&staging, path)
        .await
        .map_err(|source| CredentialError::Io {
            path: path.to_path_buf(),
            source,
        })
}

/// Takes a borrowed file back, tolerating one that is already gone.
///
/// # Errors
/// Fails when the file is there but cannot be removed.
pub async fn remove(path: &Path) -> Result<(), CredentialError> {
    match tokio::fs::remove_file(path).await {
        Ok(()) => Ok(()),
        Err(source) if source.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(source) => Err(CredentialError::Io {
            path: path.to_path_buf(),
            source,
        }),
    }
}

/// Where the file is assembled before it is renamed into place.
///
/// A sibling, because a rename is only atomic within one filesystem.
fn staging_path(path: &Path) -> PathBuf {
    let mut name = path
        .file_name()
        .map_or_else(OsString::new, ToOwned::to_owned);
    name.push(".staging");
    path.with_file_name(name)
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::MetadataExt as _;

    use tempfile::TempDir;

    use super::*;

    fn credentials() -> Credentials {
        Credentials {
            env: BTreeMap::from([(
                "CLAUDE_CODE_OAUTH_TOKEN".to_owned(),
                "sk-ant-oat01-example".to_owned(),
            )]),
            expires_at: Some(Timestamp::from_millisecond(1_788_000_000_000).unwrap()),
            pid: 41,
            proc_start: Timestamp::from_millisecond(1_787_000_000_000).unwrap(),
        }
    }

    #[tokio::test]
    async fn the_file_is_written_where_only_its_owner_can_read_it() {
        let directory = TempDir::new().unwrap();
        let path = directory.path().join("claude-creds.json");

        credentials().write_to(&path).await.unwrap();

        let mode = tokio::fs::metadata(&path)
            .await
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(
            mode & 0o777,
            MODE,
            "Claude Code refuses a credential the rest of the machine can read, and it \
             is right to: {mode:o}"
        );
    }

    #[tokio::test]
    async fn the_file_says_what_claude_code_reads() {
        let directory = TempDir::new().unwrap();
        let path = directory.path().join("claude-creds.json");

        credentials().write_to(&path).await.unwrap();

        let written: serde_json::Value =
            serde_json::from_slice(&tokio::fs::read(&path).await.unwrap()).unwrap();
        assert_eq!(
            written,
            serde_json::json!({
                "env": {"CLAUDE_CODE_OAUTH_TOKEN": "sk-ant-oat01-example"},
                "expiresAt": 1_788_000_000_000_i64,
                "pid": 41,
                "procStart": 1_787_000_000_000_i64,
            }),
            "the reader validates this shape and silently ignores a file that misses it, \
             so the names and the units are the contract"
        );
    }

    #[tokio::test]
    async fn a_rotation_replaces_the_file_rather_than_rewriting_it_in_place() {
        let directory = TempDir::new().unwrap();
        let path = directory.path().join("claude-creds.json");
        credentials().write_to(&path).await.unwrap();
        let first = tokio::fs::metadata(&path).await.unwrap();

        let mut rotated = credentials();
        rotated.env.insert(
            "CLAUDE_CODE_OAUTH_TOKEN".to_owned(),
            "sk-ant-oat01-next".to_owned(),
        );
        rotated.write_to(&path).await.unwrap();
        let second = tokio::fs::metadata(&path).await.unwrap();

        assert_ne!(
            first.ino(),
            second.ino(),
            "a reader that opens the file while it is being rewritten in place sees half \
             a credential; a rename gives it one or the other"
        );
        assert!(
            !staging_path(&path).exists(),
            "the staging file is renamed away, not left beside the real one"
        );
    }

    #[tokio::test]
    async fn a_document_is_installed_verbatim_and_only_for_its_owner() {
        let directory = TempDir::new().unwrap();
        let path = directory.path().join("nested").join("credentials.toml");
        tokio::fs::create_dir_all(path.parent().unwrap())
            .await
            .unwrap();

        install(&path, b"windsurf_api_key = \"devin-session-x\"\n")
            .await
            .unwrap();

        assert_eq!(
            tokio::fs::read_to_string(&path).await.unwrap(),
            "windsurf_api_key = \"devin-session-x\"\n",
            "a lent document is the host's bytes and nothing else"
        );
        assert_eq!(
            tokio::fs::metadata(&path)
                .await
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            MODE
        );
    }

    #[tokio::test]
    async fn taking_back_a_file_that_is_already_gone_is_not_a_failure() {
        let directory = TempDir::new().unwrap();

        remove(&directory.path().join("claude-creds.json"))
            .await
            .unwrap();
    }
}
