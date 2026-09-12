use std::{
    os::unix::fs::PermissionsExt as _,
    path::{Path, PathBuf},
};

use anyhow::{Context as _, Result};
use ssh_key::{Algorithm, LineEnding, PrivateKey, rand_core::OsRng};

/// Permissions `ssh` insists on for a private key it is asked to use.
const PRIVATE_KEY_MODE: u32 = 0o600;

/// The host-side SSH identity one sandbox is reached with.
///
/// The private half never leaves the host: the sandbox only ever receives the public
/// half, and only through its own init process. A sandbox that is destroyed and recreated
/// keeps the same identity, so the host's known-hosts and agent configuration stay valid.
#[derive(Debug, Clone)]
pub struct SandboxKey {
    private: PathBuf,
    authorized_key: String,
}

impl SandboxKey {
    /// Reads the identity for `id` under `directory`, generating it on first use.
    ///
    /// # Errors
    /// Fails when the directory cannot be created, the key cannot be generated, or an
    /// existing key cannot be read or is not a valid OpenSSH private key.
    pub async fn load_or_create(directory: &Path, id: &str) -> Result<Self> {
        let private = directory.join(id);
        let public = directory.join(format!("{id}.pub"));

        tokio::fs::create_dir_all(directory)
            .await
            .with_context(|| format!("creating the key directory {}", directory.display()))?;

        if let Some(existing) = read_optional(&private).await? {
            let key = PrivateKey::from_openssh(&existing)
                .with_context(|| format!("reading the sandbox key {}", private.display()))?;
            return Ok(Self {
                authorized_key: authorized_key(&key, id)?,
                private,
            });
        }

        let key = PrivateKey::random(&mut OsRng, Algorithm::Ed25519)
            .context("generating an ed25519 sandbox key")?;
        let encoded = key
            .to_openssh(LineEnding::LF)
            .context("encoding the sandbox key")?;
        tokio::fs::write(&private, encoded.as_bytes())
            .await
            .with_context(|| format!("writing {}", private.display()))?;
        tokio::fs::set_permissions(&private, std::fs::Permissions::from_mode(PRIVATE_KEY_MODE))
            .await
            .with_context(|| format!("restricting {}", private.display()))?;

        let authorized_key = authorized_key(&key, id)?;
        tokio::fs::write(&public, format!("{authorized_key}\n"))
            .await
            .with_context(|| format!("writing {}", public.display()))?;

        Ok(Self {
            private,
            authorized_key,
        })
    }

    /// Removes both halves of the identity, tolerating an already-deleted key.
    ///
    /// # Errors
    /// Fails when a key file exists but cannot be removed.
    pub async fn remove(directory: &Path, id: &str) -> Result<()> {
        for path in [directory.join(id), directory.join(format!("{id}.pub"))] {
            match tokio::fs::remove_file(&path).await {
                Ok(()) => {}
                Err(source) if source.kind() == std::io::ErrorKind::NotFound => {}
                Err(source) => {
                    return Err(source).with_context(|| format!("removing {}", path.display()));
                }
            }
        }
        Ok(())
    }

    /// Path of the private half, which is what `ssh -i` is given.
    #[must_use]
    pub fn identity_file(&self) -> &Path {
        &self.private
    }

    /// The `authorized_keys` line the sandbox installs for the researcher account.
    #[must_use]
    pub fn authorized_key(&self) -> &str {
        &self.authorized_key
    }
}

/// The public half in `authorized_keys` form, labelled with the sandbox it belongs to.
fn authorized_key(key: &PrivateKey, id: &str) -> Result<String> {
    let mut public = key.public_key().clone();
    public.set_comment(format!("fishbowl {id}"));
    public
        .to_openssh()
        .context("encoding the sandbox public key")
}

async fn read_optional(path: &Path) -> Result<Option<String>> {
    match tokio::fs::read_to_string(path).await {
        Ok(contents) => Ok(Some(contents)),
        Err(source) if source.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(source) => Err(source).with_context(|| format!("reading {}", path.display())),
    }
}
