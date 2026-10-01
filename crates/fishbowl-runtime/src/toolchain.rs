//! Provisioning of the `container` toolchain itself.
//!
//! A fishbowl install does not ask for a `container` install beside it: the pinned
//! release of `apple/container` is fetched, checked and laid down under the tool's state
//! directory instead, and [`AppleContainer`] drives that copy. The managed root keeps
//! the upstream installer's layout — `bin/` executables above `libexec/container/plugins/`
//! — so install-root resolution and plugin discovery work exactly as they do for a
//! system-wide install, and `system start` registers the services from here.
//!
//! `directory` holds one root per toolchain version, named for it. A root is staged
//! under a hidden sibling and renamed into place, so a `bin/container` that exists is a
//! complete one. Two invocations racing the download are serialised by a flock on
//! `.install.lock`: the kernel drops it on any exit, so it cannot go stale the way a
//! marker file could.

use std::{
    ffi::OsString,
    fmt::Write as _,
    fs::OpenOptions,
    io::ErrorKind,
    path::{Path, PathBuf},
    process::Stdio,
    time::Duration,
};

use nix::{
    errno::Errno,
    fcntl::{Flock, FlockArg},
};
use sha2::{Digest as _, Sha256};
use tokio::{io::AsyncReadExt as _, process::Command};
use tracing::{debug, info};

use crate::{apple::AppleContainer, error::RuntimeError};

/// Version of `apple/container` this driver is written against.
///
/// Also the release [`ensure`] fetches: the pinned digests below name this version's
/// artifacts, so bumping the constant changes both what is fetched and which running
/// services are considered current.
pub const VERSION: &str = "1.5.0";

/// SHA-256 of `container-1.5.0-installer-signed.pkg`, as published on the release.
const PACKAGE_SHA256: &str = "a24808cb202318fa1c3bbee0c6c6887fe1225fe899d7b687a0ddd939bd6573f8";

/// The license texts the toolchain's binaries are distributed under, as
/// `(file, sha256)` pairs. The installer package omits them, so they are fetched from
/// the release tag into the managed root — redistribution keeps its notice.
const LICENSES: &[(&str, &str)] = &[
    (
        "LICENSE",
        "c71d239df91726fc519c6eb72d318ec65820627232b2f796219e87dcf35d0ab4",
    ),
    (
        "NOTICE.md",
        "3af54d132e70dfaad11be4d5492765c59a33e40899ec19b6d98a6ce154522cf3",
    ),
];

/// Payload entries fishbowl never invokes.
///
/// `k8s` only backs the `container k8s` command group — nothing in this driver starts
/// a Kubernetes node — and the two scripts operate a system-wide install, which a
/// managed root is not.
const PRUNED: &[&str] = &[
    "bin/uninstall-container.sh",
    "bin/update-container.sh",
    "libexec/container/plugins/k8s",
];

/// The executables the staged root must hold before it is committed, relative to it.
///
/// Checking them is what turns an upstream layout change into an error here rather
/// than a half-installed root.
const EXPECTED: &[&str] = &[
    "bin/container",
    "bin/container-apiserver",
    "libexec/container/plugins/container-core-images/bin/container-core-images",
    "libexec/container/plugins/container-network-vmnet/bin/container-network-vmnet",
    "libexec/container/plugins/container-runtime-linux/bin/container-runtime-linux",
    "libexec/container/plugins/machine-apiserver/bin/machine-apiserver",
];

/// How often the install lock is retried while a sibling's download is in flight.
const LOCK_RETRY: Duration = Duration::from_millis(250);

/// The file whose flock serialises installs, kept inside `directory`.
const LOCK_FILE: &str = ".install.lock";

/// The pinned toolchain, downloaded and laid down under `directory` when absent.
///
/// Returns the driver pointing at `directory/<VERSION>/bin/container`. A concurrent
/// invocation doing the same work is waited out: the loser ends up driving the root
/// the winner committed.
///
/// # Errors
/// Fails when the package cannot be fetched, hashes to something other than the
/// pinned digest, cannot be expanded, or cannot be committed into place.
pub async fn ensure(directory: &Path) -> Result<AppleContainer, RuntimeError> {
    let root = directory.join(VERSION);
    let cli = root.join("bin").join("container");
    if cli.is_file() {
        return Ok(AppleContainer::at(cli));
    }

    let _hold = install_lock(directory, &cli).await?;
    if cli.is_file() {
        // The holder we waited out finished; its root is the one to drive.
        return Ok(AppleContainer::at(cli));
    }

    info!(
        version = VERSION,
        "fetching the container toolchain; first run only"
    );
    install(directory, &root).await?;
    sweep(directory).await;
    Ok(AppleContainer::at(cli))
}

/// The flock serialising installs, taken once it is known the toolchain is missing.
///
/// `None` means the root appeared while the lock was contended — whoever held it
/// finished, and there is nothing left to install. Nonblocking with a retry loop
/// rather than blocking, because a sibling's download legitimately holds it for a
/// while.
async fn install_lock(
    directory: &Path,
    cli: &Path,
) -> Result<Option<Flock<std::fs::File>>, RuntimeError> {
    std::fs::create_dir_all(directory)
        .map_err(|source| stage_error("create", directory, source))?;
    let path = directory.join(LOCK_FILE);
    loop {
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(&path)
            .map_err(|source| stage_error("open", &path, source))?;
        match Flock::lock(file, FlockArg::LockExclusiveNonblock) {
            Ok(hold) => return Ok(Some(hold)),
            Err((_, Errno::EWOULDBLOCK)) => {
                if cli.is_file() {
                    return Ok(None);
                }
                tokio::time::sleep(LOCK_RETRY).await;
            }
            Err((_, errno)) => {
                return Err(stage_error("lock", &path, errno.into()));
            }
        }
    }
}

/// Stages the toolchain under a private sibling of `root` and commits it by rename.
async fn install(directory: &Path, root: &Path) -> Result<(), RuntimeError> {
    let staging = directory.join(format!(".incoming-{}", std::process::id()));
    drop(tokio::fs::remove_dir_all(&staging).await);
    tokio::fs::create_dir(&staging)
        .await
        .map_err(|source| stage_error("create", &staging, source))?;
    let outcome = stage(&staging, root).await;
    drop(tokio::fs::remove_dir_all(&staging).await);
    outcome
}

/// Fetches and checks the toolchain into `staging/root`, then moves it onto `root`.
async fn stage(staging: &Path, root: &Path) -> Result<(), RuntimeError> {
    let package = staging.join("container.pkg");
    fetch(
        "the toolchain package",
        &format!(
            "https://github.com/apple/container/releases/download/{VERSION}/container-{VERSION}-installer-signed.pkg"
        ),
        PACKAGE_SHA256,
        &package,
    )
    .await?;

    let expanded = staging.join("expanded");
    run(
        "/usr/sbin/pkgutil",
        vec![
            "--expand-full".into(),
            package.clone().into(),
            expanded.clone().into(),
        ],
    )
    .await?;

    let payload = expanded.join("Payload");
    let staged = staging.join("root");
    tokio::fs::create_dir(&staged)
        .await
        .map_err(|source| stage_error("create", &staged, source))?;
    for entry in ["bin", "libexec"] {
        let source_path = payload.join(entry);
        tokio::fs::rename(&source_path, staged.join(entry))
            .await
            .map_err(|source| stage_error("move", &source_path, source))?;
    }
    for pruned in PRUNED {
        prune(&staged.join(pruned)).await?;
    }
    for &(file, sha256) in LICENSES {
        fetch(
            file,
            &format!("https://raw.githubusercontent.com/apple/container/{VERSION}/{file}"),
            sha256,
            &staged.join(file),
        )
        .await?;
    }
    for binary in EXPECTED {
        if !staged.join(binary).is_file() {
            return Err(RuntimeError::InvalidValue {
                kind: "toolchain payload",
                value: (*binary).to_owned(),
                reason: "the expanded installer does not carry it",
            });
        }
    }

    match tokio::fs::rename(&staged, root).await {
        Ok(()) => Ok(()),
        Err(source) if root.join("bin").join("container").is_file() => {
            debug!(%source, "a sibling committed its toolchain first; using it");
            Ok(())
        }
        Err(source) => Err(stage_error("commit", root, source)),
    }
}

/// Removes everything under `directory` that is not the live toolchain — superseded
/// roots and stagings an interrupted install left behind.
///
/// Runs with the install lock held: anything present is definitionally stale, since a
/// live installer's staging can only exist while it holds the lock.
async fn sweep(directory: &Path) {
    let mut entries = match tokio::fs::read_dir(directory).await {
        Ok(entries) => entries,
        Err(source) => {
            debug!(%source, "the toolchain directory could not be swept");
            return;
        }
    };
    let live = directory.join(VERSION);
    let lock = directory.join(LOCK_FILE);
    loop {
        let entry = match entries.next_entry().await {
            Ok(Some(entry)) => entry,
            Ok(None) => break,
            Err(source) => {
                debug!(%source, "a toolchain directory entry could not be read");
                break;
            }
        };
        let path = entry.path();
        // Removing the lock while it is held would let the next contender create and
        // take a different inode — the mutual exclusion this file exists for.
        if path == live || path == lock {
            continue;
        }
        let result = if entry.file_type().await.is_ok_and(|kind| kind.is_dir()) {
            tokio::fs::remove_dir_all(&path).await
        } else {
            tokio::fs::remove_file(&path).await
        };
        if let Err(source) = result {
            debug!(path = %path.display(), %source, "a stale toolchain entry could not be swept");
        }
    }
}

/// Downloads `url` to `path` and refuses it when the bytes hash elsewhere than
/// `sha256`.
async fn fetch(
    name: &'static str,
    url: &str,
    sha256: &'static str,
    path: &Path,
) -> Result<(), RuntimeError> {
    run_attached(
        "/usr/bin/curl",
        vec![
            "--fail".into(),
            "--location".into(),
            "--retry".into(),
            "3".into(),
            "--retry-all-errors".into(),
            "--speed-limit".into(),
            "10240".into(),
            "--speed-time".into(),
            "30".into(),
            "-o".into(),
            path.as_os_str().to_owned(),
            url.into(),
        ],
    )
    .await?;
    let actual = sha256_of(path).await?;
    if actual == sha256 {
        Ok(())
    } else {
        Err(RuntimeError::Digest {
            name,
            expected: sha256,
            actual,
        })
    }
}

/// The SHA-256 of `path`, as lowercase hex.
async fn sha256_of(path: &Path) -> Result<String, RuntimeError> {
    let mut file = tokio::fs::File::open(path)
        .await
        .map_err(|source| stage_error("read", path, source))?;
    let mut hasher = Sha256::new();
    let mut buffer = vec![0_u8; 1 << 20];
    loop {
        let read = file
            .read(&mut buffer)
            .await
            .map_err(|source| stage_error("read", path, source))?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }
    let digest = hasher.finalize();
    let mut hex = String::with_capacity(digest.len() * 2);
    for byte in &digest {
        write!(hex, "{byte:02x}").expect("writing to a String cannot fail");
    }
    Ok(hex)
}

/// Removes one payload entry, tolerating its absence — an upstream release that no
/// longer ships a pruned path is not an install failure.
async fn prune(path: &Path) -> Result<(), RuntimeError> {
    let metadata = match tokio::fs::symlink_metadata(path).await {
        Ok(metadata) => metadata,
        Err(source) if source.kind() == ErrorKind::NotFound => return Ok(()),
        Err(source) => return Err(stage_error("inspect", path, source)),
    };
    if metadata.is_dir() {
        tokio::fs::remove_dir_all(path).await
    } else {
        tokio::fs::remove_file(path).await
    }
    .map_err(|source| stage_error("remove", path, source))
}

/// Runs a provisioning helper, capturing its output; a non-zero exit fails with what
/// it wrote to stderr.
async fn run(program: &'static str, args: Vec<OsString>) -> Result<(), RuntimeError> {
    debug!(program, args = ?args, "running a toolchain provisioning step");
    let output = Command::new(program)
        .args(&args)
        .stdin(Stdio::null())
        .output()
        .await
        .map_err(|source| spawn_error(program, &args, source))?;
    if output.status.success() {
        return Ok(());
    }
    Err(RuntimeError::Helper {
        program,
        args: os_strings(&args),
        status: output.status.to_string(),
        stderr: String::from_utf8_lossy(&output.stderr).trim().to_owned(),
    })
}

/// Runs a provisioning helper with stderr attached to this process's, so progress and
/// the helper's own error text stay visible; a non-zero exit fails.
async fn run_attached(program: &'static str, args: Vec<OsString>) -> Result<(), RuntimeError> {
    debug!(program, args = ?args, "running a toolchain provisioning step");
    let status = Command::new(program)
        .args(&args)
        .stdin(Stdio::null())
        .status()
        .await
        .map_err(|source| spawn_error(program, &args, source))?;
    if status.success() {
        Ok(())
    } else {
        Err(RuntimeError::Helper {
            program,
            args: os_strings(&args),
            status: status.to_string(),
            stderr: "see the output above".to_owned(),
        })
    }
}

/// `args` as owned strings, for an error that outlives them.
fn os_strings(args: &[OsString]) -> Vec<String> {
    args.iter()
        .map(|arg| arg.to_string_lossy().into_owned())
        .collect()
}

/// Why a provisioning helper could not be spawned.
fn spawn_error(program: &'static str, args: &[OsString], source: std::io::Error) -> RuntimeError {
    RuntimeError::Spawn {
        binary: PathBuf::from(program),
        args: os_strings(args),
        source,
    }
}

/// A filesystem failure while the toolchain is being laid down.
fn stage_error(action: &'static str, path: &Path, source: std::io::Error) -> RuntimeError {
    RuntimeError::Stage {
        action,
        path: path.to_path_buf(),
        source,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn a_file_hashes_to_its_sha256() {
        let directory = tempfile::tempdir().unwrap();
        let payload = directory.path().join("payload");
        tokio::fs::write(&payload, b"abc").await.unwrap();
        assert_eq!(
            sha256_of(&payload).await.unwrap(),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
            "the digest a download is checked against is this one's output"
        );
    }
}
