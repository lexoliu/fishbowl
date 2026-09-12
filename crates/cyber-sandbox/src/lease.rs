//! Holding a session, and stopping its machine when the holder is gone.
//!
//! A session is opened by exactly one invocation. "In use" is a flock on the session's
//! lock file, held for the life of the process that took it: the kernel drops it on any
//! exit — a crash included — so ownership is never a record that can go stale.
//!
//! Release is the reaper's job. [`Lease::acquire`] spawns `cyber-sandbox reap <id>` as a
//! detached child whose standard input is a pipe this process alone keeps the write end
//! of. However this process dies, the write end dies with it, and the reaper reads
//! end-of-file, takes the lock when it is free, and stops the machine. A successor that
//! attached in the meantime is holding the lock, so the reaper leaves its session alone.
//!
//! The descriptors never leave the owning process: the pipe's write end is marked
//! CLOEXEC, so children like the `shell` command's spawned ssh client do not hold a
//! copy that would keep the machine running past the owner's death.

use std::{
    fs::{File, OpenOptions},
    io::{Read as _, Write as _},
    os::{fd::AsRawFd as _, unix::process::CommandExt as _},
    path::Path,
    process::{Command, Stdio},
    time::Duration,
};

use anyhow::{Context as _, Result, bail};
use nix::{
    errno::Errno,
    fcntl::{Flock, FlockArg},
};

use crate::{host::Host, session::SessionId};

/// How long an opening waits for a predecessor's reaper to finish stopping the machine
/// before it reports the session as still being released.
const TAKING: Duration = Duration::from_secs(10);

/// How often the lock is retried while a release is in flight.
const TAKING_INTERVAL: Duration = Duration::from_millis(200);

/// A session held by this process: the exclusive lock on its lock file, and the write
/// end of the pipe the reaper reads the owner's death from. Nothing uses either but the
/// kernel — they are held, and closing is the whole of their work.
pub struct Lease {
    hold: Flock<File>,
    gone: File,
}

impl std::fmt::Debug for Lease {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("Lease")
            .field("lock", &self.hold.as_raw_fd())
            .field("gone", &self.gone.as_raw_fd())
            .finish()
    }
}

impl Lease {
    /// Takes the session over for this process and arms the reaper that stops its
    /// machine when the process is gone.
    ///
    /// The reaper is armed before the caller has done anything with the session —
    /// before the machine even exists on a create — so that no way out of this process,
    /// clean or not, can leave a running machine behind.
    ///
    /// # Errors
    /// Fails when another invocation holds the session, when a predecessor's release
    /// outlasts [`TAKING`], when the lock cannot be taken, or when the reaper cannot be
    /// spawned.
    pub async fn acquire(host: &Host, id: &SessionId) -> Result<Self> {
        let path = host.session_lock_path(id);
        let deadline = tokio::time::Instant::now() + TAKING;
        let hold = loop {
            match lock_file(&path)? {
                Some(hold) => break claim(hold)?,
                None if held_by_living(&path) => {
                    bail!("session {id} is in use: another cyber-sandbox command has it open")
                }
                None if tokio::time::Instant::now() >= deadline => bail!(
                    "session {id} is still being released after {}s; its machine's state \
                     is visible with `container list`",
                    TAKING.as_secs()
                ),
                None => tokio::time::sleep(TAKING_INTERVAL).await,
            }
        };
        let gone = spawn_reaper(id)?;
        Ok(Self { hold, gone })
    }

    /// The session's lock, when nobody holds it — the probe the reaper and the
    /// reclaimer answer "is anyone attached?" with.
    ///
    /// The lock is what decides, not a pid or a timestamp: a lock that can be taken is a
    /// session nobody is attached to, whatever the record or the runtime still says.
    ///
    /// # Errors
    /// Fails when the lock file cannot be created, opened or queried.
    pub fn try_lock(host: &Host, id: &SessionId) -> Result<Option<Flock<File>>> {
        lock_file(&host.session_lock_path(id))
    }
}

/// Opens the session's lock file and takes its lock without waiting.
///
/// `None` is contention — someone holds it — and nothing more precise: who and why is
/// answered separately, because the answer decides between "in use" and "still
/// releasing".
fn lock_file(path: &Path) -> Result<Option<Flock<File>>> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("creating {}", parent.display()))?;
    }
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        // The pid inside is the holder's name: probing for contention must not wipe it.
        .truncate(false)
        .open(path)
        .with_context(|| format!("opening {}", path.display()))?;
    match Flock::lock(file, FlockArg::LockExclusiveNonblock) {
        Ok(hold) => Ok(Some(hold)),
        Err((_, Errno::EWOULDBLOCK)) => Ok(None),
        Err((_, errno)) => Err(errno).with_context(|| format!("locking {}", path.display())),
    }
}

/// Marks a freshly taken lock with who holds it, so a contender can tell a live owner
/// from a predecessor's reaper still stopping the machine — one fails at once, the
/// other is worth waiting out.
fn claim(hold: Flock<File>) -> Result<Flock<File>> {
    hold.set_len(0)
        .context("truncating the session's lock file")?;
    (&*hold)
        .write_all(std::process::id().to_string().as_bytes())
        .context("writing the session's owner into its lock file")?;
    Ok(hold)
}

/// Whether the process that last wrote itself into the lock file is still alive.
///
/// A missing, empty or unreadable file answers `false`: whoever held it either never
/// claimed it or is already gone, and both mean the contention is teardown.
fn held_by_living(path: &Path) -> bool {
    let Ok(text) = std::fs::read_to_string(path) else {
        return false;
    };
    let Ok(pid) = text.trim().parse::<i32>() else {
        return false;
    };
    !matches!(
        nix::sys::signal::kill(nix::unistd::Pid::from_raw(pid), None),
        Err(Errno::ESRCH)
    )
}

/// Spawns the detached `reap` that watches for the owner's death, and hands back the
/// write end whose closing is that death.
///
/// Its own process group keeps it out of the terminal's signals: an interrupt meant for
/// the agent must not take the machine's undertaker with it.
fn spawn_reaper(id: &SessionId) -> Result<File> {
    let (read, write) = nix::unistd::pipe().context("creating the owner's death notice")?;
    // `pipe` gives descriptors without CLOEXEC, and a spawned child inherits every one
    // it gets: the reaper holding the write end itself would never read its own death
    // notice, and an ssh client holding it would keep the machine running past the
    // owner's death.
    for fd in [&read, &write] {
        nix::fcntl::fcntl(
            fd,
            nix::fcntl::FcntlArg::F_SETFD(nix::fcntl::FdFlag::FD_CLOEXEC),
        )
        .context("marking the death notice close-on-exec")?;
    }
    let mut reaper = Command::new(std::env::current_exe().context("locating this executable")?);
    reaper
        .arg("reap")
        .arg(id.as_str())
        .stdin(Stdio::from(File::from(read)))
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .process_group(0);
    reaper.spawn().context("spawning the session's reaper")?;
    Ok(File::from(write))
}

/// What `cyber-sandbox reap <session>` is: wait for the owner's death on standard
/// input, then stop the machine unless a successor has taken the session over.
///
/// End-of-file is the only signal this process reads: the pipe's write end lives and
/// dies with the owner, so however the owner went — clean exit, error, SIGKILL — the
/// read ends. What it must not do is outlive its usefulness: a session reopened in the
/// gap holds the lock, and this process leaves it to that owner's own reaper.
pub async fn reap(host: &Host, id: &SessionId) -> Result<()> {
    let mut byte = [0u8; 1];
    while std::io::stdin().read(&mut byte).is_ok_and(|read| read > 0) {}

    let Some(_hold) = Lease::try_lock(host, id)? else {
        return Ok(());
    };
    let name = id.container_name()?;
    if let Err(error) = host.runtime().stop(&name).await {
        // Already stopped or already deleted are both the outcome this is for.
        tracing::debug!(session = %id, %error, "the machine was already stopped or gone");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use super::*;

    fn lock_path() -> (tempfile::TempDir, PathBuf) {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("sessions").join("c0ffee.lock");
        (directory, path)
    }

    #[test]
    fn a_held_lock_is_contention_and_a_dropped_one_is_not() {
        let (_directory, path) = lock_path();
        let hold = lock_file(&path).unwrap().expect("a free lock is taken");

        assert!(
            lock_file(&path).unwrap().is_none(),
            "a second taker must see the first"
        );

        drop(hold);
        assert!(
            lock_file(&path).unwrap().is_some(),
            "the kernel releasing it on close is the whole mechanism"
        );
    }

    #[test]
    fn a_claimed_lock_names_a_living_holder() {
        let (_directory, path) = lock_path();
        let hold = lock_file(&path).unwrap().unwrap();

        assert!(!held_by_living(&path), "an unclaimed lock names nobody");
        claim(hold).unwrap();
        assert!(
            held_by_living(&path),
            "the test process claiming it is alive, so a contender reads \"in use\""
        );
    }

    #[test]
    fn a_dead_holder_is_teardown_not_ownership() {
        let (_directory, path) = lock_path();
        // A pid that has lived and died in this test run: guaranteed to have existed,
        // so ESRCH is what its death left behind rather than an impossible number.
        let mut child = Command::new("/bin/sh")
            .arg("-c")
            .arg("exit")
            .spawn()
            .unwrap();
        child.wait().unwrap();
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(&path, child.id().to_string()).unwrap();

        assert!(
            !held_by_living(&path),
            "a contender waits out a release rather than declaring the session held"
        );
    }

    #[test]
    fn the_lock_file_is_created_where_it_is_asked_for() {
        let (_directory, path) = lock_path();
        lock_file(&path).unwrap().expect("a free lock is taken");
        assert!(path.exists(), "the parent directory is made on the way");
    }
}
