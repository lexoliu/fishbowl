//! Taking sessions away, which nobody asks for either.
//!
//! Every session leaves a virtual machine, a disk image and an SSH identity behind, and
//! there is no command for deleting one: a researcher who has finished with an
//! environment closes the shell, and the tool is left to notice. So it is noticed here,
//! on the way in to every session — creation and resumption alike — on three grounds.
//!
//! The first is age. A session nobody has opened in [`IDLE_LIMIT`] is not being resumed;
//! keeping it only makes the picker longer and the disk fuller.
//!
//! The second is room. The runtime's state volume is shared with macOS's swapfile, and
//! filling it is what wedged this host once already, so a session that would be created
//! below the sandbox disk floor takes the least recently opened ones with it until the
//! floor is clear again.
//!
//! The third is the store's own size. Free disk is a slow alarm: a session costs its
//! machine's disk and each image costs an unpacked snapshot per platform variant —
//! several gigabytes apiece — so a busy week of openings piles the store up long before
//! the host's floor ever notices. Once what this tool owns passes [`USAGE_LIMIT`],
//! sessions go in the same least-recently-opened order until it is under again. The
//! measure is this tool's share alone: the base image, the builder and anything the
//! researcher pulled for themselves are neither counted nor touched.
//!
//! A running machine is only worth protecting while somebody holds it. The session's
//! lock answers that exactly: one that cannot be taken has a live owner — whatever its
//! machine's state — and one that can is a machine left running by an invocation that
//! is already gone, so those are stopped on sight and the ordinary rules then judge
//! them like any other.
//!
//! Images go by a rule of their own, which is reference. An image is named for the
//! sources it was built from, so every upgrade of the tool leaves the previous one
//! behind; one that no session was created from and that the session being opened will
//! not use has nothing left to start, and at several gigabytes each they are the first
//! thing to take away when the disk is short.

use std::time::Duration;

use anyhow::{Context as _, Result};
use fishbowl_runtime::{ContainerState, ImageInfo, ImageReference, RunState, Sandbox, Workload};
use jiff::Timestamp;

use crate::{cli, host::Host, keys::SandboxKey, lease::Lease, session::SessionRecord};

/// Bytes in a gibibyte, for measuring the store and reporting it.
const GIB: u64 = 1024 * 1024 * 1024;

/// How long a session may go unopened before it is reclaimed.
///
/// A week: long enough to span a holiday and come back to the environment an
/// investigation was left in, short enough that abandoned ones do not accumulate.
pub const IDLE_LIMIT: Duration = Duration::from_secs(7 * 24 * 60 * 60);

/// How much of the runtime's store this tool may hold before sessions are taken away.
///
/// Sixty-four gibibytes: about a dozen sessions with their images, which is far more
/// than a working set of environments ever is — the cap exists to catch accumulation
/// that nothing else notices, not to bound how many sessions may be kept.
const USAGE_LIMIT: u64 = 64 * GIB;

/// Reclaims whatever a session's opening makes expendable, keeping `image` held.
///
/// Runs on every open rather than only on a create, so a host whose sessions are only
/// ever resumed still collects. `image` is the image that session was — or is about to
/// be — created from, and it is kept regardless of what else refers to it.
///
/// # Errors
/// Fails when the host's state, the runtime's containers or its images cannot be read,
/// when the store's usage cannot be measured, or when a machine or image that should
/// go cannot be deleted. It does not fail for a host that is still short of disk
/// afterwards: the budget refuses that, with a message about the host rather than
/// about reclamation.
pub async fn make_room(host: &Host, image: &ImageReference) -> Result<()> {
    let live = host
        .runtime()
        .list()
        .await
        .context("listing the runtime's containers")?;
    let now = Timestamp::now();

    // A session whose lock cannot be taken has a live owner — held, whatever state its
    // machine is in, and never a candidate. One whose lock is free but whose machine is
    // still running was left up by an invocation already gone — the flock going free is
    // the proof — so it is stopped on sight and then judged by the rules like any other.
    let mut candidates = host.sessions().await?;
    let mut held = Vec::new();
    for record in &candidates {
        if Lease::try_lock(host, &record.id)?.is_none() {
            held.push(record.id.clone());
            continue;
        }
        if is_running(&live, record) {
            tracing::info!(session = %record.id, "stopping a session whose owner is gone");
            host.runtime()
                .stop(&record.id.container_name()?)
                .await
                .with_context(|| format!("stopping the ownerless session {}", record.id))?;
        }
    }

    // Least recently opened first: that is the order every rule below reclaims in.
    candidates.retain(|record| !held.contains(&record.id));
    candidates.reverse();

    let mut recent = Vec::new();
    for record in candidates {
        if record.idle_for(now) >= IDLE_LIMIT {
            tracing::info!(
                session = %record.id,
                idle = %crate::session::describe_age(record.idle_for(now)),
                "reclaiming a session nobody has come back to"
            );
            remove(host, &record).await?;
        } else {
            recent.push(record);
        }
    }

    // Images before sessions anyone might still want: an image nothing refers to costs
    // nobody anything to lose, and is the size of several sessions.
    prune_images(host, image).await?;

    for (index, record) in recent.iter().enumerate() {
        if !under_pressure(host, &recent[index..]).await? {
            return Ok(());
        }
        tracing::info!(
            session = %record.id,
            "reclaiming the least recently opened session to make room"
        );
        remove(host, record).await?;
        // Whatever the removal stranded — above all an image only that session was
        // still created from — is unreferenced now, and goes before the next oldest
        // session does.
        prune_images(host, image).await?;
    }
    Ok(())
}

/// Whether a session still has to go: the host's free disk is under the sandbox floor
/// outright, or this tool's own share of the runtime's store is over [`USAGE_LIMIT`].
///
/// The floor is measured first because it is the cheaper probe; the walk the share
/// costs is only paid when the floor alone does not already demand room.
async fn under_pressure(host: &Host, remaining: &[SessionRecord]) -> Result<bool> {
    if host.budget().await?.free_disk() < <Sandbox as Workload>::DISK_FLOOR {
        return Ok(true);
    }
    let used = usage(host, remaining).await?;
    if used > USAGE_LIMIT {
        tracing::info!(
            used_gib = used / GIB,
            limit_gib = USAGE_LIMIT / GIB,
            "the sandbox store is over its cap"
        );
        return Ok(true);
    }
    Ok(false)
}

/// Bytes of the runtime's store this tool owns: the machine disk of every session on
/// record, plus the unpacked snapshots of every sandbox image still held.
///
/// Only this tool's own repositories count — the base image, the builder's and
/// anything the researcher pulled for themselves are not this tool's to measure or
/// take away.
async fn usage(host: &Host, sessions: &[SessionRecord]) -> Result<u64> {
    let containers = sessions
        .iter()
        .map(|record| record.id.container_name())
        .collect::<Result<Vec<_>>>()?;
    let images = host
        .runtime()
        .image_list()
        .await
        .context("listing the runtime's images")?;
    let held = images
        .iter()
        .filter(|image| is_sandbox_image(&image.name))
        .collect::<Vec<_>>();
    host.runtime()
        .usage(&containers, &held)
        .await
        .context("measuring the sandbox share of the runtime's store")
}

/// Whether `image` is one of this tool's, by the repositories sessions are created
/// from — the published one, and the local one images were built under before the
/// registry existed.
fn is_sandbox_image(image: &ImageReference) -> bool {
    [cli::IMAGE_REPOSITORY, cli::LEGACY_IMAGE_REPOSITORY]
        .iter()
        .any(|repository| image.as_str().starts_with(&format!("{repository}:")))
}

/// Removes every sandbox image that no session was created from, other than `keep`.
///
/// Only images in this tool's own repository are considered: the base image, the
/// builder's and anything the researcher pulled for themselves are not this tool's to
/// take away.
async fn prune_images(host: &Host, keep: &ImageReference) -> Result<()> {
    let held = host
        .runtime()
        .image_list()
        .await
        .context("listing the runtime's images")?;
    let sessions = host.sessions().await?;
    for image in unreferenced(&held, &sessions, keep) {
        tracing::info!(image = %image.name, "removing a sandbox image no session was created from");
        host.runtime()
            .image_remove(&image.name)
            .await
            .with_context(|| format!("removing the image {}", image.name))?;
    }
    Ok(())
}

/// The sandbox images among `held` that neither `sessions` nor `keep` refer to.
fn unreferenced<'a>(
    held: &'a [ImageInfo],
    sessions: &[SessionRecord],
    keep: &ImageReference,
) -> Vec<&'a ImageInfo> {
    held.iter()
        .filter(|image| is_sandbox_image(&image.name))
        .filter(|image| image.name != *keep)
        .filter(|image| !sessions.iter().any(|record| record.image == image.name))
        .collect()
}

/// Takes one session away completely: its machine, its identity, its host key and its
/// record.
///
/// A machine the runtime has already forgotten is not an error, because the host's own
/// state still has to go — that is exactly the state a half-deleted session leaves
/// behind, and leaving it would offer the researcher a session that cannot be opened.
///
/// # Errors
/// Fails when the runtime refuses to delete the machine, or when the host's own state
/// cannot be removed.
pub async fn remove(host: &Host, record: &SessionRecord) -> Result<()> {
    let name = record.id.container_name()?;
    let live = host
        .runtime()
        .list()
        .await
        .context("listing the runtime's containers")?;
    if live.iter().any(|container| container.id == name) {
        host.runtime()
            .remove(&name)
            .await
            .context("deleting the session's machine")?;
    }
    // The agents' entries name an address the machine no longer has. They are written
    // when a session is opened and taken away when it goes, so that neither agent is ever
    // offered a machine that cannot answer — or worse, an address vmnet has since given
    // to a different one.
    host.agents()
        .unregister(record.id.as_str())
        .await
        .context("unregistering the session from the host's agents")?;
    SandboxKey::remove(&host.key_directory(), record.id.as_str()).await?;
    forget_host_key(host, record).await?;
    host.forget(&record.id).await?;
    tracing::info!(session = %record.id, "reclaimed");
    Ok(())
}

/// Drops the record of the host key this session's machine presented.
///
/// The next machine to be handed its vmnet address must be free to present a different
/// one, so the file goes when the session does.
async fn forget_host_key(host: &Host, record: &SessionRecord) -> Result<()> {
    let path = host.known_hosts_of(&record.id).await?;
    match tokio::fs::remove_file(&path).await {
        Ok(()) => Ok(()),
        Err(source) if source.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(source) => Err(source).with_context(|| format!("removing {}", path.display())),
    }
}

/// Whether the runtime is running this session's machine right now.
#[must_use]
pub fn is_running(live: &[ContainerState], record: &SessionRecord) -> bool {
    live.iter().any(|container| {
        container.id.as_str() == record.id.as_str() && container.status.state == RunState::Running
    })
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use fishbowl_runtime::{Arch, ImageReference};

    use super::*;

    fn live() -> Vec<ContainerState> {
        serde_json::from_str(include_str!("../tests/data/containers.json")).unwrap()
    }

    fn record(id: &str, last_used: Timestamp) -> SessionRecord {
        SessionRecord {
            id: id.parse().unwrap(),
            image: ImageReference::new("localhost/fishbowl:arm64").unwrap(),
            arch: Arch::Arm64,
            ssh_port: 22,
            researcher: "researcher".to_owned(),
            work_dir: PathBuf::from("/work"),
            samples: None,
            identity_file: PathBuf::from("/keys/id"),
            created_at: last_used,
            last_used,
        }
    }

    fn image(reference: &str) -> ImageInfo {
        ImageInfo {
            name: ImageReference::new(reference).unwrap(),
            variants: Vec::new(),
        }
    }

    #[test]
    fn only_sandbox_images_nothing_refers_to_are_taken_away() {
        let held = [
            image("docker.io/kalilinux/kali-rolling:latest"),
            image("ghcr.io/apple/container-builder-shim/builder:0.13.1"),
            image("ghcr.io/lexoliu/fishbowl:arm64-0123456789ab"),
            image("ghcr.io/lexoliu/fishbowl:arm64-fedcba987654"),
            image("ghcr.io/lexoliu/fishbowl:amd64-0123456789ab"),
            image("localhost/fishbowl:arm64-0123456789ab"),
        ];
        let mut in_use = record("c0ffee", Timestamp::now());
        in_use.image = ImageReference::new("ghcr.io/lexoliu/fishbowl:amd64-0123456789ab").unwrap();
        let keep = ImageReference::new("ghcr.io/lexoliu/fishbowl:arm64-fedcba987654").unwrap();

        assert_eq!(
            unreferenced(&held, &[in_use], &keep),
            vec![&held[2], &held[5]],
            "the base image and the builder are not this tool's; the image a session was \
             created from and the one about to be used are still wanted — and that holds \
             for images built before the registry existed"
        );
    }

    #[test]
    fn a_session_someone_is_working_in_is_never_a_candidate() {
        let ancient = Timestamp::now() - jiff::SignedDuration::from_hours(24 * 365);
        let running = record("c0ffee", ancient);
        assert!(
            is_running(&live(), &running),
            "no amount of disk pressure justifies deleting the machine a researcher's \
             shell is attached to, so a running one is excluded before age is even read"
        );
        assert!(!is_running(&live(), &record("dec0de", ancient)));
        assert!(!is_running(&live(), &record("abcdef", ancient)));
    }

    #[test]
    fn a_session_is_stale_only_once_a_whole_week_has_passed() {
        let now = Timestamp::now();
        let six_days = record("dec0de", now - jiff::SignedDuration::from_hours(24 * 6));
        let eight_days = record("dec0de", now - jiff::SignedDuration::from_hours(24 * 8));
        assert!(six_days.idle_for(now) < IDLE_LIMIT);
        assert!(eight_days.idle_for(now) >= IDLE_LIMIT);
    }
}
