use std::{
    cmp::Reverse,
    net::Ipv4Addr,
    path::{Path, PathBuf},
};

use anyhow::{Context as _, Result, bail};
use fishbowl_agents::{
    AgentIntegration, key_directory, known_hosts_directory, work_alias_directory,
};
use fishbowl_image::SandboxLayout;
use fishbowl_runtime::{AppleContainer, Committed, ContainerName, HostBudget, RunState};

use crate::{
    loan::Attachment,
    session::{SessionId, SessionRecord},
};

/// Directory under the user's home holding everything fishbowl owns.
const STATE_DIRECTORY: &str = ".fishbowl";

/// Everything a command needs to reach both the runtime and the host's own state.
///
/// Constructed once per invocation so that the runtime binary, the layout the image was
/// built from and the state directory cannot disagree between commands.
#[derive(Debug, Clone)]
pub struct Host {
    home: PathBuf,
    state: PathBuf,
    runtime: AppleContainer,
    layout: SandboxLayout,
}

impl Host {
    /// Locates the runtime and the host's state directory.
    ///
    /// # Errors
    /// Fails when the home directory is unknown or `container` is not installed.
    pub fn discover() -> Result<Self> {
        let home = std::env::var_os("HOME")
            .map(PathBuf::from)
            .context("HOME is not set, so the host's configuration cannot be located")?;
        let runtime = AppleContainer::discover()?;
        Ok(Self {
            state: home.join(STATE_DIRECTORY),
            home,
            runtime,
            layout: SandboxLayout::default(),
        })
    }

    /// The `apple/container` driver.
    #[must_use]
    pub fn runtime(&self) -> &AppleContainer {
        &self.runtime
    }

    /// Measures what the host can spare, against the volume the runtime stores images
    /// and VM disks on.
    ///
    /// That volume is the one that matters: it is where a build's layer snapshots and a
    /// sandbox's writes land, and filling it is what stops macOS growing a swapfile.
    ///
    /// Every virtual machine the runtime is already running is charged against the
    /// measurement, so a second session is sized against the host as it is rather than as
    /// it was before the first one started.
    ///
    /// # Errors
    /// Fails when the runtime cannot report where its state lives or what it is running,
    /// or when the host's cores, memory or free space cannot be measured.
    pub async fn budget(&self) -> Result<HostBudget> {
        let status = self
            .runtime
            .system_status()
            .await
            .context("asking the runtime where it stores its state")?;
        let running = self
            .runtime
            .list()
            .await
            .context("asking the runtime what it is already running")?;
        HostBudget::measure(Path::new(&status.app_root), Committed::of(&running))
            .map_err(Into::into)
    }

    /// The layout the sandbox image was rendered from.
    #[must_use]
    pub fn layout(&self) -> &SandboxLayout {
        &self.layout
    }

    /// The host's agent configuration files.
    #[must_use]
    pub fn agents(&self) -> AgentIntegration {
        AgentIntegration::for_home(&self.home)
    }

    /// Directory holding the per-session SSH identities.
    #[must_use]
    pub fn key_directory(&self) -> PathBuf {
        key_directory(&self.home)
    }

    /// File the host key `id` presents is remembered in, with its directory in place.
    ///
    /// Created here rather than left to `ssh`, which writes the file but not the
    /// directory holding it and would otherwise warn on every connection.
    ///
    /// # Errors
    /// Fails when the directory cannot be created.
    pub async fn known_hosts_of(&self, id: &SessionId) -> Result<PathBuf> {
        let path = known_hosts_directory(&self.home).join(id.as_str());
        create_parent(&path).await?;
        Ok(path)
    }

    /// Directory an agent is pointed at for `id`, with the directory itself in place.
    ///
    /// Empty, and meant to stay that way: the session holds a symlink at the same
    /// absolute path pointing at its own work directory, so an agent that resolves the
    /// path here and then executes it there lands in the session. It is created on every
    /// open because an agent validates the path before it connects, and a researcher who
    /// has cleaned out their home directory would otherwise be refused by their own
    /// agent rather than by anything to do with the session.
    ///
    /// # Errors
    /// Fails when the directory cannot be created.
    pub async fn work_alias_of(&self, id: &SessionId) -> Result<PathBuf> {
        let path = work_alias_directory(&self.home).join(id.as_str());
        tokio::fs::create_dir_all(&path)
            .await
            .with_context(|| format!("creating {}", path.display()))?;
        Ok(path)
    }

    /// Directory image build contexts are staged into.
    #[must_use]
    pub fn build_directory(&self) -> PathBuf {
        self.state.join("build")
    }

    /// Socket one opening of a session fetches its borrowed token over.
    ///
    /// Under the state directory rather than the system's temporary one so that its
    /// permissions are the researcher's own, and named for the opening rather than the
    /// session so that two agents in one machine cannot be handed each other's socket.
    #[must_use]
    pub fn loan_socket(&self, attachment: &Attachment) -> PathBuf {
        self.state.join("run").join(attachment.socket_name())
    }

    /// The address the session's machine is answering on right now.
    ///
    /// # Errors
    /// Fails when the runtime does not know the container, or knows it but is not running
    /// it. Neither case has an address to offer: the one it had on its last run belongs to
    /// whatever holds that address now, not to this session.
    pub async fn address_of(&self, name: &ContainerName) -> Result<Ipv4Addr> {
        let state = self
            .runtime()
            .inspect(name)
            .await
            .with_context(|| format!("looking up `{name}`"))?;
        if state.status.state != RunState::Running {
            bail!("session {name} is not running; reopen it with `--resume {name}`");
        }
        state
            .ipv4_address()
            .with_context(|| format!("`{name}` is running but has not been given an address yet"))
    }

    /// Path of the record describing `id`.
    #[must_use]
    pub fn session_path(&self, id: &SessionId) -> PathBuf {
        self.state.join("sessions").join(format!("{id}.json"))
    }

    /// Path of the lock that marks `id`'s session as held by a running invocation.
    ///
    /// The file is beside the record rather than inside it, because it is a kernel-held
    /// fact — the flock on it is the ownership — while the record is data the holder
    /// itself wrote.
    #[must_use]
    pub fn session_lock_path(&self, id: &SessionId) -> PathBuf {
        self.state.join("sessions").join(format!("{id}.lock"))
    }

    /// Reads the record for `id`.
    ///
    /// # Errors
    /// Fails when no such session exists, or the record cannot be read.
    pub async fn session(&self, id: &SessionId) -> Result<SessionRecord> {
        let path = self.session_path(id);
        let text = match tokio::fs::read_to_string(&path).await {
            Ok(text) => text,
            Err(source) if source.kind() == std::io::ErrorKind::NotFound => {
                bail!("no session {id} on this host")
            }
            Err(source) => {
                return Err(source).with_context(|| format!("reading {}", path.display()));
            }
        };
        serde_json::from_str(&text).with_context(|| format!("parsing {}", path.display()))
    }

    /// Every session the host holds, most recently opened first.
    ///
    /// That order is the picker's order and the reclaimer's reverse order, so both agree
    /// on which environments a researcher is still working in.
    ///
    /// # Errors
    /// Fails when the state directory cannot be read or holds an unreadable record.
    pub async fn sessions(&self) -> Result<Vec<SessionRecord>> {
        let directory = self.state.join("sessions");
        let mut entries = match tokio::fs::read_dir(&directory).await {
            Ok(entries) => entries,
            Err(source) if source.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(source) => {
                return Err(source).with_context(|| format!("reading {}", directory.display()));
            }
        };
        let mut records = Vec::new();
        while let Some(entry) = entries
            .next_entry()
            .await
            .with_context(|| format!("reading {}", directory.display()))?
        {
            let path = entry.path();
            if path.extension().is_none_or(|extension| extension != "json") {
                continue;
            }
            let text = tokio::fs::read_to_string(&path)
                .await
                .with_context(|| format!("reading {}", path.display()))?;
            records.push(
                serde_json::from_str::<SessionRecord>(&text)
                    .with_context(|| format!("parsing {}", path.display()))?,
            );
        }
        records.sort_by_key(|record| Reverse(record.last_used));
        Ok(records)
    }

    /// Writes the record for a session that has just been opened.
    ///
    /// # Errors
    /// Fails when the state directory cannot be created or written.
    pub async fn store(&self, record: &SessionRecord) -> Result<()> {
        let path = self.session_path(&record.id);
        create_parent(&path).await?;
        let mut text =
            serde_json::to_string_pretty(record).context("encoding the session record")?;
        text.push('\n');
        tokio::fs::write(&path, text)
            .await
            .with_context(|| format!("writing {}", path.display()))
    }

    /// Deletes the record for `id`, tolerating one that is already gone.
    ///
    /// The lock file goes with it: a session nobody can open has nothing left to hold.
    /// Unlinking a file while a flock is held on it is safe — the lock follows the inode,
    /// and whoever held it is gone by the time its session is forgotten.
    ///
    /// # Errors
    /// Fails when the record exists but cannot be removed.
    pub async fn forget(&self, id: &SessionId) -> Result<()> {
        let path = self.session_path(id);
        match tokio::fs::remove_file(&path).await {
            Ok(()) => Ok(()),
            Err(source) if source.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(source) => Err(source).with_context(|| format!("removing {}", path.display())),
        }?;
        let path = self.session_lock_path(id);
        match tokio::fs::remove_file(&path).await {
            Ok(()) => Ok(()),
            Err(source) if source.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(source) => Err(source).with_context(|| format!("removing {}", path.display())),
        }
    }
}

async fn create_parent(path: &Path) -> Result<()> {
    let Some(parent) = path.parent() else {
        return Ok(());
    };
    tokio::fs::create_dir_all(parent)
        .await
        .with_context(|| format!("creating {}", parent.display()))
}
