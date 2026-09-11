//! Turning a request for a session into a machine that answers.
//!
//! Everything the old lifecycle commands did happens here instead, in the order a session
//! needs it: start the runtime's services, reclaim what has gone stale, size the machine
//! against the host, build the image if none was built from these sources for this
//! architecture, create or restart the machine, and wait until sshd answers on it. None
//! of it is a step the researcher takes.

use std::{
    net::{Ipv4Addr, SocketAddr},
    path::{Path, PathBuf},
    time::Duration,
};

use anyhow::{Context as _, Result, bail};
use cyber_sandbox_runtime::{
    Arch, Capability, ContainerName, ContainerSpec, ContainerState, ImageReference, Mount,
    Reservation, RunState, Sandbox,
};
use jiff::Timestamp;

use crate::{
    cli,
    host::Host,
    image,
    keys::SandboxKey,
    lease::Lease,
    pick, reclaim,
    session::{SessionId, SessionRecord},
};

/// How long a machine has to obtain an address and answer on its SSH port.
const READY_TIMEOUT: Duration = Duration::from_secs(120);

/// How often readiness is re-checked while waiting.
const READY_INTERVAL: Duration = Duration::from_millis(500);

/// How many identifiers are drawn before giving up on finding an unused one.
///
/// Reaching this means the entropy source is repeating itself, which is a fault worth
/// reporting rather than looping on.
const ID_ATTEMPTS: usize = 32;

/// Environment the entrypoint reads its per-session facts from.
const NAME_VARIABLE: &str = "CYBER_SANDBOX_NAME";
const RESOLVER_VARIABLE: &str = "CYBER_SANDBOX_RESOLVER";
const AUTHORIZED_KEY_VARIABLE: &str = "CYBER_SANDBOX_AUTHORIZED_KEY";
const WORK_ALIAS_VARIABLE: &str = "CYBER_SANDBOX_WORK_ALIAS";

/// A session whose machine is running and reachable right now, held by this process.
#[derive(Debug)]
pub struct Session {
    /// What the host remembers about it.
    pub record: SessionRecord,
    /// The address it is answering on, as the runtime reports it.
    pub address: Ipv4Addr,
    /// Whether this invocation created it.
    pub created: bool,
    /// The hold on the session: kept for the life of the process, its release stops the
    /// machine — and a process that is gone releases it without being asked. Held, never
    /// read: holding it is the whole of its work.
    #[allow(dead_code)]
    pub lease: Lease,
}

/// Opens the session `attach` asks for, creating one when it asks for none.
///
/// # Errors
/// Fails when the host cannot carry another machine, when the image cannot be built, when
/// an argument contradicts the session being resumed, or when the machine does not answer
/// in time.
pub async fn open(host: &Host, attach: &cli::Attach) -> Result<Session> {
    ensure_services(host).await?;
    match resolve(host, attach.resume.as_ref()).await? {
        Some(record) => resume(host, attach, record).await,
        None => create(host, attach).await,
    }
}

/// Which session was asked for, if an existing one was.
async fn resolve(host: &Host, resume: Option<&cli::Resume>) -> Result<Option<SessionRecord>> {
    match resume {
        None => Ok(None),
        Some(cli::Resume::Named(id)) => host.session(id).await.map(Some),
        Some(cli::Resume::Pick) => {
            let sessions = host.sessions().await?;
            if sessions.is_empty() {
                bail!("there are no sessions to resume; run the same command without `--resume`");
            }
            let live = host
                .runtime()
                .list()
                .await
                .context("listing the runtime's containers")?;
            pick::choose(sessions, &live).map(Some)
        }
    }
}

/// Starts the runtime's system services when they are not already up.
///
/// This is the one repair the old `doctor --fix` did that a session cannot do without:
/// without the API server there is no runtime to ask anything of.
async fn ensure_services(host: &Host) -> Result<()> {
    let status = host
        .runtime()
        .system_status()
        .await
        .context("asking the runtime whether its services are running")?;
    if status.is_running() {
        return Ok(());
    }
    tracing::info!(status = status.status, "starting the runtime's services");
    host.runtime()
        .system_start()
        .await
        .context("starting the runtime's services")
}

/// Creates a session, and the machine underneath it.
async fn create(host: &Host, attach: &cli::Attach) -> Result<Session> {
    let arch = attach.arch.unwrap_or(Arch::HOST);
    let samples = canonical_samples(attach.samples.as_deref())?;

    // The image is named before anything is reclaimed, because reclamation takes away
    // every image no session refers to — and the one this session is about to start from
    // is exactly that until the session exists.
    let source = image::source(host, attach.workspace.as_deref(), arch).await?;

    // Stale environments go before the host is measured, so that the measurement is of
    // the host this session will actually run on.
    reclaim::make_room(host, source.tag()).await?;

    // Sizing is checked before anything is created, so a host that cannot carry another
    // session refuses without leaving an identity or a machine behind.
    let reservation = host.budget().await?.suggest::<Sandbox>()?;
    tracing::info!(
        cpus = %reservation.cpus(),
        memory = %reservation.memory(),
        "the host can carry another session"
    );

    image::ensure(host, &source, arch).await?;
    let image = source.tag().clone();

    let id = allocate(host).await?;
    // The lease is taken before the machine is: a failure or a kill between here and the
    // record being written still ends with the machine stopped, because the reaper is
    // already armed.
    let lease = Lease::acquire(host, &id).await?;
    let name = id.container_name()?;
    let key = SandboxKey::load_or_create(&host.key_directory(), id.as_str()).await?;
    let work_alias = host.work_alias_of(&id).await?;

    let layout = host.layout();
    let machine = Machine {
        name,
        image: image.clone(),
        arch,
        key: &key,
        reservation,
        samples: samples.clone(),
        work_alias,
    };
    host.runtime()
        .run_detached(&machine.spec(host))
        .await
        .context("creating the session's machine")?;

    let address = wait_until_reachable(host, &machine.name, layout.ssh_port).await?;
    let now = Timestamp::now();
    let record = SessionRecord {
        id,
        image,
        arch,
        ssh_port: layout.ssh_port,
        researcher: layout.researcher.name.clone(),
        work_dir: layout.work_dir.clone(),
        samples,
        identity_file: key.identity_file().to_path_buf(),
        created_at: now,
        last_used: now,
    };
    host.store(&record).await?;

    Ok(Session {
        record,
        address,
        created: true,
        lease,
    })
}

/// Reopens a session, refusing anything its machine's shape cannot honour.
async fn resume(host: &Host, attach: &cli::Attach, mut record: SessionRecord) -> Result<Session> {
    // The lock is taken before the machine's state is read: a predecessor's reaper may
    // still be stopping it, and only the lock makes the state observed underneath stable.
    let lease = Lease::acquire(host, &record.id).await?;
    let name = record.id.container_name()?;
    let Some(container) = existing(host, &name).await? else {
        // The record describes a machine the runtime no longer holds, so there is nothing
        // to reopen and nothing worth keeping: the session goes rather than being offered
        // again by the next picker.
        let id = record.id.clone();
        reclaim::remove(host, &record).await?;
        bail!(
            "session {id} is gone: the runtime no longer holds its machine, so it has been \
             cleared away. Run the same command without `--resume` for a new one"
        );
    };

    if let Some(arch) = attach.arch
        && arch != record.arch
    {
        bail!(
            "session {} runs {}, but was asked for {arch}; a machine's architecture is \
             settled when it is created, so start a new session for {arch} instead",
            record.id,
            record.arch
        );
    }
    if let Some(samples) = canonical_samples(attach.samples.as_deref())?
        && record.samples.as_ref() != Some(&samples)
    {
        bail!(
            "session {} was created with {}, but was asked for {}; a machine's mounts are \
             settled when it is created, so start a new session for those samples instead",
            record.id,
            record.samples.as_ref().map_or_else(
                || "no samples".to_owned(),
                |mounted| mounted.display().to_string()
            ),
            samples.display()
        );
    }

    if container.status.state == RunState::Running {
        // The lock was free, so no owner is attached: a machine this old was left
        // running by an invocation that ended before the reaper could stop it, and
        // attaching to it is still cheaper than a fresh boot.
        tracing::debug!(session = %record.id, "already running");
    } else {
        // A stopped machine costs the host nothing and a started one costs its whole
        // allocation, so restarting it is checked against the host exactly as creating it
        // is — for the size it already has, which is the only size it can come back at.
        let (cpus, memory) = container.configuration.resources.allocation()?;
        let reservation = host.budget().await?.reserve::<Sandbox>(cpus, memory)?;
        tracing::info!(
            cpus = %reservation.cpus(),
            memory = %reservation.memory(),
            "the host can carry this session again"
        );
        host.runtime()
            .start(&name, &reservation)
            .await
            .context("restarting the session's machine")?;
    }

    let address = wait_until_reachable(host, &name, record.ssh_port).await?;
    record.last_used = Timestamp::now();
    host.store(&record).await?;

    Ok(Session {
        record,
        address,
        created: false,
        lease,
    })
}

/// Draws an identifier neither the host's state nor the runtime already holds.
async fn allocate(host: &Host) -> Result<SessionId> {
    let live = host
        .runtime()
        .list()
        .await
        .context("listing the runtime's containers")?;
    for _ in 0..ID_ATTEMPTS {
        let id = SessionId::random()?;
        let taken = live
            .iter()
            .any(|container| container.id.as_str() == id.as_str())
            || host.session_path(&id).exists()
            || host.session_lock_path(&id).exists();
        if !taken {
            return Ok(id);
        }
    }
    bail!(
        "drew {ID_ATTEMPTS} session identifiers and every one was already in use; the \
         system's entropy source is repeating itself"
    )
}

/// Everything one session's machine is made of, gathered before any of it exists.
///
/// These travel together because they describe a single machine, and taken apart they
/// become a row of loose values whose order is all that keeps them straight.
struct Machine<'key> {
    name: ContainerName,
    image: ImageReference,
    arch: Arch,
    key: &'key SandboxKey,
    reservation: Reservation<Sandbox>,
    samples: Option<PathBuf>,
    work_alias: PathBuf,
}

impl Machine<'_> {
    /// What the runtime is asked to create.
    fn spec(&self, host: &Host) -> ContainerSpec {
        let layout = host.layout();
        let mut spec = ContainerSpec::new(
            self.name.clone(),
            self.image.clone(),
            self.arch,
            self.reservation,
        );

        // Neither capability below has a use inside the machine, so the runtime removes them
        // before the guest is even started.
        spec.cap_drop = vec![Capability::SysModule, Capability::SysAdmin];
        // NET_ADMIN is what the entrypoint installs the egress policy with, and it is not in
        // the runtime's default set. The entrypoint hands it to nothing else: it drops the
        // capability from the bounding set of the process tree that runs sample code, so only
        // the code between container start and sshd ever holds it. SYS_PTRACE is for the
        // debuggers and tracers in the analysis toolchain, which have to attach to the
        // processes they are analysing.
        spec.cap_add = vec![Capability::NetAdmin, Capability::SysPtrace];
        spec.init = true;

        if let Some(source) = self.samples.as_ref() {
            spec.mounts
                .push(Mount::read_only(source.clone(), layout.samples_dir.clone()));
        }

        spec.env
            .insert(NAME_VARIABLE.to_owned(), self.name.to_string());
        spec.env.insert(
            RESOLVER_VARIABLE.to_owned(),
            cli::DEFAULT_RESOLVER.to_owned(),
        );
        spec.env.insert(
            AUTHORIZED_KEY_VARIABLE.to_owned(),
            self.key.authorized_key().to_owned(),
        );
        // Not a mount: the entrypoint makes this path a symlink to the work directory, so an
        // agent that resolved it on the host executes in the session's own filesystem and
        // the host directory it named stays empty.
        spec.env.insert(
            WORK_ALIAS_VARIABLE.to_owned(),
            self.work_alias.display().to_string(),
        );

        spec
    }
}

fn canonical_samples(samples: Option<&Path>) -> Result<Option<PathBuf>> {
    samples
        .map(|path| {
            path.canonicalize()
                .with_context(|| format!("resolving the sample directory {}", path.display()))
        })
        .transpose()
}

/// The runtime's view of a machine, when it has one.
async fn existing(host: &Host, name: &ContainerName) -> Result<Option<ContainerState>> {
    let containers = host
        .runtime()
        .list()
        .await
        .context("listing the runtime's containers")?;
    Ok(containers
        .into_iter()
        .find(|container| &container.id == name))
}

/// Waits until the machine has an address and sshd answers on it.
///
/// Both halves matter: the runtime reports an address as soon as the guest's interface is
/// configured, which is well before the entrypoint has installed the egress policy and
/// started sshd. Handing back a session that cannot yet be reached would turn into a
/// connection that fails on first use.
async fn wait_until_reachable(
    host: &Host,
    name: &ContainerName,
    ssh_port: u16,
) -> Result<Ipv4Addr> {
    let deadline = tokio::time::Instant::now() + READY_TIMEOUT;
    let mut last = String::from("the runtime has not reported an address yet");

    while tokio::time::Instant::now() < deadline {
        match host.runtime().inspect(name).await {
            Ok(state) => match state.ipv4_address() {
                Some(address) if accepts(SocketAddr::from((address, ssh_port))).await => {
                    return Ok(address);
                }
                Some(address) => last = format!("{address} is not answering yet"),
                None => "the runtime has not reported an address yet".clone_into(&mut last),
            },
            Err(error) => last = error.to_string(),
        }
        tokio::time::sleep(READY_INTERVAL).await;
    }

    bail!(
        "session {name} did not become reachable within {}s: {last}. Its startup output is \
         available with `container logs {name}`",
        READY_TIMEOUT.as_secs()
    )
}

async fn accepts(address: SocketAddr) -> bool {
    matches!(
        tokio::time::timeout(READY_INTERVAL, tokio::net::TcpStream::connect(address)).await,
        Ok(Ok(_))
    )
}
