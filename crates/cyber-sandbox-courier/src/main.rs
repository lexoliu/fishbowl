//! Runs an agent inside a session on a credential the host keeps lending it.
//!
//! Claude Code will take its credential from a file when told the host manages one, but
//! it does not take the file's word for it: the file names a process, and the credential
//! counts only while that process is alive and was started when the file says it was.
//! This program is that process. Devin's file is simpler — it reads whatever it is handed
//! — so for Devin the loan is only that the file is written before the agent starts and
//! removed after it exits. Either way this program is the one that fetches the credential
//! over a socket the host forwarded in, writes it where the agent reads it, starts the
//! agent, and keeps fetching for as long as the agent runs — so a credential renewed on
//! the host reaches the session without the session ever holding what renews it.
//!
//! It also means the loan ends when the session's agent does. The file goes on the way
//! out, and even a Claude Code file left behind could not be picked up: the process it
//! names is gone, and the next process to be given that pid started at a different moment.

use std::{
    os::unix::process::ExitStatusExt as _,
    path::{Path, PathBuf},
    process::ExitStatus,
    time::Duration,
};

use anyhow::{Context as _, Result, bail};
use clap::{Parser, ValueEnum};
use cyber_sandbox_creds::{Credentials, Lent};
use jiff::Timestamp;
use tokio::{
    net::UnixStream,
    process::{Child, Command},
    signal::unix::{SignalKind, signal},
};

/// How often the credential is fetched again.
///
/// The host renews its login well before the token it lends stops being accepted, and
/// this only has to notice within that margin. Fetching is a round trip over a socket
/// that is already open, so it is cheap enough to do far more often than needed and let
/// the margin be generous.
const REFRESH: Duration = Duration::from_secs(300);

/// The program Claude Code is started as.
const CLAUDE: &str = "claude";

/// Claude Code's own flag for picking up the conversation it last had here.
const CONTINUE: &str = "--continue";

/// Where Claude Code keeps its conversations, under the account's home directory.
const CLAUDE_TRANSCRIPTS: &str = ".claude/projects";

/// Extension of one Claude Code conversation's transcript.
const CLAUDE_TRANSCRIPT: &str = "jsonl";

/// The program Devin is started as, under the account's home directory.
///
/// The researcher's own install rather than a system path, so that Devin's self-updater —
/// which writes beside the binary — may do its job inside a resumed session.
const DEVIN: &str = ".local/bin/devin";

/// Where Devin keeps its conversations, under the account's home directory.
const DEVIN_TRANSCRIPTS: &str = ".local/share/devin/cli/transcripts";

/// Extension of one Devin conversation's transcript.
const DEVIN_TRANSCRIPT: &str = "json";

/// The rules file the briefing is written into, under the account's home directory.
///
/// Devin has no flag for adding to its system prompt the way Claude Code has
/// `--append-system-prompt`; a rule in the account's own `.windsurf/rules` is read at the
/// start of every session, which is the same channel for telling it about a key it has
/// been given. It is the home directory's rules and not the work directory's on purpose:
/// the work directory is where samples are detonated, and a rule a sample can rewrite is
/// a prompt a sample can write.
const BRIEFING_RULE: &str = ".windsurf/rules/cyber-sandbox.md";

/// The agent the courier is holding a credential for.
///
/// Which one decides what the lent bytes become, where a continuing conversation is
/// found, and how the agent is started — the loan, the renewal and the take-back are the
/// same for both.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
enum Agent {
    /// Claude Code, which reads the courier's pid-bound credentials file.
    Claude,
    /// Devin, which reads the credentials file it is handed verbatim.
    Devin,
}

impl Agent {
    /// The agent's name, for messages.
    fn name(self) -> &'static str {
        match self {
            Self::Claude => "claude",
            Self::Devin => "devin",
        }
    }
}

#[derive(Debug, Parser)]
#[command(about = "Runs an agent on a credential lent by the cyber-sandbox host")]
struct Courier {
    /// Agent to run.
    #[arg(long)]
    agent: Agent,
    /// Socket the host publishes the current credential on.
    #[arg(long)]
    socket: PathBuf,
    /// File to write the credential into, where the agent reads it.
    #[arg(long)]
    credentials: PathBuf,
    /// Directory the agent is started in.
    #[arg(long)]
    directory: PathBuf,
    /// Carry on the conversation this session was last left in, if it has one.
    ///
    /// The host knows the researcher asked to come back to the session; only the session
    /// knows whether there is anything here to come back to. Asking the agent to continue
    /// a conversation that was never had is an error rather than a fresh start, so the
    /// two halves of the question are answered where each of them is known.
    #[arg(long)]
    continue_conversation: bool,
    /// What the agent is told about the keys it has been given, written where it reads
    /// its rules.
    ///
    /// Only Devin takes a briefing this way; Claude is briefed through its own
    /// `--append-system-prompt`, passed through after `--` like anything else of its.
    #[arg(long)]
    briefing: Option<String>,
    /// Arguments the agent is started with.
    #[arg(last = true)]
    arguments: Vec<String>,
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> std::process::ExitCode {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("warn")),
        )
        .with_writer(std::io::stderr)
        .init();

    let courier = Courier::parse();
    match run(&courier).await {
        Ok(status) => {
            std::process::ExitCode::from(u8::try_from(exit_code(status)).unwrap_or(u8::MAX))
        }
        Err(error) => {
            tracing::error!("{error:#}");
            std::process::ExitCode::FAILURE
        }
    }
}

/// Lends the credential, runs the agent on it, and takes it back.
async fn run(courier: &Courier) -> Result<ExitStatus> {
    if courier.agent != Agent::Devin && courier.briefing.is_some() {
        bail!(
            "--briefing goes where {} reads its rules, and {} has none; brief claude \
             through its own --append-system-prompt",
            Agent::Devin.name(),
            courier.agent.name()
        );
    }
    // The first fetch is not allowed to fail: starting the agent without a credential
    // would land the researcher in a login prompt inside a machine that cannot complete
    // one, which is a worse answer than saying why here.
    lend(courier)
        .await
        .context("fetching the host's credential")?;
    place_briefing(courier.briefing.as_deref()).await?;

    let agent = spawn(courier).context("starting the agent in the session")?;
    let status = supervise(courier, agent).await;

    // Whatever happened above, and before anything is reported: the loan is over, and so
    // is what the agent was told — a briefing left behind would describe a key the next
    // run may not have been given.
    cyber_sandbox_creds::remove(&courier.credentials)
        .await
        .context("taking back the credential")?;
    place_briefing(None)
        .await
        .context("taking back the briefing")?;
    // And so is the way the credential arrived. sshd unlinks the forwarded socket when it
    // tears the channel down, but a connection cut rather than closed leaves the name
    // behind, and nothing else will ever ask for this one: it was named for this run
    // alone.
    remove_if_present(&courier.socket)
        .await
        .context("taking back the socket the credential arrived on")?;
    status
}

/// Removes `path`, treating an absent file as the state that was asked for.
async fn remove_if_present(path: &Path) -> Result<()> {
    match tokio::fs::remove_file(path).await {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error).with_context(|| format!("removing {}", path.display())),
    }
}

/// Runs the agent to completion, renewing the loan underneath it.
///
/// The agent is a child rather than a replacement for this process because the
/// credential file has to keep being rewritten while it runs — and for Claude Code,
/// because the process the file names has to still be there for it to be read. That makes
/// the terminal's interrupt this process's problem too — it reaches the whole foreground
/// process group — so it is received and deliberately ignored here, leaving the agent to
/// shut itself down.
async fn supervise(courier: &Courier, mut agent: Child) -> Result<ExitStatus> {
    let mut interrupt = signal(SignalKind::interrupt()).context("listening for an interrupt")?;
    let mut terminate = signal(SignalKind::terminate()).context("listening for a termination")?;
    let mut hangup = signal(SignalKind::hangup()).context("listening for a hangup")?;
    let mut renewal = tokio::time::interval(REFRESH);
    renewal.tick().await;

    loop {
        tokio::select! {
            status = agent.wait() => return status.context("waiting for the agent to finish"),
            _ = renewal.tick() => {
                // A failed renewal is not fatal: the credential already written stays
                // valid until it expires, and the next attempt is five minutes away.
                if let Err(error) = lend(courier).await {
                    tracing::warn!("could not renew the host's credential: {error:#}");
                }
            }
            _ = interrupt.recv() => {}
            _ = terminate.recv() => {}
            _ = hangup.recv() => {}
        }
    }
}

/// Fetches the current credential and writes it where the agent reads it.
///
/// The variant the host sends is the agent's whole answer: a bearer becomes the
/// pid-vouched file Claude Code checks, and a document is installed as Devin's
/// credentials file unchanged. A variant meant for the other agent is refused, because a
/// credential written in the wrong shape is a login that fails for no stated reason.
async fn lend(courier: &Courier) -> Result<()> {
    if let Some(parent) = courier.credentials.parent() {
        tokio::fs::create_dir_all(parent)
            .await
            .with_context(|| format!("creating {}", parent.display()))?;
    }
    match (courier.agent, fetch(&courier.socket).await?) {
        (Agent::Claude, Lent::Bearer(bearer)) => {
            let stamp = Stamp::of_self().context("reading this process's own identity")?;
            let credentials = Credentials {
                env: cyber_sandbox_creds::bearer_environment(&bearer.token),
                expires_at: bearer.expires_at,
                pid: stamp.pid,
                proc_start: stamp.started,
            };
            credentials
                .write_to(&courier.credentials)
                .await
                .with_context(|| format!("writing {}", courier.credentials.display()))
        }
        (Agent::Devin, Lent::Document(contents)) => {
            cyber_sandbox_creds::install(&courier.credentials, contents.as_bytes())
                .await
                .with_context(|| format!("writing {}", courier.credentials.display()))
        }
        (agent, lent) => {
            let lent = match lent {
                Lent::Bearer(_) => "a token",
                Lent::Document(_) => "a document",
            };
            bail!(
                "the host lent {lent}, which is not a credential {} can read",
                agent.name()
            )
        }
    }
}

/// Asks the host for the credential it is currently prepared to lend.
async fn fetch(socket: &Path) -> Result<Lent> {
    let stream = UnixStream::connect(socket)
        .await
        .with_context(|| format!("connecting to {}", socket.display()))?;
    Lent::receive(stream)
        .await
        .context("reading the credential the host sent")
}

/// Writes the briefing where Devin reads its rules, or takes it back when there is none.
///
/// The file is this run's rather than the session's: which keys the agent was given is
/// decided by the host's environment at attach time, so a rule written by one run and
/// left behind would tell the next run about a key it does not have.
async fn place_briefing(briefing: Option<&str>) -> Result<()> {
    let home = std::env::var_os("HOME").context("this account has no HOME to write in")?;
    let path = PathBuf::from(home).join(BRIEFING_RULE);
    match briefing {
        Some(briefing) => {
            if let Some(parent) = path.parent() {
                tokio::fs::create_dir_all(parent)
                    .await
                    .with_context(|| format!("creating {}", parent.display()))?;
            }
            tokio::fs::write(
                &path,
                format!("---\ntrigger: always_on\n---\n\n{briefing}\n"),
            )
            .await
            .with_context(|| format!("writing {}", path.display()))
        }
        None => remove_if_present(&path).await,
    }
}

/// How the agent is started for a session.
fn spawn(courier: &Courier) -> Result<Child> {
    let mut command = match courier.agent {
        Agent::Claude => {
            let mut command = Command::new(CLAUDE);
            command.envs(cyber_sandbox_creds::launch_environment(
                &courier.credentials,
            ));
            command
        }
        Agent::Devin => {
            let home = std::env::var_os("HOME").context("this account has no HOME to run from")?;
            Command::new(PathBuf::from(home).join(DEVIN))
        }
    };
    command
        .args(arguments(courier)?)
        .current_dir(&courier.directory);
    command.spawn().with_context(|| {
        format!(
            "running {} in {}",
            courier.agent.name(),
            courier.directory.display()
        )
    })
}

/// The arguments the agent is given, once the session has answered what only it knows.
///
/// # Errors
/// Fails when the account has no home directory to look in.
fn arguments(courier: &Courier) -> Result<Vec<String>> {
    let mut arguments = courier.arguments.clone();
    if courier.continue_conversation && has_conversation(courier.agent)? {
        arguments.insert(0, CONTINUE.to_owned());
    }
    Ok(arguments)
}

/// Whether this session holds a conversation the agent could carry on.
///
/// Each agent is only ever started in one directory here, so the question is whether it
/// has written any transcript at all — which is read from its own files, rather than by
/// reproducing the way it names the directory one belongs to.
fn has_conversation(agent: Agent) -> Result<bool> {
    let home =
        PathBuf::from(std::env::var_os("HOME").context("this account has no HOME to look in")?);
    match agent {
        Agent::Claude => has_transcript(home.join(CLAUDE_TRANSCRIPTS), CLAUDE_TRANSCRIPT, true),
        Agent::Devin => has_transcript(home.join(DEVIN_TRANSCRIPTS), DEVIN_TRANSCRIPT, false),
    }
}

/// Whether `directory` holds a transcript file with `extension`, recursing when the
/// agent files its own deeper.
fn has_transcript(directory: PathBuf, extension: &str, recurse: bool) -> Result<bool> {
    let mut pending = vec![directory];
    while let Some(directory) = pending.pop() {
        let entries = match std::fs::read_dir(&directory) {
            Ok(entries) => entries,
            // Nothing has been written here yet, which is itself the answer.
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
            Err(error) => {
                return Err(error).with_context(|| format!("reading {}", directory.display()));
            }
        };
        for entry in entries {
            let entry = entry.with_context(|| format!("reading {}", directory.display()))?;
            let path = entry.path();
            if recurse && path.is_dir() {
                pending.push(path);
            } else if path.extension().is_some_and(|kind| kind == extension) {
                return Ok(true);
            }
        }
    }
    Ok(false)
}

/// This process's identity, as Claude Code will go and check it.
#[derive(Debug, Clone, Copy)]
struct Stamp {
    pid: u32,
    started: Timestamp,
}

impl Stamp {
    /// Reads this process's own pid and start time.
    ///
    /// Claude Code learns the start time from `ps`, which reports whole seconds, and
    /// procps arrives at them by adding the process's start — counted in clock ticks
    /// since boot — to the boot time and truncating. The same arithmetic is done here, so
    /// that the two agree exactly rather than within the tolerance Claude Code allows.
    fn of_self() -> Result<Self> {
        let process = procfs::process::Process::myself().context("opening /proc/self")?;
        let stat = process.stat().context("reading /proc/self/stat")?;
        let boot = procfs::boot_time_secs().context("reading the boot time")?;
        let ticks = procfs::ticks_per_second();
        let started = i64::try_from(boot + stat.starttime / ticks)
            .context("the boot time is not a time this century")?;
        Ok(Self {
            pid: std::process::id(),
            started: Timestamp::from_second(started).context("the start time is not a time")?,
        })
    }
}

/// What a shell would report for `status`, so that an agent killed by a signal is not
/// mistaken for one that merely returned nothing.
fn exit_code(status: ExitStatus) -> i32 {
    status
        .code()
        .or_else(|| status.signal().map(|signal| 128 + signal))
        .unwrap_or(1)
}
