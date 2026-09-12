//! Implementations of the individual commands.

pub mod audit;
pub mod claude;
pub mod codex;
pub mod devin;
pub mod shell;

use std::{
    io::Write as _,
    os::unix::process::ExitStatusExt as _,
    path::{Path, PathBuf},
    process::ExitStatus,
};

use anyhow::{Context as _, Result};
use askama::Template;
use fishbowl_agents::SandboxEndpoint;
use tokio::{
    process::Command,
    signal::unix::{SignalKind, signal},
};

use crate::{handoff::Handoff, host::Host, provision};

/// What is printed before the session is handed over.
#[derive(Debug, Template)]
#[template(path = "session.txt", escape = "none")]
struct Banner {
    created: bool,
    command: &'static str,
    id: String,
    image: String,
    arch: String,
    samples: String,
    work_dir: String,
    keys: String,
}

/// Tells the researcher what they are about to be dropped into, where `command` is the
/// subcommand that would reopen this session.
///
/// Written to standard error, because the session's own output is what belongs on
/// standard output — a `fishbowl shell -- file sample.bin` piped into something else
/// must not have this in front of it.
pub fn banner(
    host: &Host,
    session: &provision::Session,
    handoff: &Handoff,
    command: &'static str,
) -> Result<()> {
    let record = &session.record;
    let text = Banner {
        created: session.created,
        command,
        id: record.id.to_string(),
        image: record.image.to_string(),
        arch: record.arch.to_string(),
        samples: record.samples.as_ref().map_or_else(
            || "none mounted".to_owned(),
            |path| {
                format!(
                    "{} \u{2192} {}",
                    path.display(),
                    host.layout().samples_dir.display()
                )
            },
        ),
        work_dir: record.work_dir.display().to_string(),
        keys: handoff.summary(),
    }
    .render()
    .context("rendering the session summary")?;
    std::io::stderr()
        .lock()
        .write_all(text.as_bytes())
        .context("writing the session summary")
}

/// What is printed as a session's run ends.
///
/// The agents' own exit lines — `devin -r <name>`, `claude --resume <id>` — name a
/// process inside a machine that is already being released, and following them on the
/// host finds nothing. The session is the thing that can be reopened, so it gets the
/// last word.
///
/// # Errors
/// Fails when the line cannot be written.
pub fn epilogue(session: &provision::Session, command: &'static str) -> Result<()> {
    let text = format!(
        "Come back to this session with `fishbowl {command} --resume {}`\n",
        session.record.id
    );
    std::io::stderr()
        .lock()
        .write_all(text.as_bytes())
        .context("writing the session's closing line")
}

/// Quotes `value` for a POSIX shell, since a remote command is interpreted by one.
///
/// Every path this tool sends across is one it made itself, so this is not the difference
/// between working and broken — it is the difference between a session that goes wrong
/// where a path holds a quote and one that cannot be made to run something else by it.
pub fn shell_quote(value: &str) -> String {
    format!("'{}'", value.replace('\'', r"'\''"))
}

/// The courier, which is what a session holding a borrowed credential is asked to run.
pub const COURIER: &str = "/usr/local/bin/fishbowl-courier";

/// Tells the courier the researcher came back to this session rather than made one.
///
/// Not the agent's own flag for it: a machine can be reopened without ever having held a
/// conversation, and whether there is a transcript to carry on is known in the session,
/// so the courier is the one that decides.
const CARRY_ON: &str = "--continue-conversation";

/// Tells the courier what the agent is to know about the keys it has been given, for the
/// agents that take a briefing through it rather than through a flag of their own.
const BRIEF: &str = "--briefing";

/// What a session is asked to do on the researcher's behalf, in the session's own terms.
///
/// The agent's name decides which credential the courier expects over the socket and how
/// the agent is started; the rest of the errand is the same whatever is run.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Errand {
    /// The agent the courier runs: its `--agent` value.
    pub agent: &'static str,
    /// Where the loan socket appears inside the session.
    pub socket: PathBuf,
    /// Where the courier writes the credential for the agent to read.
    pub credentials: PathBuf,
    /// Directory the agent works in.
    pub directory: PathBuf,
    /// Whether this session is being reopened rather than created.
    pub resumed: bool,
    /// What the agent is told about the researcher's keys it has been given, if any.
    pub briefing: Option<String>,
    /// How a briefing reaches this agent.
    pub channel: Briefing,
    /// How the agent is asked to run, passed after `--`.
    pub autonomous: &'static [&'static str],
}

/// How an agent is told about the keys it has been given.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Briefing {
    /// Through a flag of the agent's own, passed through after `--`.
    Flag(&'static str),
    /// Through the courier, which writes it where the agent reads its rules.
    Rule,
}

impl Errand {
    /// The one command the session runs, as a shell there will read it.
    ///
    /// The courier is exec'd rather than run under a shell, so the process the session's
    /// sshd is waiting on is the courier itself: a connection that drops takes the
    /// courier with it, and the courier taking the credential file away is what happens
    /// when it goes.
    #[must_use]
    pub fn remote_command(&self) -> String {
        let mut parts = vec![
            "exec".to_owned(),
            COURIER.to_owned(),
            "--agent".to_owned(),
            self.agent.to_owned(),
            "--socket".to_owned(),
            shell_quote(&self.socket.display().to_string()),
            "--credentials".to_owned(),
            shell_quote(&self.credentials.display().to_string()),
            "--directory".to_owned(),
            shell_quote(&self.directory.display().to_string()),
        ];
        if self.resumed {
            parts.push(CARRY_ON.to_owned());
        }
        if let (Some(briefing), Briefing::Rule) = (&self.briefing, self.channel) {
            parts.push(BRIEF.to_owned());
            parts.push(shell_quote(briefing));
        }
        parts.push("--".to_owned());
        parts.extend(
            self.autonomous
                .iter()
                .map(|argument| (*argument).to_owned()),
        );
        if let (Some(briefing), Briefing::Flag(flag)) = (&self.briefing, self.channel) {
            parts.push((*flag).to_owned());
            parts.push(shell_quote(briefing));
        }
        parts.join(" ")
    }
}

/// Runs the session's agent to completion, outliving the signals that end it.
///
/// `ssh` is a child rather than a replacement for this process, because this process is
/// the one holding the socket the session fetches its credential from — replacing it
/// would take the credential away at the moment the session first asked for one. That
/// makes the terminal's interrupt this process's problem too: it reaches the whole
/// foreground process group, so it is received and deliberately ignored here, leaving
/// the agent to shut itself down while the parent survives long enough to take the
/// socket back.
pub async fn supervise(
    endpoint: &SandboxEndpoint,
    errand: &Errand,
    host_socket: &Path,
) -> Result<ExitStatus> {
    let mut interrupt = signal(SignalKind::interrupt()).context("listening for an interrupt")?;
    let mut terminate = signal(SignalKind::terminate()).context("listening for a termination")?;
    let mut hangup = signal(SignalKind::hangup()).context("listening for a hangup")?;

    let mut client = invocation(endpoint, errand, host_socket)
        .spawn()
        .context("opening the session")?;

    loop {
        tokio::select! {
            status = client.wait() => return status.context("waiting for the session to finish"),
            _ = interrupt.recv() => {}
            _ = terminate.recv() => {}
            _ = hangup.recv() => {}
        }
    }
}

/// How `ssh` is invoked to put the agent on the far side of it.
fn invocation(endpoint: &SandboxEndpoint, errand: &Errand, host_socket: &Path) -> Command {
    let mut command = Command::new("ssh");
    command.args([
        // The agent is a full-screen program and the researcher is sitting in front of
        // it, so the session needs a terminal of its own; ssh only allocates one for a
        // remote command when asked twice.
        "-t",
        "-t",
        "-o",
        // Without this the forward failing is a warning, and what follows is an agent
        // with no credential to fetch — which fails much later and says nothing about a
        // socket.
        "ExitOnForwardFailure=yes",
        "-R",
    ]);
    command.arg(forward(&errand.socket, host_socket));
    // The destination is the last of these, so everything of ours goes in front of it.
    command.args(endpoint.ssh_arguments());
    command.arg(errand.remote_command());
    command
}

/// The `-R` specification publishing the host's socket inside the session.
fn forward(guest_socket: &Path, host_socket: &Path) -> String {
    format!("{}:{}", guest_socket.display(), host_socket.display())
}

/// What a shell would report for `status`, so that a session killed by a signal is not
/// mistaken for one that merely returned nothing.
pub fn exit_code(status: ExitStatus) -> i32 {
    status
        .code()
        .or_else(|| status.signal().map(|signal| 128 + signal))
        .unwrap_or(1)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn endpoint() -> SandboxEndpoint {
        SandboxEndpoint {
            id: "c0ffee".to_owned(),
            user: "researcher".to_owned(),
            host: "192.168.65.40".to_owned(),
            port: 22,
            identity_file: PathBuf::from("/state/keys/c0ffee"),
            known_hosts: PathBuf::from("/state/known_hosts/c0ffee"),
            start_directory: PathBuf::from("/work"),
            send_environment: Vec::new(),
        }
    }

    fn errand() -> Errand {
        Errand {
            agent: "an-agent",
            socket: PathBuf::from("/run/fishbowl/c0ffee-1a2b3c4d.sock"),
            credentials: PathBuf::from("/run/fishbowl/c0ffee-1a2b3c4d.json"),
            directory: PathBuf::from("/work"),
            resumed: false,
            briefing: None,
            channel: Briefing::Rule,
            autonomous: &["--autonomous"],
        }
    }

    fn arguments() -> Vec<String> {
        invocation(
            &endpoint(),
            &errand(),
            Path::new("/Users/researcher/.fishbowl/run/c0ffee-1a2b3c4d.sock"),
        )
        .as_std()
        .get_args()
        .map(|argument| argument.to_string_lossy().into_owned())
        .collect()
    }

    #[test]
    fn a_path_holding_a_quote_cannot_escape_the_remote_command() {
        assert_eq!(shell_quote("/srv/work"), "'/srv/work'");
        assert_eq!(shell_quote("/srv/it's"), r"'/srv/it'\''s'");
    }

    #[test]
    fn the_credential_socket_is_published_into_the_session_rather_than_out_of_it() {
        let arguments = arguments();
        let forward = arguments
            .windows(2)
            .find(|pair| pair[0] == "-R")
            .map(|pair| pair[1].clone())
            .expect("the forward is what the session fetches its credential over");

        assert_eq!(
            forward,
            "/run/fishbowl/c0ffee-1a2b3c4d.sock:\
             /Users/researcher/.fishbowl/run/c0ffee-1a2b3c4d.sock",
            "the guest path comes first: a local forward would instead let the host \
             originate connections through the machine running samples"
        );
    }

    #[test]
    fn a_forward_that_could_not_be_made_stops_the_session_rather_than_starting_it() {
        assert!(
            arguments()
                .windows(2)
                .any(|pair| pair == ["-o", "ExitOnForwardFailure=yes"]),
            "the default is a warning, and what follows it is an agent whose credential \
             fetch fails minutes later with nothing said about a socket"
        );
    }

    #[test]
    fn the_credential_never_appears_on_the_command_line() {
        let arguments = arguments().join(" ");
        assert!(
            !arguments.contains("key=") && !arguments.contains("TOKEN"),
            "a command line is readable by every process on both machines, so the \
             credential crosses over the socket and only over the socket: {arguments}"
        );
    }

    #[test]
    fn a_signalled_run_is_reported_the_way_a_shell_would() {
        assert_eq!(exit_code(ExitStatus::from_raw(2 << 8)), 2);
        assert_eq!(exit_code(ExitStatus::from_raw(9)), 137);
    }
}
