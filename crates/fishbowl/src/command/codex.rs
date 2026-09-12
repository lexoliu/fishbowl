//! Running Codex against a session.
//!
//! Codex has no `ssh` subcommand and no switch for choosing an environment. Its
//! equivalent of one is an entry in `~/.codex/environments.toml` whose transport is a
//! stdio command, and the only way to attach to it without making the researcher walk a
//! menu they did not ask for is to preselect it as that file's `default`. So this command
//! writes the session's entry, preselects it, runs Codex on the host, and puts the
//! researcher's configuration back the way it found it.
//!
//! The agent and its credential stay on the host throughout. What runs in the session is
//! `codex exec-server --listen stdio`, which authenticates to nothing — so the machine
//! executing untrusted code never holds a token, and never needs egress to be useful.

use std::{os::unix::process::ExitStatusExt as _, path::Path, process::ExitStatus};

use anyhow::{Context as _, Result};
use fishbowl_agents::Codex;
use tokio::{
    process::Command,
    signal::unix::{SignalKind, signal},
};

use crate::{
    cli,
    command::{self, banner},
    handoff::Handoff,
    host::Host,
    provision,
    session::SessionId,
};

/// How Codex is asked to run: never stopping to ask, never sandboxing what it runs.
///
/// The session is the sandbox. Codex's own approval prompts and seatbelt policy are built
/// for a laptop, and layering them over a machine whose every packet is already audited —
/// and whose disk is meant to be thrown away — only turns an autonomous agent back into a
/// manual one. The corollary is that these settings also describe how Codex would behave
/// if it ever ran a command on the host instead, which is why the environment is written
/// and preselected before Codex is started rather than alongside it.
const AUTONOMOUS: &[&str] = &[
    "--ask-for-approval",
    "never",
    "--sandbox",
    "danger-full-access",
];

/// Codex's hooks, switched off for the length of the run.
///
/// Hooks are the one part of Codex that runs on the host rather than in the session — its
/// own dialog says so — and the ones a stock install carries belong to plugins that drive
/// the host's browser. Codex keeps its trust in them per directory, and a session's
/// directory is minutes old, so it would stop the first prompt of every session to ask
/// about them. This answers the question the way the dialog's own third option does:
/// nothing runs on the host, and nothing about the researcher's trust is written down.
/// An override rather than a setting, so the researcher's configuration is not touched.
const NO_HOOKS: &[&str] = &["--config", "features.hooks=false"];

/// The configuration key Codex reads the researcher's standing instructions from, which
/// is where it is told about a key it has been given.
const INSTRUCTIONS: &str = "developer_instructions";

/// Opens Codex on an isolated research session.
///
/// # Errors
/// Fails when the session cannot be opened, when Codex's configuration cannot be edited,
/// or when Codex cannot be started. Codex's own exit status becomes fishbowl's, so a
/// failing run is reported as one.
pub async fn run(host: &Host, arguments: &cli::Codex) -> Result<()> {
    let session = provision::open(host, &arguments.attach).await?;
    let record = &session.record;
    let handoff = Handoff::from_host(host.layout());
    banner(host, &session, &handoff, "codex")?;

    let known_hosts = host.known_hosts_of(&record.id).await?;
    let endpoint = record.endpoint(session.address, known_hosts, handoff.sent());
    let agents = host.agents();
    let codex = agents.codex();

    let work_alias = host.work_alias_of(&record.id).await?;
    let instructions = match handoff.briefing() {
        Some(briefing) => Some(
            codex
                .config()
                .developer_instructions_with(&briefing)
                .await
                .context("reading codex's developer instructions")?,
        ),
        None => None,
    };

    codex
        .register(&endpoint)
        .await
        .with_context(|| format!("adding session {} to codex's configuration", record.id))?;
    let previous = preselect(codex, &record.id).await?;

    let status = supervise(&work_alias, instructions.as_deref()).await;

    // Before the run is reported, and whatever it did: an entry left behind is a dead
    // machine in the researcher's environment list, and a preselection left behind would
    // silently capture the next `codex` they start by hand.
    restore(codex, &record.id, previous.as_deref()).await?;
    command::epilogue(&session, "codex")?;

    match status? {
        status if status.success() => Ok(()),
        status => std::process::exit(exit_code(status)),
    }
}

/// Points Codex at `id`, answering with the preselection to put back afterwards.
///
/// A `default` that is itself a session id belongs to a run that was killed outright
/// rather than to the researcher, and restoring it would leave them attached to a machine
/// that is no longer there — so it is dropped rather than remembered.
async fn preselect(codex: &Codex, id: &SessionId) -> Result<Option<String>> {
    let previous = codex
        .selected()
        .await
        .context("reading codex's default environment")?
        .filter(|selected| selected.parse::<SessionId>().is_err());
    codex
        .select(Some(id.as_str()))
        .await
        .with_context(|| format!("preselecting session {id} in codex"))?;
    Ok(previous)
}

/// Leaves Codex's configuration as it was before the session opened.
async fn restore(codex: &Codex, id: &SessionId, previous: Option<&str>) -> Result<()> {
    codex
        .select(previous)
        .await
        .context("restoring codex's default environment")?;
    codex
        .unregister(id.as_str())
        .await
        .with_context(|| format!("removing session {id} from codex's configuration"))
}

/// Runs Codex to completion, outliving the signals that end it.
///
/// Codex resolves the directory it works in against the host and then asks the session to
/// execute there, so it is started in `work_alias` — an empty host directory the session
/// mirrors as a symlink to its own work directory. Left in the researcher's own working
/// directory instead, Codex would name a path the session does not have, and on being
/// refused would quietly run the command on the host.
///
/// Codex is a child rather than a replacement for this process, because the researcher's
/// own configuration has to be put back when it exits. That makes the terminal's
/// interrupt this process's problem too: it reaches the whole foreground process group,
/// so it is received and deliberately ignored here, leaving Codex to shut itself down
/// while the parent survives long enough to clean up after it.
async fn supervise(work_alias: &Path, instructions: Option<&str>) -> Result<ExitStatus> {
    let mut interrupt = signal(SignalKind::interrupt()).context("listening for an interrupt")?;
    let mut terminate = signal(SignalKind::terminate()).context("listening for a termination")?;
    let mut hangup = signal(SignalKind::hangup()).context("listening for a hangup")?;

    let mut codex = invocation(work_alias, instructions)
        .spawn()
        .context("starting codex on the host")?;

    loop {
        tokio::select! {
            status = codex.wait() => return status.context("waiting for codex to finish"),
            _ = interrupt.recv() => {}
            _ = terminate.recv() => {}
            _ = hangup.recv() => {}
        }
    }
}

/// How Codex is started for a session, with `instructions` — a TOML string literal — as
/// its developer instructions when there is something to tell it.
fn invocation(work_alias: &Path, instructions: Option<&str>) -> Command {
    let mut command = Command::new("codex");
    command
        .arg("--cd")
        .arg(work_alias)
        .args(AUTONOMOUS)
        .args(NO_HOOKS);
    if let Some(instructions) = instructions {
        command
            .arg("--config")
            .arg(format!("{INSTRUCTIONS}={instructions}"));
    }
    command
}

/// What a shell would report for `status`, so that a Codex killed by a signal is not
/// mistaken for one that merely returned nothing.
fn exit_code(status: ExitStatus) -> i32 {
    status
        .code()
        .or_else(|| status.signal().map(|signal| 128 + signal))
        .unwrap_or(1)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn codex_is_asked_to_stop_for_nothing() {
        assert!(
            AUTONOMOUS
                .windows(2)
                .any(|pair| pair == ["--ask-for-approval", "never"]),
            "an agent that stops to ask is one a researcher has to babysit, which is the \
             thing the session exists to avoid"
        );
    }

    #[test]
    fn codex_is_started_where_the_session_can_follow_it() {
        let command = invocation(Path::new("/home/researcher/.fishbowl/work/c0ffee"), None);
        let arguments: Vec<_> = command.as_std().get_args().collect();
        assert!(
            arguments
                .windows(2)
                .any(|pair| pair == ["--cd", "/home/researcher/.fishbowl/work/c0ffee"]),
            "codex resolves its working directory on the host, so one it is not given \
             explicitly is the researcher's own — a path the session does not have, which \
             codex answers by running the command on the host instead: {arguments:?}"
        );
    }

    #[test]
    fn a_briefing_becomes_codexs_developer_instructions_and_no_briefing_becomes_nothing() {
        let silent = invocation(Path::new("/work-alias"), None);
        assert!(
            !silent
                .as_std()
                .get_args()
                .any(|argument| argument.to_string_lossy().starts_with(INSTRUCTIONS))
        );
        let briefed = invocation(Path::new("/work-alias"), Some("\"the key is set\""));
        let arguments: Vec<_> = briefed
            .as_std()
            .get_args()
            .map(|argument| argument.to_string_lossy().into_owned())
            .collect();
        assert!(
            arguments
                .windows(2)
                .any(|pair| pair == ["--config", "developer_instructions=\"the key is set\""]),
            "{arguments:?}"
        );
    }

    #[test]
    fn nothing_codex_runs_on_the_host_is_left_to_a_dialog() {
        let command = invocation(Path::new("/home/researcher/.fishbowl/work/c0ffee"), None);
        let arguments: Vec<_> = command.as_std().get_args().collect();
        assert!(
            arguments
                .windows(2)
                .any(|pair| pair == ["--config", "features.hooks=false"]),
            "hooks run on the host, and a session's directory is one codex has never seen, \
             so left on it would stop every session's first prompt to ask about them: \
             {arguments:?}"
        );
    }

    #[test]
    fn a_signalled_run_is_reported_the_way_a_shell_would() {
        assert_eq!(exit_code(ExitStatus::from_raw(2 << 8)), 2);
        assert_eq!(exit_code(ExitStatus::from_raw(9)), 137);
    }
}
