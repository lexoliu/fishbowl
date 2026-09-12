//! Running Claude Code inside a session.
//!
//! Claude Code has no split between a model side and a tool side: it is one program, and
//! it runs where the work is. So unlike Codex it runs *inside* the session, and needs a
//! credential there — which is the whole difficulty, since the machine it runs on is the
//! one executing untrusted code.
//!
//! What crosses is an access token and nothing more. It is fetched over a unix socket the
//! host owns and ssh publishes inside the session, by a courier that writes it where
//! Claude Code reads a host-managed credential from, starts Claude Code, fetches a fresh
//! one before the old one runs out, and takes the file away again when Claude Code exits.
//! The refresh token that could mint further tokens never leaves the host's keychain: a
//! session gets the few hours the token it was lent has left, and nothing beyond them.
//!
//! Running inside the session is also why this is the one agent that gets the researcher's
//! subscription rather than an API key — usage, connectors and all — and why it can be run
//! with every permission prompt off. The session is the sandbox.

use anyhow::{Context as _, Result};
use fishbowl_agents::ClaudeLogin;

use crate::{
    cli,
    command::{self, Briefing, Errand},
    handoff::Handoff,
    host::Host,
    loan::{Attachment, Lender, Loan},
    provision,
};

/// How Claude Code is asked to run: never stopping to ask.
///
/// The session is the sandbox. Claude Code's permission prompts are built for a laptop
/// holding the researcher's own files, and a machine whose disk is meant to be thrown
/// away and whose every packet is already audited has nothing left for them to protect —
/// only an autonomous agent to turn back into a manual one.
const AUTONOMOUS: &str = "--dangerously-skip-permissions";

/// Claude Code's own way of being told something on top of its system prompt.
const BRIEF: &str = "--append-system-prompt";

/// Opens Claude Code on an isolated research session.
///
/// # Errors
/// Fails when the researcher has no Claude Code login to lend from, when the session
/// cannot be opened, or when `ssh` cannot be started. Claude Code's own exit status
/// becomes fishbowl's, so a failing run is reported as one.
pub async fn run(host: &Host, arguments: &cli::Claude) -> Result<()> {
    // Read before anything is built or started, because the socket it will be lent over
    // can only be named once the session has one: a researcher who is not logged in is
    // told so now rather than by a machine that has already spent a minute booting.
    let login = ClaudeLogin::discover();
    login.bearer().await.with_context(|| {
        format!(
            "reading the Claude Code login stored under `{}`; running `claude` once on the \
             host is what puts it there",
            login.service()
        )
    })?;

    let session = provision::open(host, &arguments.attach).await?;
    let record = &session.record;
    let handoff = Handoff::from_host(host.layout());
    command::banner(host, &session, &handoff, "claude")?;

    let attachment = Attachment::random(record.id.clone())?;
    let loan = Loan::open(Lender::Claude(login), host.loan_socket(&attachment)).await?;

    let known_hosts = host.known_hosts_of(&record.id).await?;
    let endpoint = record.endpoint(session.address, known_hosts, handoff.sent());
    let runtime_dir = &host.layout().runtime_dir;
    let errand = Errand {
        agent: "claude",
        socket: runtime_dir.join(attachment.socket_name()),
        credentials: runtime_dir.join(attachment.credentials_name()),
        directory: record.work_dir.clone(),
        resumed: arguments.attach.resume.is_some(),
        briefing: handoff.briefing(),
        channel: Briefing::Flag(BRIEF),
        autonomous: &[AUTONOMOUS],
    };

    let status = command::supervise(&endpoint, &errand, loan.socket()).await;

    // Whatever the run did: the socket is the researcher's login, and one left on disk is
    // one a later process on this host could still fetch a token from.
    loan.close().await?;
    command::epilogue(&session, "claude")?;

    match status? {
        status if status.success() => Ok(()),
        status => std::process::exit(command::exit_code(status)),
    }
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use super::*;

    fn errand(resumed: bool) -> Errand {
        Errand {
            agent: "claude",
            socket: PathBuf::from("/run/fishbowl/c0ffee-1a2b3c4d.sock"),
            credentials: PathBuf::from("/run/fishbowl/c0ffee-1a2b3c4d.json"),
            directory: PathBuf::from("/work"),
            resumed,
            briefing: None,
            channel: Briefing::Flag(BRIEF),
            autonomous: &[AUTONOMOUS],
        }
    }

    #[test]
    fn the_session_runs_the_courier_and_not_the_agent_directly() {
        let remote = errand(false).remote_command();
        assert!(
            remote.starts_with(&format!("exec {} --agent claude ", command::COURIER)),
            "sshd waits on the process it started, so the courier has to be that process \
             for the credential to be taken away when the connection drops: {remote}"
        );
        assert!(remote.contains(AUTONOMOUS));
    }

    #[test]
    fn the_credentials_are_written_where_the_socket_is_read_from() {
        let remote = errand(false).remote_command();
        assert!(
            remote.contains("--credentials '/run/fishbowl/c0ffee-1a2b3c4d.json'"),
            "the credentials file lives beside the socket it was fetched over, and is \
             named for this opening so two of them never share one: {remote}"
        );
    }

    #[test]
    fn only_a_reopened_session_is_asked_to_carry_a_conversation_on() {
        assert!(
            !errand(false)
                .remote_command()
                .contains("--continue-conversation"),
            "a machine that was created a moment ago was not come back to"
        );
        let remote = errand(true).remote_command();
        assert!(remote.contains("--continue-conversation"));
        assert!(
            remote.find("--continue-conversation") < remote.find(" -- "),
            "the courier is the one that decides, so this is its flag and not one passed \
             through to claude: {remote}"
        );
    }

    #[test]
    fn a_key_the_agent_was_given_is_explained_to_it_and_one_it_was_not_is_not_mentioned() {
        assert!(!errand(false).remote_command().contains(BRIEF));
        let mut briefed = errand(false);
        briefed.briefing = Some("MALWAREBAZAAR_API_KEY holds the researcher's key.".to_owned());
        let remote = briefed.remote_command();
        assert!(
            remote.ends_with(
                "-- --dangerously-skip-permissions --append-system-prompt \
                 'MALWAREBAZAAR_API_KEY holds the researcher'\\''s key.'"
            ),
            "the briefing is claude's argument, quoted for the shell that reads the \
             remote command: {remote}"
        );
    }
}
