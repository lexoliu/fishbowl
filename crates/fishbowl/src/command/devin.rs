//! Running Devin inside a session.
//!
//! Devin, like Claude Code, is one program with no split between a model side and a tool
//! side, so it runs *inside* the session where the files it is asked about are. What it
//! is lent is different: Devin's login is a credentials file rather than a keychain
//! entry, and it has no short-lived token to lend instead — so the file itself crosses,
//! over the same socket, written by the courier where Devin reads it and taken back when
//! Devin exits. The session key it carries does not expire on its own the way an OAuth
//! token does; the loan's bound is the run, not a clock.
//!
//! The socket is the part that stays host-side: it is published into the session by ssh
//! for exactly one opening, answers one credential per connection, and stops existing
//! when the run does — so a key that outlives the run cannot be fetched once the run is
//! over.

use anyhow::{Context as _, Result};

use crate::{
    cli,
    command::{self, Briefing, Errand},
    handoff::Handoff,
    host::Host,
    loan::{Attachment, Lender, Loan},
    provision,
};

/// How Devin is asked to run: never stopping to ask.
///
/// The session is the sandbox. Devin's permission prompts are built for a laptop holding
/// the researcher's own files, and a machine whose disk is meant to be thrown away and
/// whose every packet is already audited has nothing left for them to protect — only an
/// autonomous agent to turn back into a manual one.
const AUTONOMOUS: &[&str] = &["--permission-mode", "dangerous"];

/// Opens Devin on an isolated research session.
///
/// # Errors
/// Fails when the researcher has no Devin login to lend from, when the session cannot be
/// opened, or when `ssh` cannot be started. Devin's own exit status becomes
/// fishbowl's, so a failing run is reported as one.
pub async fn run(host: &Host, arguments: &cli::Devin) -> Result<()> {
    // Read before anything is built or started, because the socket it will be lent over
    // can only be named once the session has one: a researcher who is not logged in is
    // told so now rather than by a machine that has already spent a minute booting.
    let login = host.agents().devin().clone();
    login.document().await.with_context(|| {
        format!(
            "reading the Devin login stored at {}; running `devin auth login` once on the \
             host is what puts it there",
            login.path().display()
        )
    })?;

    let session = provision::open(host, &arguments.attach).await?;
    let record = &session.record;
    let handoff = Handoff::from_host(host.layout());
    command::banner(host, &session, &handoff, "devin")?;

    let attachment = Attachment::random(record.id.clone())?;
    let loan = Loan::open(Lender::Devin(login), host.loan_socket(&attachment)).await?;

    let known_hosts = host.known_hosts_of(&record.id).await?;
    let endpoint = record.endpoint(session.address, known_hosts, handoff.sent());
    let runtime_dir = &host.layout().runtime_dir;
    let errand = Errand {
        agent: "devin",
        socket: runtime_dir.join(attachment.socket_name()),
        credentials: host.layout().devin_credentials(),
        directory: record.work_dir.clone(),
        resumed: arguments.attach.resume.is_some(),
        briefing: handoff.briefing(),
        channel: Briefing::Rule,
        autonomous: AUTONOMOUS,
    };

    let status = command::supervise(&endpoint, &errand, loan.socket()).await;

    // Whatever the run did: the socket is the researcher's login, and one left on disk is
    // one a later process on this host could still fetch a credential from.
    loan.close().await?;
    command::epilogue(&session, "devin")?;

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
            agent: "devin",
            socket: PathBuf::from("/run/fishbowl/c0ffee-1a2b3c4d.sock"),
            credentials: PathBuf::from("/home/researcher/.local/share/devin/credentials.toml"),
            directory: PathBuf::from("/work"),
            resumed,
            briefing: None,
            channel: Briefing::Rule,
            autonomous: AUTONOMOUS,
        }
    }

    #[test]
    fn the_session_runs_the_courier_and_not_the_agent_directly() {
        let remote = errand(false).remote_command();
        assert!(
            remote.starts_with(&format!("exec {} --agent devin ", command::COURIER)),
            "sshd waits on the process it started, so the courier has to be that process \
             for the credential to be taken away when the connection drops: {remote}"
        );
        assert!(
            remote.ends_with("-- --permission-mode dangerous"),
            "devin is asked to run without its prompts: {remote}"
        );
    }

    #[test]
    fn the_credentials_are_written_where_devin_reads_them() {
        let remote = errand(false).remote_command();
        assert!(
            remote.contains("--credentials '/home/researcher/.local/share/devin/credentials.toml'"),
            "the file is lent where Devin already looks rather than where it could be \
             pointed: {remote}"
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
             through to devin: {remote}"
        );
    }

    #[test]
    fn a_key_the_agent_was_given_is_explained_to_it_and_one_it_was_not_is_not_mentioned() {
        assert!(!errand(false).remote_command().contains("--briefing"));
        let mut briefed = errand(false);
        briefed.briefing = Some("MALWAREBAZAAR_API_KEY holds the researcher's key.".to_owned());
        let remote = briefed.remote_command();
        assert!(
            remote.contains("--briefing 'MALWAREBAZAAR_API_KEY holds the researcher'\\''s key.'"),
            "devin has no system-prompt flag, so the briefing is the courier's argument, \
             quoted for the shell that reads the remote command: {remote}"
        );
        assert!(
            remote.find("--briefing") < remote.find(" -- "),
            "the courier writes it where devin reads its rules, so it is the courier's \
             flag and not one passed through to devin: {remote}"
        );
    }
}
