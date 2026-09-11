use anyhow::{Context as _, Result};

use crate::{
    cli,
    command::{self, banner, shell_quote},
    handoff::Handoff,
    host::Host,
    provision,
};

/// Opens a shell, or runs a command, inside an isolated research session.
///
/// `ssh` is a child rather than a replacement for this process — and cannot be a
/// replacement: a process that execs keeps the identity the network stack knew it by,
/// and a packet-tunnel network extension (a VPN deciding flows per application) goes on
/// claiming this one's, sending the session's traffic into a tunnel that cannot reach
/// it. A spawned child is seen as itself, so its flow follows the route the address
/// says.
///
/// The session's lease never leaves this process: the client shares its terminal and
/// foreground process group, so the terminal's signals still reach it directly, while
/// this process surviving — or dying, which closes the lease all the same — is what the
/// release of the machine is hung on. The client's exit status becomes cyber-sandbox's
/// own.
///
/// # Errors
/// Fails when the session cannot be opened, or when `ssh` cannot be started at all.
pub async fn run(host: &Host, arguments: &cli::Shell) -> Result<()> {
    let session = provision::open(host, &arguments.attach).await?;
    let record = &session.record;
    let handoff = Handoff::from_host(host.layout());
    banner(host, &session, &handoff, "shell")?;

    let known_hosts = host.known_hosts_of(&record.id).await?;
    let endpoint = record.endpoint(session.address, known_hosts, handoff.sent());

    let mut client = std::process::Command::new("ssh");
    if arguments.command.is_empty() {
        // A shell without a terminal is one without job control, line editing or a
        // prompt — the endpoint's arguments end with the destination, so this goes in
        // front of them. A command given means the caller wants pipes, not a pty.
        client.arg("-t");
    }
    client.args(endpoint.ssh_arguments());
    client.arg(remote_command(
        &record.work_dir.display().to_string(),
        &arguments.command,
    ));

    let status = client.status().context("running the session's client")?;
    command::epilogue(&session, "shell")?;
    match status {
        status if status.success() => Ok(()),
        status => std::process::exit(command::exit_code(status)),
    }
}

/// What the session is asked to run, starting in the session's work directory.
///
/// The `cd` is part of the remote command because sshd starts every session in the
/// account's home, and a command runs where an interactive shell would land rather than
/// somewhere the researcher was never shown.
fn remote_command(work_dir: &str, command: &[String]) -> String {
    let run = if command.is_empty() {
        // A login shell is what a researcher wants when they asked for nothing else.
        "exec $SHELL -l".to_owned()
    } else {
        // `ssh` joins a multi-word command with spaces before sending it, so the parts
        // arrive as one line either way; joining here only makes that explicit.
        command.join(" ")
    };
    format!("cd {} && {run}", shell_quote(work_dir))
}

#[cfg(test)]
mod tests {
    use super::remote_command;

    #[test]
    fn a_session_starts_where_the_samples_are_mounted() {
        assert_eq!(remote_command("/work", &[]), "cd '/work' && exec $SHELL -l");
    }

    #[test]
    fn a_command_runs_where_a_shell_would_have_landed() {
        let command = ["file".to_owned(), "sample.bin".to_owned()];
        assert_eq!(
            remote_command("/work", &command),
            "cd '/work' && file sample.bin",
            "a command that lands in the home directory cannot see the samples the \
             session was started for"
        );
    }
}
