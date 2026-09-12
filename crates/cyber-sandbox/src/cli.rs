use std::path::PathBuf;

use clap::{Args, Parser, Subcommand};
use cyber_sandbox_runtime::Arch;

use crate::session::SessionId;

/// Repository the sandbox image is published under and pulled from.
pub const IMAGE_REPOSITORY: &str = "ghcr.io/lexoliu/cyber-sandbox";

/// Repository images were built under before the registry existed.
///
/// Sessions created then still name it, so reclamation keeps recognising them.
pub const LEGACY_IMAGE_REPOSITORY: &str = "localhost/cyber-sandbox";

/// Resolver the in-sandbox gateway forwards DNS to.
///
/// The gateway dials it directly, so it is the one destination the sandbox reaches
/// without being redirected — the sandbox itself still cannot speak to it.
pub const DEFAULT_RESOLVER: &str = "1.1.1.1";

/// cyber-sandbox's command line.
///
/// There is nothing here for starting, stopping, listing or deleting a machine. A session
/// is what a researcher asks for, and the virtual machine underneath it is this tool's
/// business: it is created when a session begins, resumed when one is reopened, and
/// reclaimed when it has gone stale or the host is short of room.
#[derive(Debug, Parser)]
#[command(name = "cyber-sandbox", version, about, long_about = None)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Command,
}

/// The top-level commands.
#[derive(Debug, Subcommand)]
pub enum Command {
    /// Opens Claude Code on an isolated research session.
    Claude(Claude),
    /// Opens Codex on an isolated research session.
    Codex(Codex),
    /// Opens Devin on an isolated research session.
    Devin(Devin),
    /// Opens a shell in an isolated research session.
    Shell(Shell),
    /// Follows a session's network audit trail.
    Audit(Audit),
}

/// Which session to work in, and how a new one is furnished.
///
/// Shared by every command that puts a researcher inside a machine, so that opening one
/// with a shell and opening one with an agent cannot drift apart.
#[derive(Debug, Args)]
pub struct Attach {
    /// Reopen a session instead of starting a new one. Without a value, pick one.
    ///
    /// A bare `--resume` offers the sessions this host holds and reopens the chosen one.
    /// There is deliberately no "most recent" shorthand: which environment untrusted code
    /// runs in is never guessed.
    #[arg(long, num_args = 0..=1, default_missing_value = "", value_name = "SESSION")]
    pub resume: Option<Resume>,
    /// Host directory exposed read-only inside the session as the sample source.
    #[arg(long)]
    pub samples: Option<PathBuf>,
    /// Guest architecture. `amd64` runs an `x86_64` root filesystem under Rosetta.
    ///
    /// Settled when the session is created, so it is only accepted on a resume when it
    /// agrees with what the session already is.
    #[arg(long)]
    pub arch: Option<Arch>,
    /// Checkout the image is compiled from, forcing a local build.
    ///
    /// Without it, an invocation from inside a checkout still builds from it — the
    /// sources on disk are what the guest programs must agree with — and any other
    /// directory pulls the image this version was published as.
    #[arg(long)]
    pub workspace: Option<PathBuf>,
}

/// Arguments of `claude`.
///
/// Claude Code runs inside the session, unlike Codex, because that is where the files it
/// is being asked about are. What stays on the host is the login: the session is lent a
/// token that expires in hours, over a socket, for exactly as long as the agent runs.
#[derive(Debug, Args)]
pub struct Claude {
    #[command(flatten)]
    pub attach: Attach,
}

/// Arguments of `codex`.
///
/// Codex itself stays on the host, where its credential already is; only its exec-server
/// runs in the session. There is nothing to configure beyond which session that is.
#[derive(Debug, Args)]
pub struct Codex {
    #[command(flatten)]
    pub attach: Attach,
}

/// Arguments of `devin`.
///
/// Devin runs inside the session for the same reason Claude Code does: it is one program
/// with no tool side to leave on the host. What it is lent is its credentials file, whole
/// — Devin keeps no refresh token beside it to hold back, and the file is taken off the
/// disk again when the agent exits.
#[derive(Debug, Args)]
pub struct Devin {
    #[command(flatten)]
    pub attach: Attach,
}

/// Arguments of `shell`.
#[derive(Debug, Args)]
pub struct Shell {
    #[command(flatten)]
    pub attach: Attach,
    /// Command to run instead of an interactive shell.
    #[arg(trailing_var_arg = true)]
    pub command: Vec<String>,
}

/// Arguments of `audit`.
#[derive(Debug, Args)]
pub struct Audit {
    /// Session whose trail to follow.
    ///
    /// Named rather than picked: a trail read from the wrong machine is evidence about
    /// something the researcher was not looking at.
    pub session: SessionId,
    /// Number of trailing records to print before catching up with the gateway.
    #[arg(long, short = 'n', default_value = "20")]
    pub lines: u32,
    /// Print the gateway's own JSONL rather than one rendered line per event.
    ///
    /// An exported trail is evidence, so this is byte-for-byte what the gateway recorded.
    #[arg(long)]
    pub raw: bool,
}

/// Which existing session `--resume` asks for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Resume {
    /// `--resume` with no value: offer the host's sessions and reopen the chosen one.
    Pick,
    /// `--resume <session>`: reopen that one.
    Named(SessionId),
}

impl std::str::FromStr for Resume {
    type Err = crate::session::NotASession;

    /// Parses the flag's value, where the empty string is clap's way of saying the flag
    /// was given without one.
    fn from_str(value: &str) -> Result<Self, Self::Err> {
        if value.is_empty() {
            Ok(Self::Pick)
        } else {
            value.parse().map(Self::Named)
        }
    }
}

#[cfg(test)]
mod tests {
    use clap::CommandFactory as _;

    use super::*;

    #[test]
    fn the_command_line_is_one_clap_can_build() {
        Cli::command().debug_assert();
    }

    fn resume_of(arguments: &[&str]) -> Option<Resume> {
        let Command::Shell(shell) = Cli::try_parse_from(arguments).unwrap().command else {
            panic!("`shell` parses as `shell`");
        };
        shell.attach.resume
    }

    #[test]
    fn no_resume_flag_asks_for_a_new_session() {
        assert_eq!(resume_of(&["cyber-sandbox", "shell"]), None);
    }

    #[test]
    fn a_bare_resume_flag_asks_to_be_offered_a_choice() {
        assert_eq!(
            resume_of(&["cyber-sandbox", "shell", "--resume"]),
            Some(Resume::Pick),
            "there is no most-recent shorthand: which environment untrusted code runs in \
             is never guessed"
        );
    }

    #[test]
    fn a_named_resume_flag_asks_for_that_session() {
        assert_eq!(
            resume_of(&["cyber-sandbox", "shell", "--resume", "c0ffee"]),
            Some(Resume::Named("c0ffee".parse().unwrap()))
        );
    }

    #[test]
    fn a_session_that_was_never_issued_is_refused_before_anything_is_started() {
        assert!(
            Cli::try_parse_from(["cyber-sandbox", "audit", "../../etc/passwd"]).is_err(),
            "the identifier becomes a container name and a file name"
        );
    }
}
