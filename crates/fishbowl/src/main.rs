//! fishbowl: isolated, fully audited security-research environments on macOS.
//!
//! One command opens a session; everything underneath it — the runtime's services, the
//! image, the virtual machine, its identity and its eventual reclamation — is this tool's
//! business rather than the researcher's. Every packet a session sends is either audited
//! by the in-guest gateway or refused by the packet filter.

mod cli;
mod command;
mod handoff;
mod host;
mod image;
mod keys;
mod lease;
mod loan;
mod pick;
mod provision;
mod reclaim;
mod session;

use anyhow::Result;
use clap::Parser as _;
use tracing_subscriber::EnvFilter;

use crate::{cli::Cli, host::Host};

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_env("FISHBOWL_LOG").unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .with_target(false)
        .with_writer(std::io::stderr)
        .init();

    let arguments = Cli::parse();
    let host = Host::discover()?;

    match &arguments.command {
        cli::Command::Claude(claude) => command::claude::run(&host, claude).await,
        cli::Command::Codex(codex) => command::codex::run(&host, codex).await,
        cli::Command::Devin(devin) => command::devin::run(&host, devin).await,
        cli::Command::Shell(shell) => command::shell::run(&host, shell).await,
        cli::Command::Audit(audit) => command::audit::follow(&host, audit).await,
        cli::Command::Reap(reap) => lease::reap(&host, &reap.session).await,
    }
}
