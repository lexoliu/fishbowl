//! The auditing egress gateway that runs inside a fishbowl research VM.
//!
//! Every packet the sandbox sends is either terminated here and written to the audit trail
//! or refused by the packet filter and written to the audit trail as a refusal. The gateway
//! is the only account the filter lets reach the network directly, so it going away leaves
//! the sandbox with no egress at all — the failure mode is silence, never an unaudited byte.

mod audit;
mod ca;
mod dns;
mod error;
mod http;
mod nflog;
mod peer;
mod redirect;
mod stream;
mod tcp;
mod tls;

use std::{
    net::{IpAddr, Ipv4Addr, SocketAddr},
    path::PathBuf,
    sync::Arc,
};

use anyhow::Context as _;
use clap::{Parser, Subcommand};
use tokio::net::{TcpListener, UdpSocket};
use tracing_subscriber::EnvFilter;

use crate::{ca::CertificateAuthority, tls::TlsBridge};

/// Command line of the in-sandbox audit gateway.
#[derive(Debug, Parser)]
#[command(version, about)]
struct Arguments {
    #[command(subcommand)]
    command: Command,
}

/// What the invocation is for.
///
/// Creating the authority is its own command so the entrypoint can install it in the
/// sandbox's trust store before any traffic flows, rather than racing a gateway that
/// writes the file while it starts up.
#[derive(Debug, Subcommand)]
enum Command {
    /// Generates the interception authority if it is not already on disk, then exits.
    InitCa(InitCa),
    /// Runs the gateway until it is stopped.
    Serve(Serve),
}

/// Arguments of `init-ca`.
#[derive(Debug, Parser)]
struct InitCa {
    /// Certificate authority the gateway signs intercepted sessions with.
    #[arg(long)]
    ca_certificate: PathBuf,
}

/// Arguments of `serve`.
#[derive(Debug, Parser)]
struct Serve {
    /// Name of the sandbox, recorded on every audit record.
    #[arg(long)]
    sandbox: String,
    /// JSONL audit trail the gateway appends to.
    #[arg(long)]
    audit_trail: PathBuf,
    /// Certificate authority the gateway signs intercepted sessions with.
    #[arg(long)]
    ca_certificate: PathBuf,
    /// Port redirected TCP connections arrive on.
    #[arg(long)]
    proxy_port: u16,
    /// Port redirected DNS queries arrive on.
    #[arg(long)]
    dns_port: u16,
    /// NFLOG group the packet filter reports refused packets on.
    #[arg(long)]
    nflog_group: u16,
    /// Resolver the gateway forwards DNS queries to.
    #[arg(long)]
    upstream_resolver: IpAddr,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();

    rustls::crypto::ring::default_provider()
        .install_default()
        .map_err(|_| anyhow::anyhow!("the rustls cryptography provider was already installed"))?;

    match Arguments::parse().command {
        Command::InitCa(arguments) => init_ca(arguments).await,
        Command::Serve(arguments) => serve(arguments).await,
    }
}

async fn init_ca(arguments: InitCa) -> anyhow::Result<()> {
    CertificateAuthority::load_or_create(&arguments.ca_certificate)
        .await
        .context("preparing the interception certificate authority")?;
    tracing::info!(
        certificate = %arguments.ca_certificate.display(),
        "the interception certificate authority is ready"
    );
    Ok(())
}

async fn serve(arguments: Serve) -> anyhow::Result<()> {
    let (sink, writer) = audit::spawn(&arguments.sandbox, &arguments.audit_trail)
        .await
        .context("opening the audit trail")?;
    let authority = Arc::new(
        CertificateAuthority::load_or_create(&arguments.ca_certificate)
            .await
            .context("preparing the interception certificate authority")?,
    );
    let bridge = Arc::new(TlsBridge::new(authority));

    // Both sockets bind the loopback address rather than a wildcard, because that is the
    // address the packet filter's redirection rewrites the sandbox's traffic to. It also
    // has to be the address replies leave from: a wildcard-bound socket would answer a
    // redirected DNS query from the sandbox's own interface address, conntrack would not
    // recognise that as the reply to what it redirected, and the resolver's answer would
    // never be translated back to the address the client asked. Binding the loopback
    // address makes the reply's source correct by construction, and keeps the gateway
    // unreachable from anywhere but inside this sandbox.
    let proxy = TcpListener::bind((Ipv4Addr::LOCALHOST, arguments.proxy_port))
        .await
        .context("binding the transparent proxy port")?;
    let resolver = UdpSocket::bind((Ipv4Addr::LOCALHOST, arguments.dns_port))
        .await
        .context("binding the intercepting resolver port")?;
    let upstream = SocketAddr::new(arguments.upstream_resolver, 53);

    tracing::info!(
        sandbox = arguments.sandbox,
        proxy_port = arguments.proxy_port,
        dns_port = arguments.dns_port,
        "the audit gateway is ready"
    );

    let result = tokio::try_join!(
        tcp::serve(proxy, bridge, sink.clone()),
        dns::serve(resolver, upstream, sink.clone()),
        nflog::watch(arguments.nflog_group, sink),
    );
    drop(writer);
    result.context("the audit gateway stopped")?;
    Ok(())
}
