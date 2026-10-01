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
mod hello;
mod http;
mod nflog;
mod peer;
mod redirect;
mod stream;
mod tcp;
mod tls;
mod udp;

use std::{
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddrV4},
    path::PathBuf,
    sync::Arc,
};

use anyhow::Context as _;
use clap::{Parser, Subcommand};
use fishbowl_audit::{AuditEvent, Route, Tier};
use fishbowl_egress::{Egress, Leg, Mode, Routes};
use tokio::net::{TcpListener, UdpSocket};
use tracing_subscriber::EnvFilter;

use crate::{ca::CertificateAuthority, tcp::Inspection, tls::TlsBridge};

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
    /// Port the `torsion` uid's redirected TCP connections arrive on — the dedicated
    /// listener whose every connection rides Tor or is refused.
    #[arg(long)]
    torsion_port: u16,
    /// Uid of the `torsion` account: the packet filter sends its TCP to the dedicated
    /// listener, and the resolver reads the uid to send its DNS over Tor.
    #[arg(long)]
    torsion_uid: u32,
    /// Port redirected DNS queries arrive on.
    #[arg(long)]
    dns_port: u16,
    /// Port redirected datagrams that are not DNS arrive on — the UDP relay.
    #[arg(long)]
    udp_port: u16,
    /// NFLOG group the packet filter reports refused packets on.
    #[arg(long)]
    nflog_group: u16,
    /// Resolver the gateway forwards DNS queries to.
    #[arg(long)]
    upstream_resolver: IpAddr,
    /// Which network upstream traffic rides on.
    ///
    /// `auto` tunnels through Cloudflare WARP when the tunnel can be raised and falls
    /// back to direct egress when it cannot; `warp` and `tor` refuse connections while
    /// their transport is down rather than emit them under the machine's own address;
    /// `redteam` rides WARP as the floor and raises a parallel Tor leg for the
    /// `torsion` uid — a command deliberately wrapped for it is Tor or a refusal.
    ///
    /// Parsed by name rather than as a value enum: `redteam` is a mode the host's
    /// `--egress` does not offer — only a session created as red team names it here.
    #[arg(long, value_parser = parse_mode, default_value_t = Mode::Auto)]
    egress: Mode,
    /// Directory the egress transports keep what must survive a restart in: the WARP
    /// device registration and Tor's cache.
    #[arg(long)]
    egress_state: PathBuf,
    /// How much of the sandbox's traffic to inspect before relaying it.
    ///
    /// `strict` terminates TLS and lets the packet filter drop whatever cannot be
    /// audited in cleartext; `default` audits without standing in the way — client
    /// hellos are read for their SNI and relayed untouched, and traffic no route can
    /// carry is refused rather than dropped; `off` relays everything and records
    /// nothing but this gateway's own route reports.
    ///
    /// The default is the heaviest tier on purpose: reductions in what the trail can
    /// say are requested explicitly, by the session that wants them.
    #[arg(long, value_enum, default_value_t = Tier::Strict)]
    audit: Tier,
}

/// Parses `--egress`, accepting every mode the host's record can name — including
/// `redteam`, which the host's own flag never hands out.
fn parse_mode(value: &str) -> Result<Mode, fishbowl_egress::NotAMode> {
    value.parse()
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
    let (sink, writer) = audit::spawn(&arguments.sandbox, &arguments.audit_trail, arguments.audit)
        .await
        .context("opening the audit trail")?;
    // The interception authority is only loaded by the tier that terminates TLS — under
    // `default` and `off` no leaf is ever minted, and the entrypoint never installed
    // the CA into the trust store.
    let inspection = match arguments.audit {
        Tier::Strict => Inspection::Terminate(Arc::new(TlsBridge::new(Arc::new(
            CertificateAuthority::load_or_create(&arguments.ca_certificate)
                .await
                .context("preparing the interception certificate authority")?,
        )))),
        Tier::Default => Inspection::Observe,
        Tier::Off => Inspection::Pass,
    };

    let [proxy, proxy6] = bind_tcp(arguments.proxy_port)
        .await
        .context("binding the transparent proxy port")?;
    let [torsion, torsion6] = bind_tcp(arguments.torsion_port)
        .await
        .context("binding the torsion proxy port")?;
    let resolver = vec![
        UdpSocket::bind((Ipv4Addr::LOCALHOST, arguments.dns_port))
            .await
            .context("binding the intercepting resolver port")?,
        UdpSocket::bind((Ipv6Addr::LOCALHOST, arguments.dns_port))
            .await
            .context("binding the IPv6 resolver port")?,
    ];
    // A v6 resolver could never be dialled — the gateway's bootstrap traffic is v4 —
    // so one is refused here rather than discovered failing at runtime.
    let IpAddr::V4(resolver_address) = arguments.upstream_resolver else {
        anyhow::bail!("--upstream-resolver must be an IPv4 address");
    };
    let upstream = SocketAddrV4::new(resolver_address, 53);

    // The egress layer starts before either listener serves traffic: under a strict
    // mode, connections that arrive while the transport is still being raised wait
    // for the verdict rather than leaking out directly.
    let egress = Arc::new(Egress::start(
        arguments.egress,
        &arguments.egress_state,
        upstream,
    ));

    // Which network audited traffic actually leaves over is itself part of the trail:
    // a record's meaning depends on the route it went out on. A mode that raises a
    // second leg reports it under its own name, so the base route's records — the
    // ones the host's proof reads — are never a leg's observation.
    tokio::spawn(report_routes(egress.routes(), sink.clone(), None));
    if let Some(torsion) = egress.torsion_routes() {
        tokio::spawn(report_routes(torsion, sink.clone(), Some("torsion")));
    }

    tracing::info!(
        sandbox = arguments.sandbox,
        proxy_port = arguments.proxy_port,
        dns_port = arguments.dns_port,
        egress = %arguments.egress,
        audit = %arguments.audit,
        "the audit gateway is ready"
    );

    let result = tokio::try_join!(
        tcp::serve(
            proxy,
            inspection.clone(),
            Arc::clone(&egress),
            sink.clone(),
            Leg::Base
        ),
        tcp::serve(
            proxy6,
            inspection.clone(),
            Arc::clone(&egress),
            sink.clone(),
            Leg::Base
        ),
        tcp::serve(
            torsion,
            inspection.clone(),
            Arc::clone(&egress),
            sink.clone(),
            Leg::Torsion
        ),
        tcp::serve(
            torsion6,
            inspection,
            Arc::clone(&egress),
            sink.clone(),
            Leg::Torsion
        ),
        dns::serve(
            resolver,
            upstream,
            Arc::clone(&egress),
            sink.clone(),
            arguments.torsion_uid
        ),
        udp::serve(
            arguments.udp_port,
            egress,
            sink.clone(),
            arguments.torsion_uid
        ),
        nflog::watch(arguments.nflog_group, sink),
    );
    drop(writer);
    result.context("the audit gateway stopped")?;
    Ok(())
}

/// Binds one TCP listener per address family on `port`.
///
/// Every socket binds the loopback address rather than a wildcard, because that is
/// the address the packet filter's redirection rewrites the sandbox's traffic to —
/// `127.0.0.1` for IPv4, `::1` for IPv6. It also has to be the address replies
/// leave from: a wildcard-bound socket would answer a redirected packet from the
/// sandbox's own interface address, conntrack would not recognise that as the
/// reply to what it redirected, and the answer would never be translated back to
/// the address the client asked. Binding the loopback address makes the reply's
/// source correct by construction, and keeps the gateway unreachable from anywhere
/// but inside this sandbox.
async fn bind_tcp(port: u16) -> anyhow::Result<[TcpListener; 2]> {
    Ok([
        TcpListener::bind((Ipv4Addr::LOCALHOST, port)).await?,
        TcpListener::bind((Ipv6Addr::LOCALHOST, port)).await?,
    ])
}

/// Appends an egress record to the trail each time the route upstream traffic rides
/// on changes. `leg` names which supervised route is being reported — `None` is the
/// base route every connection falls to, and `Some` is a dedicated uid's parallel
/// leg.
async fn report_routes(mut routes: Routes, sink: audit::AuditSink, leg: Option<&'static str>) {
    loop {
        let (route, reason) = routes.current();
        sink.record(AuditEvent::Egress(fishbowl_audit::Egress {
            route: match route {
                fishbowl_egress::Route::Warp => Route::Warp,
                fishbowl_egress::Route::Tor => Route::Tor,
                fishbowl_egress::Route::Direct => Route::Direct,
                fishbowl_egress::Route::Down => Route::Down,
            },
            reason: reason.as_deref().map(ToOwned::to_owned),
            leg: leg.map(ToOwned::to_owned),
        }))
        .await;
        if routes.changed().await.is_none() {
            return;
        }
    }
}
