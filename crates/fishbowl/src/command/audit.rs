use std::io::Write as _;

use anyhow::{Context as _, Result};
use fishbowl_audit::{AuditEvent, AuditRecord, BlockReason, Endpoint, Transport};

use crate::{cli, host::Host};

/// Follows a session's network audit trail.
///
/// It always follows. A trail that stopped at the moment the command was typed says
/// nothing about the sample that is running right now, and having to remember a flag to
/// see the packets a detonation sends is a way to miss them.
///
/// The trail is read through the runtime rather than a host mount: it is written inside
/// the guest by the gateway account and by nothing else, so reading it as that account
/// keeps the file out of reach of everything that runs sample code.
///
/// # Errors
/// Fails when no such session exists, when its machine is not running, when the trail
/// cannot be read, or when a record in it is not a record this build understands.
pub async fn follow(host: &Host, arguments: &cli::Audit) -> Result<()> {
    let record = host.session(&arguments.session).await?;
    let name = record.id.container_name()?;
    // Asked for its own sake: the trail lives inside the machine, so a stopped one has
    // nothing to read and the researcher should hear that rather than an exec failure.
    host.address_of(&name).await?;
    let layout = host.layout();

    let command = vec![
        "tail".to_owned(),
        "-n".to_owned(),
        arguments.lines.to_string(),
        // `-F` rather than `-f`, because the gateway rotates the trail it is appending to.
        "-F".to_owned(),
        layout.audit_trail().display().to_string(),
    ];

    let mut stream = host
        .runtime()
        .exec_streaming(&name, &layout.gateway.name, &command)?;

    let mut stdout = std::io::stdout().lock();
    while let Some(line) = stream.next_line().await? {
        if line.trim().is_empty() {
            continue;
        }
        // `--raw` is what an exported trail is: evidence has to stay byte-for-byte what
        // the gateway recorded, so it is passed through without being parsed at all.
        if arguments.raw {
            writeln!(stdout, "{line}").context("writing the audit trail")?;
        } else {
            let record: AuditRecord = serde_json::from_str(&line)
                .with_context(|| format!("parsing an audit record: {line}"))?;
            writeln!(stdout, "{}", summarize(&record)).context("writing the audit trail")?;
        }
        stdout.flush().context("writing the audit trail")?;
    }

    stream.finish().await.map_err(Into::into)
}

/// One audited event as a single line a person can scan.
fn summarize(record: &AuditRecord) -> String {
    let uid = record
        .uid
        .map_or_else(|| "-".to_owned(), |uid| uid.to_string());
    format!("{} uid={uid} {}", record.at, event(&record.event))
}

fn event(event: &AuditEvent) -> String {
    match event {
        AuditEvent::Dns(query) => format!(
            "dns    {} {} -> {} ({}ms)",
            query.record_type,
            query.name,
            if query.answers.is_empty() {
                "no answer".to_owned()
            } else {
                query
                    .answers
                    .iter()
                    .map(|answer| answer.data.clone())
                    .collect::<Vec<_>>()
                    .join(", ")
            },
            query.elapsed_ms
        ),
        AuditEvent::Connect(connect) => format!(
            "tcp    {} {}up/{}down ({}ms)",
            destination(&connect.destination, connect.resolved_from.as_deref()),
            connect.bytes_out,
            connect.bytes_in,
            connect.elapsed_ms
        ),
        AuditEvent::Tls(handshake) => format!(
            "tls    {} sni={} alpn={} cert={}",
            destination(&handshake.destination, None),
            handshake.server_name.as_deref().unwrap_or("-"),
            handshake.alpn.as_deref().unwrap_or("-"),
            &handshake.upstream_cert_sha256[..16.min(handshake.upstream_cert_sha256.len())]
        ),
        AuditEvent::Http(exchange) => format!(
            "http   {} {} -> {} ({}B in, {}B out, {}ms)",
            exchange.method,
            exchange.url,
            exchange.status,
            exchange.response_bytes,
            exchange.request_bytes,
            exchange.elapsed_ms
        ),
        AuditEvent::Blocked(blocked) => format!(
            "BLOCK  {} {} {}",
            transport(blocked.transport),
            destination(&blocked.destination, None),
            reason(blocked.reason)
        ),
    }
}

fn destination(endpoint: &Endpoint, resolved_from: Option<&str>) -> String {
    match resolved_from {
        Some(name) => format!("{}:{} ({name})", endpoint.ip, endpoint.port),
        None => format!("{}:{}", endpoint.ip, endpoint.port),
    }
}

const fn transport(transport: Transport) -> &'static str {
    match transport {
        Transport::Tcp => "tcp",
        Transport::Udp => "udp",
        Transport::Other => "other",
    }
}

const fn reason(reason: BlockReason) -> &'static str {
    match reason {
        BlockReason::UnauditableTransport => "the transport cannot be audited in cleartext",
        BlockReason::NoHandler => "no transparent handler for the destination port",
        BlockReason::UpstreamUnreachable => "the upstream connection failed",
    }
}
