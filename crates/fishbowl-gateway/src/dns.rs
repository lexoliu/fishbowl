//! The intercepting resolver.
//!
//! Name resolution is where a sample says what it is looking for before it says anything
//! else, so the gateway answers every query itself: it forwards the wire message upstream
//! unchanged and records both the question and the answers.

use std::{net::SocketAddr, sync::Arc, time::Instant};

use fishbowl_audit::{AuditEvent, DnsAnswer, DnsQuery, Endpoint};
use hickory_proto::op::Message;
use tokio::{net::UdpSocket, time::Duration};

use crate::{
    audit::AuditSink,
    error::{GatewayError, Result},
    peer::{Udp, owner_of},
};

/// Largest DNS message the gateway relays; anything larger belongs on TCP.
const MAX_MESSAGE: usize = 4096;

/// How long the upstream resolver is given to answer.
const UPSTREAM_TIMEOUT: Duration = Duration::from_secs(5);

/// Answers redirected DNS queries until the socket fails.
///
/// # Errors
/// Fails only when the listening socket itself breaks.
pub async fn serve(socket: UdpSocket, upstream: SocketAddr, sink: AuditSink) -> Result<()> {
    let socket = Arc::new(socket);
    let mut buffer = vec![0_u8; MAX_MESSAGE];
    loop {
        let (length, client) =
            socket
                .recv_from(&mut buffer)
                .await
                .map_err(|source| GatewayError::Socket {
                    context: "receiving a redirected DNS query",
                    source,
                })?;
        let query = buffer[..length].to_vec();
        let socket = Arc::clone(&socket);
        let sink = sink.clone();
        tokio::spawn(async move {
            if let Err(error) = resolve(&socket, client, upstream, query, sink).await {
                tracing::warn!(%error, %client, "a DNS query could not be answered");
            }
        });
    }
}

async fn resolve(
    socket: &UdpSocket,
    client: SocketAddr,
    upstream: SocketAddr,
    query: Vec<u8>,
    sink: AuditSink,
) -> Result<()> {
    let started = Instant::now();
    // Attributed before anything is forwarded, while the querying socket is still bound.
    let SocketAddr::V4(source) = client else {
        return Err(GatewayError::NotIpv4 { peer: client });
    };
    let sink = sink.attributed_to(owner_of::<Udp>(source).await?);
    let outbound =
        UdpSocket::bind(("0.0.0.0", 0))
            .await
            .map_err(|source| GatewayError::Socket {
                context: "opening a socket towards the upstream resolver",
                source,
            })?;
    outbound
        .send_to(&query, upstream)
        .await
        .map_err(|source| GatewayError::Socket {
            context: "forwarding a DNS query upstream",
            source,
        })?;

    let mut buffer = vec![0_u8; MAX_MESSAGE];
    let length = tokio::time::timeout(UPSTREAM_TIMEOUT, outbound.recv(&mut buffer))
        .await
        .map_err(|_| GatewayError::Socket {
            context: "waiting for the upstream resolver",
            source: std::io::Error::from(std::io::ErrorKind::TimedOut),
        })?
        .map_err(|source| GatewayError::Socket {
            context: "reading the upstream resolver's answer",
            source,
        })?;
    let answer = &buffer[..length];

    socket
        .send_to(answer, client)
        .await
        .map_err(|source| GatewayError::Socket {
            context: "returning a DNS answer to the sandbox",
            source,
        })?;

    let elapsed_ms = u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX);
    let question = Message::from_vec(&query)?;
    let response = Message::from_vec(answer)?;
    for query in &question.queries {
        sink.record(AuditEvent::Dns(DnsQuery {
            name: query.name().to_string(),
            record_type: query.query_type().to_string(),
            answers: response
                .answers
                .iter()
                .map(|record| DnsAnswer {
                    record_type: record.record_type().to_string(),
                    data: record.data.to_string(),
                })
                .collect(),
            upstream: Some(Endpoint {
                ip: upstream.ip(),
                port: upstream.port(),
            }),
            elapsed_ms,
        }))
        .await;
    }
    Ok(())
}
