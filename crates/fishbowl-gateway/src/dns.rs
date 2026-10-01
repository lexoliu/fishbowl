//! The intercepting resolver.
//!
//! Name resolution is where a sample says what it is looking for before it says anything
//! else, so the gateway answers every query itself: it forwards the wire message upstream
//! unchanged and records both the question and the answers.

use std::{
    net::{SocketAddr, SocketAddrV4},
    sync::Arc,
    time::Instant,
};

use fishbowl_audit::{AuditEvent, BlockReason, Blocked, DnsAnswer, DnsQuery, Endpoint, Transport};
use fishbowl_egress::{Egress, Leg};
use hickory_proto::op::Message;
use tokio::{net::UdpSocket, time::Duration};

use crate::{
    audit::AuditSink,
    error::{GatewayError, Result},
    peer::{Udp, owner_of},
};

/// Largest DNS message the gateway relays; anything larger belongs on TCP.
const MAX_MESSAGE: usize = 4096;

/// How long an exchange with the upstream resolver may take before it is abandoned.
///
/// The transports pace themselves — five seconds over WARP, fifteen over Tor — so this
/// bound is the wedge guard behind them, not the real pacing.
const UPSTREAM_TIMEOUT: Duration = Duration::from_secs(30);

/// Answers redirected DNS queries until the socket fails.
///
/// `torsion_uid` splits the queries' route just as the packet filter splits
/// connections': a query from the dedicated account resolves inside Tor, everyone
/// else's on the base route — a lookup must never precede the traffic it names and
/// leak it to the wrong network.
///
/// # Errors
/// Fails only when the listening socket itself breaks.
pub async fn serve(
    socket: UdpSocket,
    upstream: SocketAddrV4,
    egress: Arc<Egress>,
    sink: AuditSink,
    torsion_uid: u32,
) -> Result<()> {
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
        let egress = Arc::clone(&egress);
        let sink = sink.clone();
        tokio::spawn(async move {
            if let Err(error) =
                resolve(&socket, client, upstream, egress, query, sink, torsion_uid).await
            {
                tracing::warn!(%error, %client, "a DNS query could not be answered");
            }
        });
    }
}

async fn resolve(
    socket: &UdpSocket,
    client: SocketAddr,
    upstream: SocketAddrV4,
    egress: Arc<Egress>,
    query: Vec<u8>,
    sink: AuditSink,
    torsion_uid: u32,
) -> Result<()> {
    let started = Instant::now();
    // Attributed before anything is forwarded, while the querying socket is still
    // bound — and under every tier, not just those that record traffic: the uid is
    // what routes the query, so the lookup is load-bearing even when nothing is
    // written to the trail.
    let SocketAddr::V4(source) = client else {
        return Err(GatewayError::NotIpv4 { peer: client });
    };
    let owner = owner_of::<Udp>(source).await?;
    let sink = sink.attributed_to(owner);
    let leg = if owner == Some(torsion_uid) {
        Leg::Torsion
    } else {
        Leg::Base
    };

    // The exchange crosses whatever route the querier's connections cross: a query
    // that went around its leg's tunnel would name the machine it came from.
    let exchanged =
        tokio::time::timeout(UPSTREAM_TIMEOUT, egress.dns_exchange(upstream, &query, leg))
            .await
            .map_err(|_| GatewayError::Socket {
                context: "waiting for the upstream resolver",
                source: std::io::Error::from(std::io::ErrorKind::TimedOut),
            })?;
    let answer = match exchanged {
        Ok(answer) => answer,
        Err(source) => {
            // A refused exchange is as much evidence as a refused connection: under a
            // strict egress mode it is the policy, not the resolver, answering.
            if source.kind() == std::io::ErrorKind::ConnectionAborted {
                sink.record(AuditEvent::Blocked(Blocked {
                    transport: Transport::Udp,
                    destination: Endpoint {
                        ip: (*upstream.ip()).into(),
                        port: upstream.port(),
                    },
                    reason: BlockReason::EgressUnavailable,
                }))
                .await;
            }
            return Err(GatewayError::Socket {
                context: "exchanging a DNS query with the upstream resolver",
                source,
            });
        }
    };
    let answer = answer.as_slice();

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
                ip: (*upstream.ip()).into(),
                port: upstream.port(),
            }),
            elapsed_ms,
        }))
        .await;
    }
    Ok(())
}
