//! The transparent TCP path.
//!
//! Every connection the sandbox opens arrives here through a netfilter redirect. What it
//! is decided by its first bytes: TLS gets terminated and re-originated, HTTP gets parsed,
//! and anything else is tunnelled and accounted for by volume — never dropped silently.

use std::{net::SocketAddr, sync::Arc, time::Instant};

use fishbowl_audit::{AuditEvent, BlockReason, Blocked, Connect, Endpoint, TlsSeen, Transport};
use fishbowl_egress::{Egress, Upstream};
use tokio::{
    io::{AsyncRead, AsyncWrite, copy_bidirectional},
    net::{TcpListener, TcpStream},
};

use crate::{
    audit::AuditSink,
    error::{GatewayError, Result},
    hello,
    http::{self, ExchangeContext},
    peer::{Tcp, owner_of},
    redirect::original_destination,
    stream::{Prefixed, looks_like_http, looks_like_tls},
    tls::TlsBridge,
};

/// What the session's audit tier does to a redirected connection.
///
/// The tier decides how far inside a connection the gateway goes; the egress policy
/// decides where the connection goes. `Observe` and `Pass` never terminate anything —
/// the bytes the sandbox sent cross end-to-end untouched.
#[derive(Clone)]
pub enum Inspection {
    /// `strict`: terminate TLS at the gateway and parse what is inside.
    Terminate(Arc<TlsBridge>),
    /// `default`: read client hellos for their SNI, parse plaintext HTTP, relay
    /// everything end-to-end.
    Observe,
    /// `off`: relay every connection; nothing about it is written to the trail.
    Pass,
}

/// Accepts redirected connections until the listener fails.
///
/// # Errors
/// Fails only when the listening socket itself breaks; a failure on one connection is
/// recorded and the loop continues.
pub async fn serve(
    listener: TcpListener,
    inspection: Inspection,
    egress: Arc<Egress>,
    sink: AuditSink,
) -> Result<()> {
    loop {
        let (stream, peer) = listener
            .accept()
            .await
            .map_err(|source| GatewayError::Socket {
                context: "accepting a redirected connection",
                source,
            })?;
        let inspection = inspection.clone();
        let egress = Arc::clone(&egress);
        let sink = sink.clone();
        tokio::spawn(async move {
            if let Err(error) = handle(stream, peer, inspection, egress, sink).await {
                tracing::warn!(%error, %peer, "a redirected connection ended in an error");
            }
        });
    }
}

async fn handle(
    stream: TcpStream,
    peer: SocketAddr,
    inspection: Inspection,
    egress: Arc<Egress>,
    sink: AuditSink,
) -> Result<()> {
    let destination = original_destination(&stream)?;
    // The account that opened this connection is only recoverable while its socket is
    // still in the kernel's table, which is now: the connection is established and the
    // gateway has not yet started relaying it. Under `off` nothing is recorded, so the
    // lookup is skipped rather than wasted.
    let SocketAddr::V4(source) = peer else {
        return Err(GatewayError::NotIpv4 { peer });
    };
    let sink = if sink.records_traffic() {
        sink.attributed_to(owner_of::<Tcp>(source).await?)
    } else {
        sink
    };
    let endpoint = Endpoint {
        ip: destination.ip(),
        port: destination.port(),
    };

    // `off` probes nothing: a connection is a connection, and the sandbox's bytes are
    // relayed exactly as they arrived.
    if let Inspection::Pass = inspection {
        let Some(upstream) = connect(destination, &egress, &endpoint, &sink).await? else {
            return Ok(());
        };
        return tunnel(stream, upstream, endpoint, sink).await;
    }

    let probed = Prefixed::probe(stream)
        .await
        .map_err(|source| GatewayError::Socket {
            context: "probing a redirected connection",
            source,
        })?;

    if looks_like_tls(probed.prefix()) {
        return match inspection {
            Inspection::Terminate(bridge) => {
                intercept_tls(probed, peer, destination, endpoint, bridge, egress, sink).await
            }
            Inspection::Observe => observe_tls(probed, destination, endpoint, egress, sink).await,
            Inspection::Pass => unreachable!("the pass-through path never probes"),
        };
    }

    let Some(upstream) = connect(destination, &egress, &endpoint, &sink).await? else {
        return Ok(());
    };
    if looks_like_http(probed.prefix()) {
        let context = ExchangeContext {
            scheme: "http",
            authority: destination.to_string(),
            destination: endpoint,
        };
        http::proxy(probed, upstream, context, sink)
            .await
            .map_err(|error| GatewayError::Socket {
                context: "proxying a plain HTTP connection",
                source: std::io::Error::other(error.to_string()),
            })
    } else {
        tunnel(probed, upstream, endpoint, sink).await
    }
}

/// Records the client hello's declared destination and relays the session untouched.
///
/// The record is written before the upstream attempt so the trail holds what the
/// sandbox asked for even when no route could carry it there.
async fn observe_tls(
    probed: Prefixed<TcpStream>,
    destination: SocketAddr,
    endpoint: Endpoint,
    egress: Arc<Egress>,
    sink: AuditSink,
) -> Result<()> {
    let (probed, hello) = hello::observe(probed)
        .await
        .map_err(|source| GatewayError::Socket {
            context: "reading a client hello for the record",
            source,
        })?;
    sink.record(AuditEvent::TlsSeen(TlsSeen {
        destination: endpoint.clone(),
        server_name: hello.server_name,
        alpn: hello.alpn,
    }))
    .await;
    let Some(upstream) = connect(destination, &egress, &endpoint, &sink).await? else {
        return Ok(());
    };
    tunnel(probed, upstream, endpoint, sink).await
}

async fn intercept_tls(
    probed: Prefixed<TcpStream>,
    peer: SocketAddr,
    destination: SocketAddr,
    endpoint: Endpoint,
    bridge: Arc<TlsBridge>,
    egress: Arc<Egress>,
    sink: AuditSink,
) -> Result<()> {
    let intercepted = match bridge.intercept(probed, peer, destination, &egress).await {
        Ok(intercepted) => intercepted,
        Err(error) => {
            sink.record(AuditEvent::Blocked(Blocked {
                transport: Transport::Tcp,
                destination: endpoint,
                reason: refusal_reason(&error),
            }))
            .await;
            return Err(error);
        }
    };
    let authority = intercepted
        .handshake
        .server_name
        .clone()
        .unwrap_or_else(|| destination.ip().to_string());
    sink.record(AuditEvent::Tls(intercepted.handshake)).await;

    let inner = Prefixed::probe(intercepted.sandbox)
        .await
        .map_err(|source| GatewayError::Socket {
            context: "probing the inside of an intercepted TLS session",
            source,
        })?;
    if looks_like_http(inner.prefix()) {
        let context = ExchangeContext {
            scheme: "https",
            authority,
            destination: endpoint,
        };
        http::proxy(inner, intercepted.upstream, context, sink)
            .await
            .map_err(|error| GatewayError::Socket {
                context: "proxying an intercepted HTTPS connection",
                source: std::io::Error::other(error.to_string()),
            })
    } else {
        tunnel(inner, intercepted.upstream, endpoint, sink).await
    }
}

/// Opens the upstream connection on the session's egress route, recording a refusal if
/// the destination is unreachable — or, under a strict egress mode, refused while the
/// tunnel that must carry it is down.
async fn connect(
    destination: SocketAddr,
    egress: &Egress,
    endpoint: &Endpoint,
    sink: &AuditSink,
) -> Result<Option<Upstream>> {
    match egress.connect(destination).await {
        Ok(stream) => Ok(Some(stream)),
        Err(error) => {
            tracing::debug!(%error, %destination, "the destination refused the connection");
            sink.record(AuditEvent::Blocked(Blocked {
                transport: Transport::Tcp,
                destination: endpoint.clone(),
                reason: if refused_by_egress(&error) {
                    BlockReason::EgressUnavailable
                } else {
                    BlockReason::UpstreamUnreachable
                },
            }))
            .await;
            Ok(None)
        }
    }
}

/// Why an upstream attempt failed, for the refusal record.
///
/// The egress layer reports a down transport under a strict mode as
/// `ConnectionAborted`: the connection was refused by policy, not by anything the
/// destination did — telling that apart from an unreachable destination is what a
/// fail-closed audit trail exists for.
fn refusal_reason(error: &GatewayError) -> BlockReason {
    let (GatewayError::Socket { source, .. } | GatewayError::Tls { source, .. }) = error else {
        return BlockReason::UpstreamUnreachable;
    };
    if refused_by_egress(source) {
        BlockReason::EgressUnavailable
    } else {
        BlockReason::UpstreamUnreachable
    }
}

/// Whether `error` is the egress layer refusing a connection rather than the
/// destination doing so.
fn refused_by_egress(error: &std::io::Error) -> bool {
    error.kind() == std::io::ErrorKind::ConnectionAborted
}

/// Relays a connection the gateway cannot parse, accounting for it by volume.
async fn tunnel<S, U>(
    mut sandbox: S,
    mut upstream: U,
    destination: Endpoint,
    sink: AuditSink,
) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
    U: AsyncRead + AsyncWrite + Unpin,
{
    let started = Instant::now();
    let (bytes_out, bytes_in) = copy_bidirectional(&mut sandbox, &mut upstream)
        .await
        .map_err(|source| GatewayError::Socket {
            context: "relaying an unparsed connection",
            source,
        })?;
    let elapsed_ms = u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX);
    sink.record(AuditEvent::Connect(Connect {
        destination,
        resolved_from: None,
        bytes_out,
        bytes_in,
        elapsed_ms,
    }))
    .await;
    Ok(())
}
