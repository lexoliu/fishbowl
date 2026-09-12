//! The transparent TCP path.
//!
//! Every connection the sandbox opens arrives here through a netfilter redirect. What it
//! is decided by its first bytes: TLS gets terminated and re-originated, HTTP gets parsed,
//! and anything else is tunnelled and accounted for by volume — never dropped silently.

use std::{net::SocketAddr, sync::Arc, time::Instant};

use fishbowl_audit::{AuditEvent, BlockReason, Blocked, Connect, Endpoint, Transport};
use tokio::{
    io::{AsyncRead, AsyncWrite, copy_bidirectional},
    net::{TcpListener, TcpStream},
};

use crate::{
    audit::AuditSink,
    error::{GatewayError, Result},
    http::{self, ExchangeContext},
    peer::{Tcp, owner_of},
    redirect::original_destination,
    stream::{Prefixed, looks_like_http, looks_like_tls},
    tls::TlsBridge,
};

/// Accepts redirected connections until the listener fails.
///
/// # Errors
/// Fails only when the listening socket itself breaks; a failure on one connection is
/// recorded and the loop continues.
pub async fn serve(listener: TcpListener, bridge: Arc<TlsBridge>, sink: AuditSink) -> Result<()> {
    loop {
        let (stream, peer) = listener
            .accept()
            .await
            .map_err(|source| GatewayError::Socket {
                context: "accepting a redirected connection",
                source,
            })?;
        let bridge = Arc::clone(&bridge);
        let sink = sink.clone();
        tokio::spawn(async move {
            if let Err(error) = handle(stream, peer, bridge, sink).await {
                tracing::warn!(%error, %peer, "a redirected connection ended in an error");
            }
        });
    }
}

async fn handle(
    stream: TcpStream,
    peer: SocketAddr,
    bridge: Arc<TlsBridge>,
    sink: AuditSink,
) -> Result<()> {
    let destination = original_destination(&stream)?;
    // The account that opened this connection is only recoverable while its socket is
    // still in the kernel's table, which is now: the connection is established and the
    // gateway has not yet started relaying it.
    let SocketAddr::V4(source) = peer else {
        return Err(GatewayError::NotIpv4 { peer });
    };
    let sink = sink.attributed_to(owner_of::<Tcp>(source).await?);
    let endpoint = Endpoint {
        ip: destination.ip(),
        port: destination.port(),
    };
    let probed = Prefixed::probe(stream)
        .await
        .map_err(|source| GatewayError::Socket {
            context: "probing a redirected connection",
            source,
        })?;

    if looks_like_tls(probed.prefix()) {
        return intercept_tls(probed, peer, destination, endpoint, bridge, sink).await;
    }

    let Some(upstream) = connect(destination, &endpoint, &sink).await? else {
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

async fn intercept_tls(
    probed: Prefixed<TcpStream>,
    peer: SocketAddr,
    destination: SocketAddr,
    endpoint: Endpoint,
    bridge: Arc<TlsBridge>,
    sink: AuditSink,
) -> Result<()> {
    let intercepted = match bridge.intercept(probed, peer, destination).await {
        Ok(intercepted) => intercepted,
        Err(error) => {
            sink.record(AuditEvent::Blocked(Blocked {
                transport: Transport::Tcp,
                destination: endpoint,
                reason: BlockReason::UpstreamUnreachable,
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

/// Opens the upstream connection, recording a refusal if the destination is unreachable.
async fn connect(
    destination: SocketAddr,
    endpoint: &Endpoint,
    sink: &AuditSink,
) -> Result<Option<TcpStream>> {
    match TcpStream::connect(destination).await {
        Ok(stream) => Ok(Some(stream)),
        Err(error) => {
            tracing::debug!(%error, %destination, "the destination refused the connection");
            sink.record(AuditEvent::Blocked(Blocked {
                transport: Transport::Tcp,
                destination: endpoint.clone(),
                reason: BlockReason::UpstreamUnreachable,
            }))
            .await;
            Ok(None)
        }
    }
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
