//! HTTP auditing.
//!
//! Once a stream is in the clear — either because it never was TLS or because
//! [`crate::tls`] terminated it — the gateway speaks HTTP/1.1 on both sides so every
//! request line, header and byte count lands in the audit trail. Connections that upgrade
//! stay auditable as byte counts rather than being refused.

use std::{
    pin::Pin,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    task::{Context, Poll},
    time::Instant,
};

use fishbowl_audit::{AuditEvent, Connect, Endpoint, HttpExchange};
use hyper::{
    Request, Response, StatusCode,
    body::{Body, Bytes, Frame, Incoming, SizeHint},
    server::conn::http1 as server_http1,
    service::service_fn,
};
use hyper_util::rt::TokioIo;
use tokio::{
    io::{AsyncRead, AsyncWrite},
    sync::{mpsc, oneshot},
};

use crate::audit::AuditSink;

/// What one intercepted connection is aimed at, as the audit trail should name it.
#[derive(Debug, Clone)]
pub struct ExchangeContext {
    /// `http` or `https`, decided by whether TLS was terminated.
    pub scheme: &'static str,
    /// Authority used when the request carries no `Host` header.
    pub authority: String,
    /// Endpoint the connection was originally aimed at.
    pub destination: Endpoint,
}

/// A request or response body that counts what passes through it.
///
/// The count is what the audit trail reports, and taking it from the body itself rather
/// than from `Content-Length` means a chunked or truncated transfer is still reported by
/// what actually crossed the boundary.
struct Observed<B> {
    inner: B,
    counted: Arc<AtomicU64>,
    report: Option<ExchangeReport>,
}

/// Everything needed to write the exchange record once the response body ends.
struct ExchangeReport {
    sink: AuditSink,
    started: Instant,
    method: String,
    url: String,
    request_headers: Vec<(String, String)>,
    request_bytes: Arc<AtomicU64>,
    status: u16,
    response_headers: Vec<(String, String)>,
}

impl ExchangeReport {
    fn emit(self, response_bytes: u64) {
        let elapsed_ms = u64::try_from(self.started.elapsed().as_millis()).unwrap_or(u64::MAX);
        let event = AuditEvent::Http(HttpExchange {
            method: self.method,
            url: self.url,
            request_headers: self.request_headers,
            request_bytes: self.request_bytes.load(Ordering::Relaxed),
            status: self.status,
            response_headers: self.response_headers,
            response_bytes,
            elapsed_ms,
        });
        let sink = self.sink;
        tokio::spawn(async move { sink.record(event).await });
    }
}

impl<B> Observed<B> {
    fn counting(inner: B, counted: Arc<AtomicU64>) -> Self {
        Self {
            inner,
            counted,
            report: None,
        }
    }

    fn reporting(inner: B, report: ExchangeReport) -> Self {
        Self {
            inner,
            counted: Arc::new(AtomicU64::new(0)),
            report: Some(report),
        }
    }
}

impl<B> Body for Observed<B>
where
    B: Body<Data = Bytes> + Unpin,
{
    type Data = Bytes;
    type Error = B::Error;

    fn poll_frame(
        self: Pin<&mut Self>,
        context: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        let this = self.get_mut();
        let polled = Pin::new(&mut this.inner).poll_frame(context);
        match &polled {
            Poll::Ready(Some(Ok(frame))) => {
                if let Some(data) = frame.data_ref() {
                    this.counted.fetch_add(data.len() as u64, Ordering::Relaxed);
                }
            }
            Poll::Ready(None) => {
                if let Some(report) = this.report.take() {
                    report.emit(this.counted.load(Ordering::Relaxed));
                }
            }
            _ => {}
        }
        polled
    }

    fn is_end_stream(&self) -> bool {
        self.inner.is_end_stream()
    }

    fn size_hint(&self) -> SizeHint {
        self.inner.size_hint()
    }
}

/// One request in flight towards the upstream connection driver.
type Exchange = (
    Request<Observed<Incoming>>,
    oneshot::Sender<hyper::Result<Response<Incoming>>>,
);

/// Proxies one clear-text HTTP/1.1 connection, recording every exchange.
///
/// # Errors
/// Fails when either connection cannot be driven to completion.
pub async fn proxy<S, U>(
    sandbox: S,
    upstream: U,
    context: ExchangeContext,
    sink: AuditSink,
) -> anyhow::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    U: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let (mut sender, connection) =
        hyper::client::conn::http1::handshake(TokioIo::new(upstream)).await?;
    tokio::spawn(async move {
        if let Err(error) = connection.with_upgrades().await {
            tracing::debug!(%error, "the upstream connection ended");
        }
    });

    let (exchanges, mut incoming) = mpsc::channel::<Exchange>(1);
    tokio::spawn(async move {
        while let Some((request, reply)) = incoming.recv().await {
            let response = match sender.ready().await {
                Ok(()) => sender.send_request(request).await,
                Err(error) => Err(error),
            };
            let _ = reply.send(response);
        }
    });

    let service = service_fn(move |request: Request<Incoming>| {
        let exchanges = exchanges.clone();
        let sink = sink.clone();
        let context = context.clone();
        async move { forward(request, exchanges, sink, context).await }
    });

    server_http1::Builder::new()
        .serve_connection(TokioIo::new(sandbox), service)
        .with_upgrades()
        .await?;
    Ok(())
}

async fn forward(
    mut request: Request<Incoming>,
    exchanges: mpsc::Sender<Exchange>,
    sink: AuditSink,
    context: ExchangeContext,
) -> anyhow::Result<Response<Observed<Incoming>>> {
    let started = Instant::now();
    let method = request.method().to_string();
    let url = url_of(&request, &context);
    let request_headers = headers_of(request.headers());
    let sandbox_upgrade = hyper::upgrade::on(&mut request);

    let request_bytes = Arc::new(AtomicU64::new(0));
    let (parts, body) = request.into_parts();
    let request = Request::from_parts(parts, Observed::counting(body, Arc::clone(&request_bytes)));

    let (reply, response) = oneshot::channel();
    exchanges.send((request, reply)).await.map_err(|_| {
        anyhow::anyhow!("the upstream connection driver stopped before the request was sent")
    })?;
    let mut response = response.await??;

    let status = response.status();
    let response_headers = headers_of(response.headers());
    if status == StatusCode::SWITCHING_PROTOCOLS {
        splice_upgrade(
            sandbox_upgrade,
            hyper::upgrade::on(&mut response),
            sink.clone(),
            context.destination.clone(),
        );
    }

    let report = ExchangeReport {
        sink,
        started,
        method,
        url,
        request_headers,
        request_bytes,
        status: status.as_u16(),
        response_headers,
    };
    let (parts, body) = response.into_parts();
    Ok(Response::from_parts(
        parts,
        Observed::reporting(body, report),
    ))
}

/// Keeps an upgraded connection auditable as a byte count once HTTP framing is gone.
fn splice_upgrade(
    sandbox: hyper::upgrade::OnUpgrade,
    upstream: hyper::upgrade::OnUpgrade,
    sink: AuditSink,
    destination: Endpoint,
) {
    tokio::spawn(async move {
        let started = Instant::now();
        let (sandbox, upstream) = match tokio::try_join!(sandbox, upstream) {
            Ok(pair) => pair,
            Err(error) => {
                tracing::warn!(%error, "an upgraded connection could not be spliced");
                return;
            }
        };
        let mut sandbox = TokioIo::new(sandbox);
        let mut upstream = TokioIo::new(upstream);
        match tokio::io::copy_bidirectional(&mut sandbox, &mut upstream).await {
            Ok((bytes_out, bytes_in)) => {
                let elapsed_ms = u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX);
                sink.record(AuditEvent::Connect(Connect {
                    destination,
                    resolved_from: None,
                    bytes_out,
                    bytes_in,
                    elapsed_ms,
                }))
                .await;
            }
            Err(error) => tracing::warn!(%error, "an upgraded connection ended abruptly"),
        }
    });
}

fn url_of(request: &Request<Incoming>, context: &ExchangeContext) -> String {
    let authority = request
        .headers()
        .get(hyper::header::HOST)
        .and_then(|host| host.to_str().ok())
        .unwrap_or(context.authority.as_str());
    let path = request
        .uri()
        .path_and_query()
        .map_or("/", http::uri::PathAndQuery::as_str);
    format!("{}://{authority}{path}", context.scheme)
}

fn headers_of(headers: &hyper::HeaderMap) -> Vec<(String, String)> {
    headers
        .iter()
        .map(|(name, value)| {
            (
                name.as_str().to_owned(),
                String::from_utf8_lossy(value.as_bytes()).into_owned(),
            )
        })
        .collect()
}
