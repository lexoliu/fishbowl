//! The Tor transport: an Arti client bootstrapped inside the gateway process.
//!
//! Like the WARP tunnel this is invisible to the packet filter — a handful of outbound
//! TCP connections owned by the gateway user — except that anonymity is stronger than a
//! WARP exit's, and slower. Arti resolves names at the exit; the gateway only ever hands
//! it numeric destinations, because names belong to the audited DNS path.

use std::{
    io,
    net::{SocketAddr, SocketAddrV4},
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};

use arti_client::{
    DangerouslyIntoTorAddr, StreamPrefs, TorAddr, TorClient,
    config::{ConfigBuildError, TorClientConfigBuilder},
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    sync::watch,
};
use tor_rtcompat::PreferredRuntime;

use crate::{Link, Transport};

/// One DNS exchange attempt may take this long through a circuit — long enough for a
/// fresh circuit's build plus the exchange, short enough that a dead stream moves on
/// to a new exit quickly.
const ATTEMPT_TIMEOUT: Duration = Duration::from_secs(20);

/// The whole DNS exchange may take this long across attempts.
const DNS_TIMEOUT: Duration = Duration::from_secs(90);

/// A failed stream or exchange is retried this many times. Each retry rides a circuit
/// no other stream shares, which is how Arti is coaxed into a fresh exit — the only
/// remedy for a destination one exit refuses or cannot reach.
const ATTEMPTS: usize = 5;

/// Bootstrapping a fresh consensus can take minutes on a slow network; an attempt that
/// outlasts this is declared dead and retried under the supervisor's backoff.
const BOOTSTRAP_TIMEOUT: Duration = Duration::from_secs(240);

/// A Tor network with a usable consensus: Arti keeps the circuits alive itself, so once
/// bootstrapped the client stays for the gateway's lifetime.
#[derive(Clone)]
pub struct Tor {
    client: Arc<TorClient<PreferredRuntime>>,
}

impl Tor {
    /// Opens a TCP stream through a circuit.
    ///
    /// # Errors
    /// Fails when no circuit to the destination can be built or the exit refuses.
    pub async fn connect(&self, destination: SocketAddr) -> io::Result<arti_client::DataStream> {
        // The gateway's destinations are always numeric — the name was already resolved
        // and audited. `DangerouslyIntoTorAddr` exists for exactly this: asking an exit
        // to dial an address, which carries no DNS-leak risk at all.
        let target = destination.into_tor_addr_dangerously().map_err(|error| {
            io::Error::other(format!(
                "{destination} is not a usable Tor destination: {error}"
            ))
        })?;
        let mut last_error = None;
        for _ in 0..ATTEMPTS {
            match self.connect_fresh(target.clone()).await {
                Ok(stream) => return Ok(stream),
                Err(error) => last_error = Some(error),
            }
        }
        Err(io::Error::other(
            last_error
                .map(|error| format!("Tor could not reach {destination}: {error}"))
                .unwrap_or_default(),
        ))
    }

    /// One connect attempt on a circuit no other stream shares.
    async fn connect_fresh(
        &self,
        target: TorAddr,
    ) -> Result<arti_client::DataStream, arti_client::Error> {
        let mut prefs = StreamPrefs::new();
        prefs.new_isolation_group();
        self.client.connect_with_prefs(target, &prefs).await
    }

    /// Relays one DNS wire message over TCP to `resolver` through an exit node.
    ///
    /// Exits do not forward raw UDP, so the query goes over TCP — the resolver sees the
    /// exit, not the sandbox.
    ///
    /// # Errors
    /// Fails when the circuit or the resolver times out or refuses.
    pub async fn dns_exchange(&self, resolver: SocketAddrV4, query: &[u8]) -> io::Result<Vec<u8>> {
        tokio::time::timeout(DNS_TIMEOUT, self.dns_exchange_inner(resolver, query))
            .await
            .map_err(|_| {
                io::Error::new(
                    io::ErrorKind::TimedOut,
                    "the resolver did not answer over Tor",
                )
            })?
    }

    async fn dns_exchange_inner(
        &self,
        resolver: SocketAddrV4,
        query: &[u8],
    ) -> io::Result<Vec<u8>> {
        // A stream can be accepted by an exit and still die at first use — the exit
        // itself could not reach the resolver — so the whole exchange is what retries,
        // and the retry is what carries the per-attempt deadline. Exits that cannot
        // carry a given port are common enough that a handful of circuits is no rare
        // case; the attempt count and the outer deadline bound it together.
        let mut last_error = None;
        for _ in 0..ATTEMPTS {
            match tokio::time::timeout(ATTEMPT_TIMEOUT, self.dns_exchange_once(resolver, query))
                .await
            {
                Ok(Ok(answer)) => return Ok(answer),
                Ok(Err(error)) => last_error = Some(error),
                Err(_) => {
                    last_error = Some(io::Error::new(
                        io::ErrorKind::TimedOut,
                        "a circuit did not answer the exchange",
                    ));
                }
            }
        }
        Err(last_error
            .unwrap_or_else(|| io::Error::other("the resolver could not be reached over Tor")))
    }

    async fn dns_exchange_once(&self, resolver: SocketAddrV4, query: &[u8]) -> io::Result<Vec<u8>> {
        let mut stream = self.connect(SocketAddr::V4(resolver)).await?;
        let length = u16::try_from(query.len()).map_err(|_| {
            io::Error::new(io::ErrorKind::InvalidInput, "the DNS query is oversized")
        })?;
        stream.write_all(&length.to_be_bytes()).await?;
        stream.write_all(query).await?;
        stream.flush().await?;

        let mut length = [0_u8; 2];
        stream.read_exact(&mut length).await?;
        let length = usize::from(u16::from_be_bytes(length));
        let mut answer = vec![0_u8; length];
        stream.read_exact(&mut answer).await?;
        Ok(answer)
    }
}

/// Bootstraps Arti with its cache and state under `state_dir/tor`.
async fn establish(state_dir: &Path) -> Result<Tor, Error> {
    let directory = state_dir.join("tor");
    let state = directory.join("state");
    let cache = directory.join("cache");
    tokio::fs::create_dir_all(&state).await?;
    tokio::fs::create_dir_all(&cache).await?;
    // Arti's mistrusted-filesystem check refuses directories a stranger can read; the
    // state holds the client's keys, so owner-only is the correct mode anyway.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        for directory in [&directory, &state, &cache] {
            tokio::fs::set_permissions(directory, std::fs::Permissions::from_mode(0o700)).await?;
        }
    }
    let config = TorClientConfigBuilder::from_directories(state, cache).build()?;
    let client = tokio::time::timeout(BOOTSTRAP_TIMEOUT, TorClient::create_bootstrapped(config))
        .await
        .map_err(|_| {
            Error::Io(io::Error::new(
                io::ErrorKind::TimedOut,
                "Tor did not bootstrap in time",
            ))
        })??;
    Ok(Tor { client })
}

/// Bootstraps Tor, publishing `Connecting`/`Up`/`Unavailable` as attempts resolve.
///
/// Once `Up` is published the supervisor's job is done — Arti keeps itself alive for as
/// long as the published handle is held.
pub(super) async fn supervise(state_dir: PathBuf, link: watch::Sender<Link>) {
    let mut backoff = Duration::from_secs(5);
    let mut last_failure: Option<Arc<str>> = None;
    loop {
        let _ = link.send(match &last_failure {
            Some(reason) => Link::Retrying(Arc::clone(reason)),
            None => Link::Connecting,
        });
        match establish(&state_dir).await {
            Ok(tor) => {
                tracing::info!("the Tor client is bootstrapped");
                let _ = link.send(Link::Up(Transport::Tor(tor)));
                return;
            }
            Err(error) => {
                tracing::warn!(%error, "Tor is unavailable");
                let reason: Arc<str> = Arc::from(error.to_string());
                last_failure = Some(Arc::clone(&reason));
                let _ = link.send(Link::Unavailable(reason));
            }
        }
        tokio::time::sleep(backoff).await;
        backoff = (backoff * 2).min(Duration::from_secs(60));
    }
}

/// Why Tor could not be raised.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// The Arti configuration failed — the directories could not be laid out.
    #[error("configuring Arti: {0}")]
    Config(#[from] ConfigBuildError),
    /// Bootstrap or a later circuit failed.
    #[error(transparent)]
    Bootstrap(#[from] arti_client::Error),
    /// Laying out the state directories failed.
    #[error(transparent)]
    Io(#[from] io::Error),
}
