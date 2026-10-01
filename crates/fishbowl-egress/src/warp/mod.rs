//! The Cloudflare `WARP` transport: a `WireGuard` tunnel driven entirely in-process.
//!
//! `boringtun` answers the `WireGuard` side — handshakes, session keys, encapsulation —
//! while `smoltcp` is the IP stack at our end of the tunnel: it turns the decrypted
//! packets into TCP streams and UDP exchanges the gateway can use as if they were
//! ordinary sockets. On the wire the whole transport is one UDP socket owned by the
//! gateway user, no different to the packet filter from any other audited egress.

mod driver;
mod registration;
mod sockets;

pub use sockets::Tcp;

use std::{
    io,
    net::SocketAddr,
    net::SocketAddrV4,
    path::Path,
    path::PathBuf,
    sync::{Arc, Mutex, MutexGuard, PoisonError},
    time::Duration,
};

use smoltcp::{
    iface::{SocketHandle, SocketSet},
    wire::IpEndpoint,
};
use thiserror::Error;
use tokio::{
    sync::{Notify, mpsc, oneshot, watch},
    task::JoinHandle,
};

use crate::{Link, Transport};
use registration::RegistrationError;
use sockets::Death;

/// The `WireGuard` handshake cadence: `update_timers` retransmits and rekeys on this tick.
const TIMER_TICK: Duration = Duration::from_millis(250);

/// The longest a handshake may take before the attempt counts as failed.
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(30);

/// A session this old without a completed rekey is dead — `WireGuard` keys are
/// cryptographically rejected at 180 seconds, so a tunnel whose last handshake is older
/// is closed in fact if not yet in name.
const SESSION_STALE: Duration = Duration::from_secs(200);

/// Why the tunnel is not usable.
#[derive(Debug, Error)]
pub enum Error {
    /// Registering the device or reading its file failed.
    #[error(transparent)]
    Registration(#[from] RegistrationError),
    /// The handshake never completed, or the session died.
    #[error(transparent)]
    Io(#[from] io::Error),
}

/// Raises and re-raises the WARP tunnel, publishing its state to `link`.
///
/// The supervisor never returns: a raised tunnel is run by its driver task until it
/// dies, at which point the supervisor waits out a backoff and tries the handshake
/// again. The device registration is reused — it survives restarts by design.
pub(super) async fn supervise(
    state_dir: PathBuf,
    resolver: SocketAddrV4,
    link: watch::Sender<Link>,
) {
    let mut backoff = Duration::from_secs(5);
    let mut last_failure: Option<Arc<str>> = None;
    loop {
        let _ = link.send(match &last_failure {
            // A first attempt asks connections to wait; a retry must not — modes that
            // allow fallback keep going direct on the last verdict while this runs.
            Some(reason) => Link::Retrying(Arc::clone(reason)),
            None => Link::Connecting,
        });
        match establish(&state_dir, resolver).await {
            Ok((stack, driver)) => {
                backoff = Duration::from_secs(5);
                tracing::info!(endpoint = %stack.endpoint(), "the WARP tunnel is up");
                let _ = link.send(Link::Up(Transport::Warp(stack)));
                match driver.await {
                    Ok(Ok(())) => tracing::info!("the WARP tunnel closed"),
                    Ok(Err(error)) => {
                        tracing::warn!(%error, "the WARP tunnel died");
                    }
                    Err(error) => {
                        tracing::warn!(%error, "the WARP driver task failed");
                    }
                }
                // Publish the death now, not after the backoff: the link still says `Up`
                // otherwise, and the audit trail would show `warp` for a route that is
                // already refusing connections.
                let reason: Arc<str> = Arc::from("the tunnel went down");
                last_failure = Some(Arc::clone(&reason));
                let _ = link.send(Link::Unavailable(reason));
            }
            Err(error) => {
                tracing::warn!(%error, "WARP is unavailable");
                let reason: Arc<str> = Arc::from(error.to_string());
                last_failure = Some(Arc::clone(&reason));
                let _ = link.send(Link::Unavailable(reason));
            }
        }
        tokio::time::sleep(backoff).await;
        backoff = (backoff * 2).min(Duration::from_secs(60));
    }
}

/// Builds one tunnel and waits for its handshake.
///
/// The returned join handle is the driver's lifetime: when it finishes — on error or on
/// every [`Stack`] handle being dropped — the tunnel is dead and the supervisor should
/// try again.
///
/// # Errors
/// Fails when the device cannot be registered or the handshake does not complete in
/// [`HANDSHAKE_TIMEOUT`].
async fn establish(
    state_dir: &Path,
    resolver: SocketAddrV4,
) -> Result<(Stack, JoinHandle<io::Result<()>>), Error> {
    let device = registration::load_or_register(state_dir, resolver).await?;

    let udp = tokio::net::UdpSocket::bind((std::net::Ipv4Addr::UNSPECIFIED, 0)).await?;
    udp.connect(device.endpoint).await?;

    let socket_set = Arc::new(Mutex::new(SocketSet::new(Vec::new())));
    let wake = Arc::new(Notify::new());
    let retired = Arc::new(Mutex::new(Vec::new()));
    let death = Arc::new(Death::new());
    let (requests, receive) = mpsc::channel::<driver::Request>(64);
    let (established, became_up) = oneshot::channel::<()>();

    let endpoint = device.endpoint;
    let driver = driver::Driver::new(
        &device,
        udp,
        Arc::clone(&socket_set),
        Arc::clone(&wake),
        Arc::clone(&retired),
        Arc::clone(&death),
        receive,
        established,
    );
    let join = tokio::spawn(driver.run());

    let stack = Stack {
        sockets: socket_set,
        requests,
        wake,
        retired,
        dead: death,
        endpoint,
    };

    if !matches!(
        tokio::time::timeout(HANDSHAKE_TIMEOUT, became_up).await,
        Ok(Ok(()))
    ) {
        join.abort();
        return Err(Error::Io(io::Error::new(
            io::ErrorKind::TimedOut,
            "the WireGuard handshake did not complete in time",
        )));
    }
    Ok((stack, join))
}

/// A live WARP tunnel — the cloneable handle the egress layer carries while it is up.
///
/// Clones share the one driver task; the tunnel dies when the driver exits.
#[derive(Clone)]
pub struct Stack {
    sockets: Arc<Mutex<SocketSet<'static>>>,
    requests: mpsc::Sender<driver::Request>,
    wake: Arc<Notify>,
    /// Handles the socket wrappers have released; the driver removes them from the set
    /// once their close has been emitted.
    retired: Arc<Mutex<Vec<SocketHandle>>>,
    /// The death notice shared by every socket this stack hands out.
    dead: Arc<Death>,
    endpoint: SocketAddrV4,
}

impl Stack {
    /// Where the tunnel's `WireGuard` datagrams go.
    pub fn endpoint(&self) -> SocketAddrV4 {
        self.endpoint
    }

    /// Whether the driver is still alive.
    fn check_alive(&self) -> io::Result<()> {
        self.dead.reason().map_or(Ok(()), |reason| {
            Err(io::Error::new(
                io::ErrorKind::ConnectionAborted,
                format!("the WARP tunnel is down: {reason}"),
            ))
        })
    }

    /// Opens a TCP stream through the tunnel.
    ///
    /// # Errors
    /// Fails when the destination refuses, the connect times out inside the tunnel, or
    /// the tunnel is down.
    pub async fn connect(&self, destination: SocketAddr) -> io::Result<Tcp> {
        self.check_alive()?;
        let (reply, receive) = oneshot::channel();
        self.requests
            .send(driver::Request::Connect {
                remote: IpEndpoint::from(destination),
                reply,
            })
            .await
            .map_err(|_| {
                io::Error::new(io::ErrorKind::ConnectionAborted, "the WARP tunnel is down")
            })?;
        self.wake.notify_one();
        let handle = receive.await.map_err(|_| {
            io::Error::new(io::ErrorKind::ConnectionAborted, "the WARP tunnel is down")
        })??;

        let tcp = Tcp::new(
            Arc::clone(&self.sockets),
            handle,
            Arc::clone(&self.wake),
            Arc::clone(&self.retired),
            Arc::clone(&self.dead),
        );
        tcp.established().await?;
        Ok(tcp)
    }

    /// Relays one DNS wire message through the tunnel over UDP and returns the answer.
    ///
    /// # Errors
    /// Fails when the resolver does not answer in time or the tunnel is down.
    pub async fn dns_exchange(&self, resolver: SocketAddrV4, query: &[u8]) -> io::Result<Vec<u8>> {
        self.check_alive()?;
        let udp = sockets::Udp::bind(
            Arc::clone(&self.sockets),
            Arc::clone(&self.wake),
            Arc::clone(&self.retired),
            Arc::clone(&self.dead),
        )?;
        udp.exchange(resolver, query).await
    }
}

/// The shared socket set's guard, recovered past poisoning: a panicking socket operation
/// must not strand the whole tunnel.
pub(super) fn socket_set<'a>(
    set: &'a Mutex<SocketSet<'static>>,
) -> MutexGuard<'a, SocketSet<'static>> {
    set.lock().unwrap_or_else(PoisonError::into_inner)
}
