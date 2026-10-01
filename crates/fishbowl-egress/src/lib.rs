//! The transports a fishbowl session's audited egress rides on.
//!
//! The gateway audits every byte either way; this crate decides which network carries the
//! gateway's half of the conversation — a Cloudflare WARP tunnel, the Tor network, or the
//! plain internet — and what happens when the tunnel asked for cannot be raised. Both
//! transports live inside the gateway's own process: the packet filter only ever sees the
//! gateway's own outbound UDP and TCP, so no rule changes when the egress path does.
//!
//! Destinations that cannot be anonymized — loopback, link-local, private and shared
//! address space — never enter either transport: a tunnel that ends inside Cloudflare or
//! a Tor exit cannot reach a LAN, so those connections always go direct, in every mode.

#[cfg(feature = "tor")]
mod tor;
#[cfg(feature = "warp")]
mod warp;

use std::{
    io,
    net::{IpAddr, SocketAddr, SocketAddrV4},
    path::Path,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
    time::Duration,
};

use tokio::{
    io::{AsyncRead, AsyncWrite, ReadBuf},
    net::TcpStream,
    sync::watch,
    task::JoinHandle,
};

/// What a session's upstream traffic is asked to ride on.
///
/// The mode settles a question of policy, not mechanics: `auto` and `warp` both build the
/// same tunnel and differ only in what an unavailable tunnel does to a connection that
/// wants one.
#[derive(
    Debug,
    Clone,
    Copy,
    Default,
    PartialEq,
    Eq,
    clap::ValueEnum,
    serde::Serialize,
    serde::Deserialize,
)]
#[serde(rename_all = "lowercase")]
pub enum Mode {
    /// Route egress through Cloudflare WARP when the tunnel can be established, and fall
    /// back to direct egress when it cannot.
    #[default]
    Auto,
    /// Route egress through Cloudflare WARP, and refuse connections while the tunnel is
    /// unavailable — the failure mode is silence, never unaudited plaintext egress with
    /// the machine's real address.
    Warp,
    /// Route egress through the Tor network, and refuse connections while it is
    /// unavailable.
    Tor,
    /// Take every connection out directly; no tunnel is attempted.
    Direct,
}

impl Mode {
    /// The tunnel this mode wants, if it wants one.
    fn wants(self) -> Option<TransportKind> {
        match self {
            Self::Auto | Self::Warp => Some(TransportKind::Warp),
            Self::Tor => Some(TransportKind::Tor),
            Self::Direct => None,
        }
    }

    /// Whether a connection may go out directly when the wanted transport is down.
    fn permits_fallback(self) -> bool {
        matches!(self, Self::Auto | Self::Direct)
    }
}

impl std::fmt::Display for Mode {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::Auto => "auto",
            Self::Warp => "warp",
            Self::Tor => "tor",
            Self::Direct => "direct",
        })
    }
}

/// Which tunnel, when a mode wants one.
#[derive(Debug, Clone, Copy)]
enum TransportKind {
    Warp,
    Tor,
}

/// What a connection opened right now would go over.
///
/// This is the egress layer's own vocabulary; the audit trail renders the same four
/// states into its own format.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Route {
    /// A Cloudflare WARP tunnel is carrying upstream traffic.
    Warp,
    /// The Tor network is carrying upstream traffic.
    Tor,
    /// Upstream traffic leaves directly.
    Direct,
    /// Nothing is carrying upstream traffic: the mode demands a tunnel and none is up.
    Down,
}

impl std::fmt::Display for Route {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::Warp => "warp",
            Self::Tor => "tor",
            Self::Direct => "direct",
            Self::Down => "down",
        })
    }
}

/// The supervisor's report on the wanted transport.
// Without a transport compiled in, only `Bare` is ever constructed.
#[cfg_attr(not(any(feature = "warp", feature = "tor")), allow(dead_code))]
enum Link {
    /// The first attempt to raise the transport is in flight; no verdict yet.
    Connecting,
    /// A later attempt is in flight; carries the last failure so `auto` can keep going
    /// direct without waiting on retries it does not need.
    Retrying(Arc<str>),
    /// The transport is up and carrying connections.
    Up(Transport),
    /// The last attempt failed; the reason is kept for the audit trail.
    Unavailable(Arc<str>),
    /// The mode wants no transport; every connection goes out directly.
    Bare,
}

/// A raised tunnel, usable by however many connections it is carrying.
///
/// The transports are feature-gated: the host CLI compiles this crate without either
/// so it can speak of modes without building a tunnel.
#[derive(Clone)]
enum Transport {
    /// A userspace `WireGuard` tunnel to Cloudflare `WARP`.
    #[cfg(feature = "warp")]
    Warp(warp::Stack),
    /// A bootstrapped Arti client.
    #[cfg(feature = "tor")]
    Tor(tor::Tor),
}

impl Transport {
    /// The route this transport gives a connection.
    fn route(&self) -> Route {
        match self {
            #[cfg(feature = "warp")]
            Self::Warp(_) => Route::Warp,
            #[cfg(feature = "tor")]
            Self::Tor(_) => Route::Tor,
            // A `&Transport` is inhabited to the compiler even when the enum is empty.
            #[allow(unreachable_patterns)]
            _ => unreachable!("a transport was raised with no transport compiled in"),
        }
    }

    /// Opens a stream through the tunnel to `destination`.
    // With no transport compiled in the match body never `.await`s, but the method must
    // stay async: it is the same signature the transports' callers hold.
    #[cfg_attr(
        not(any(feature = "warp", feature = "tor")),
        allow(clippy::unused_async, clippy::unused_async_trait_impl)
    )]
    async fn connect(&self, destination: SocketAddr) -> io::Result<Upstream> {
        match self {
            #[cfg(feature = "warp")]
            Self::Warp(stack) => stack.connect(destination).await.map(Upstream::Warp),
            #[cfg(feature = "tor")]
            Self::Tor(tor) => tor
                .connect(destination)
                .await
                .map(|stream| Upstream::Tor(Box::new(stream))),
            // A `&Transport` is inhabited to the compiler even when the enum is empty.
            #[allow(unreachable_patterns)]
            _ => {
                let _ = destination;
                unreachable!("a transport was raised with no transport compiled in")
            }
        }
    }

    /// Sends one DNS wire message to `resolver` through the tunnel and returns the
    /// answer.
    // See `connect` for why the signature stays async with no transports compiled in.
    #[cfg_attr(
        not(any(feature = "warp", feature = "tor")),
        allow(clippy::unused_async, clippy::unused_async_trait_impl)
    )]
    async fn dns_exchange(&self, resolver: SocketAddrV4, query: &[u8]) -> io::Result<Vec<u8>> {
        match self {
            #[cfg(feature = "warp")]
            Self::Warp(stack) => stack.dns_exchange(resolver, query).await,
            #[cfg(feature = "tor")]
            Self::Tor(tor) => tor.dns_exchange(resolver, query).await,
            #[allow(unreachable_patterns)]
            _ => {
                let _ = (resolver, query);
                unreachable!("a transport was raised with no transport compiled in")
            }
        }
    }
}

/// A connection the gateway opened upstream, on whichever transport was in effect.
pub enum Upstream {
    /// A direct connection.
    Direct(TcpStream),
    /// A connection through the WARP tunnel.
    #[cfg(feature = "warp")]
    Warp(warp::Tcp),
    /// A connection through the Tor network — boxed: Arti's stream is large enough
    /// to dwarf the other variants.
    #[cfg(feature = "tor")]
    Tor(Box<arti_client::DataStream>),
}

impl AsyncRead for Upstream {
    fn poll_read(
        self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        match self.get_mut() {
            Self::Direct(stream) => Pin::new(stream).poll_read(context, buf),
            #[cfg(feature = "warp")]
            Self::Warp(stream) => Pin::new(stream).poll_read(context, buf),
            #[cfg(feature = "tor")]
            Self::Tor(stream) => Pin::new(stream).poll_read(context, buf),
        }
    }
}

impl AsyncWrite for Upstream {
    fn poll_write(
        self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        match self.get_mut() {
            Self::Direct(stream) => Pin::new(stream).poll_write(context, buf),
            #[cfg(feature = "warp")]
            Self::Warp(stream) => Pin::new(stream).poll_write(context, buf),
            #[cfg(feature = "tor")]
            Self::Tor(stream) => Pin::new(stream).poll_write(context, buf),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.get_mut() {
            Self::Direct(stream) => Pin::new(stream).poll_flush(context),
            #[cfg(feature = "warp")]
            Self::Warp(stream) => Pin::new(stream).poll_flush(context),
            #[cfg(feature = "tor")]
            Self::Tor(stream) => Pin::new(stream).poll_flush(context),
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.get_mut() {
            Self::Direct(stream) => Pin::new(stream).poll_shutdown(context),
            #[cfg(feature = "warp")]
            Self::Warp(stream) => Pin::new(stream).poll_shutdown(context),
            #[cfg(feature = "tor")]
            Self::Tor(stream) => Pin::new(stream).poll_shutdown(context),
        }
    }
}

/// The egress layer of one sandbox: the mode it was given and whatever transport the
/// supervisor has managed to raise for it.
///
/// Connections do not consult the supervisor themselves — [`Self::connect`] resolves the
/// state the supervisor last published and waits out a first in-flight attempt, so a
/// tunnel that takes a moment to raise holds connections briefly rather than leaking
/// them direct.
pub struct Egress {
    mode: Mode,
    link: watch::Receiver<Link>,
    /// Keeps the supervisor alive; dropping the egress layer drops the tunnel with it.
    /// The handle is never awaited: the supervisor only stops when this does.
    #[allow(dead_code)]
    supervisor: Option<JoinHandle<()>>,
}

/// How long a connection waits for a transport attempt to succeed or fail before the
/// mode's fallback decides. Attempts time out on their own sooner than this; the bound
/// exists so a wedged supervisor cannot hang a connection forever.
const TRANSPORT_GRACE: Duration = Duration::from_secs(60);

impl Egress {
    /// Starts the egress layer for `mode`.
    ///
    /// `state_dir` is where the transports keep what must survive a gateway restart: the
    /// WARP device registration and Tor's consensus cache. `resolver` is the DNS server
    /// bootstrap traffic uses — the WARP API's name has to resolve before the tunnel
    /// exists, so it is resolved directly rather than through any transport.
    #[must_use]
    pub fn start(mode: Mode, state_dir: &Path, resolver: SocketAddrV4) -> Self {
        let (sender, link) = watch::channel(match mode.wants() {
            Some(_) => Link::Connecting,
            None => Link::Bare,
        });
        let supervisor = match mode.wants() {
            None => None,
            Some(TransportKind::Warp) => Some(spawn_warp(state_dir, resolver, sender)),
            Some(TransportKind::Tor) => Some(spawn_tor(state_dir, sender)),
        };
        Self {
            mode,
            link,
            supervisor,
        }
    }

    /// The egress route as the audit trail should report it, and a stream of its changes.
    ///
    /// Attempts are folded into the verdict they leave: for `auto` a failed attempt reads
    /// as `direct`, for a strict mode as `down`, and an in-flight attempt as `down` too —
    /// nothing is flowing until it resolves.
    #[must_use]
    pub fn routes(&self) -> Routes {
        Routes {
            link: self.link.clone(),
            mode: self.mode,
        }
    }

    /// Opens a connection to `destination` on the route `mode` currently allows.
    ///
    /// # Errors
    /// Fails when the destination cannot be reached, or when the mode demands a tunnel
    /// and none could be raised.
    pub async fn connect(&self, destination: SocketAddr) -> io::Result<Upstream> {
        if !is_public(destination.ip()) {
            return TcpStream::connect(destination).await.map(Upstream::Direct);
        }
        match self.transport().await {
            Verdict::Up(transport) => transport.connect(destination).await,
            Verdict::Unavailable(reason) if self.mode.permits_fallback() => {
                tracing::debug!(%destination, %reason, "egress tunnel is unavailable; going direct");
                TcpStream::connect(destination).await.map(Upstream::Direct)
            }
            Verdict::Unavailable(reason) => Err(io::Error::new(
                io::ErrorKind::ConnectionAborted,
                format!("{} egress is unavailable: {reason}", self.mode),
            )),
        }
    }

    /// Relays one DNS wire message to `resolver` on the current route.
    ///
    /// The message crosses whatever connections cross: a tunnel carries queries just as
    /// it carries streams, because a query that went around the tunnel would name the
    /// machine it came from.
    ///
    /// # Errors
    /// Fails when the resolver does not answer or the required transport is down.
    pub async fn dns_exchange(&self, resolver: SocketAddrV4, query: &[u8]) -> io::Result<Vec<u8>> {
        if !is_public((*resolver.ip()).into()) {
            return direct_dns(resolver, query).await;
        }
        match self.transport().await {
            Verdict::Up(transport) => transport.dns_exchange(resolver, query).await,
            Verdict::Unavailable(reason) if self.mode.permits_fallback() => {
                tracing::debug!(%resolver, %reason, "egress tunnel is unavailable; DNS goes direct");
                direct_dns(resolver, query).await
            }
            Verdict::Unavailable(reason) => Err(io::Error::new(
                io::ErrorKind::ConnectionAborted,
                format!("{} egress is unavailable: {reason}", self.mode),
            )),
        }
    }

    /// The transport the supervisor currently offers, waiting out an in-flight attempt.
    ///
    /// A *retrying* supervisor does not hold connections in a mode that permits
    /// fallback: the last verdict stands until the retry overturns it.
    async fn transport(&self) -> Verdict {
        /// One read of the link, reduced to what the wait loop does with it.
        enum Now {
            /// A verdict is in.
            Done(Verdict),
            /// The link's last failure reason, to hand out if the wait ends badly.
            Pending(Option<Arc<str>>),
        }

        let mut link = self.link.clone();
        let waited = tokio::time::timeout(TRANSPORT_GRACE, async {
            loop {
                // The Ref must be dropped before `changed()` can borrow the receiver
                // again — so each pass reads the state into `Now` first.
                let now = match &*link.borrow_and_update() {
                    Link::Connecting => Now::Pending(None),
                    Link::Retrying(reason) => Now::Pending(Some(reason.clone())),
                    Link::Up(transport) => Now::Done(Verdict::Up(transport.clone())),
                    Link::Unavailable(reason) => Now::Done(Verdict::Unavailable(reason.clone())),
                    Link::Bare => Now::Done(Verdict::Unavailable(Arc::from(
                        "no transport is configured",
                    ))),
                };
                match now {
                    Now::Done(verdict) => return verdict,
                    // A retry in flight cannot hold a connection that may go direct.
                    Now::Pending(Some(reason)) if self.mode.permits_fallback() => {
                        return Verdict::Unavailable(reason);
                    }
                    Now::Pending(reason) => {
                        if link.changed().await.is_err() {
                            return Verdict::Unavailable(
                                reason
                                    .unwrap_or_else(|| Arc::from("the egress supervisor stopped")),
                            );
                        }
                    }
                }
            }
        })
        .await;
        waited.unwrap_or_else(|_| {
            Verdict::Unavailable(Arc::from("the egress transport did not come up in time"))
        })
    }
}

enum Verdict {
    Up(Transport),
    Unavailable(Arc<str>),
}

/// What a link state means for traffic, under a mode.
fn route_of(link: &Link, mode: Mode) -> (Route, Option<Arc<str>>) {
    match link {
        Link::Connecting => (Route::Down, None),
        Link::Up(transport) => (transport.route(), None),
        Link::Bare => (Route::Direct, None),
        Link::Unavailable(reason) | Link::Retrying(reason) => (
            if mode.permits_fallback() {
                Route::Direct
            } else {
                Route::Down
            },
            Some(Arc::clone(reason)),
        ),
    }
}

/// The egress route over time, for the audit trail.
///
/// Emits once per meaningful change — a strict-mode outage followed by the next attempt
/// does not repeat `down`, because nothing about the carried route changed.
pub struct Routes {
    link: watch::Receiver<Link>,
    mode: Mode,
}

impl Routes {
    /// The route right now and, on `auto` or strict failure, why it is that one.
    pub fn current(&mut self) -> (Route, Option<Arc<str>>) {
        route_of(&self.link.borrow_and_update(), self.mode)
    }

    /// The next change in the carried route, or `None` once the egress layer is gone.
    pub async fn changed(&mut self) -> Option<(Route, Option<Arc<str>>)> {
        let previous = self.current().0;
        loop {
            if self.link.changed().await.is_err() {
                return None;
            }
            let (route, reason) = self.current();
            if route != previous {
                return Some((route, reason));
            }
        }
    }
}

/// One DNS wire exchange over a plain UDP socket — the direct path's resolver traffic.
/// The socket is connected so only the resolver's datagrams are received.
async fn direct_dns(resolver: SocketAddrV4, query: &[u8]) -> io::Result<Vec<u8>> {
    let socket = tokio::net::UdpSocket::bind((std::net::Ipv4Addr::UNSPECIFIED, 0)).await?;
    socket.connect(resolver).await?;
    socket.send(query).await?;
    let mut answer = vec![0_u8; 4096];
    let length = socket.recv(&mut answer).await?;
    answer.truncate(length);
    Ok(answer)
}

#[cfg(feature = "warp")]
fn spawn_warp(
    state_dir: &Path,
    resolver: SocketAddrV4,
    link: watch::Sender<Link>,
) -> JoinHandle<()> {
    tokio::spawn(warp::supervise(state_dir.to_path_buf(), resolver, link))
}

#[cfg(not(feature = "warp"))]
fn spawn_warp(
    _state_dir: &Path,
    _resolver: SocketAddrV4,
    _link: watch::Sender<Link>,
) -> JoinHandle<()> {
    unreachable!("the `warp` transport is not compiled in")
}

#[cfg(feature = "tor")]
fn spawn_tor(state_dir: &Path, link: watch::Sender<Link>) -> JoinHandle<()> {
    tokio::spawn(tor::supervise(state_dir.to_path_buf(), link))
}

#[cfg(not(feature = "tor"))]
fn spawn_tor(_state_dir: &Path, _link: watch::Sender<Link>) -> JoinHandle<()> {
    unreachable!("the `tor` transport is not compiled in")
}

/// Whether `ip` names a destination a tunnel could carry.
///
/// Private, link-local, loopback, documentation and shared address space can only ever
/// be reached directly — WARP exits inside Cloudflare and Tor exits on the public
/// internet, so routing these destinations into a tunnel would merely be a slower way
/// to fail.
fn is_public(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(address) => {
            let octets = address.octets();
            !(address.is_private()
                || address.is_loopback()
                || address.is_link_local()
                || address.is_multicast()
                || address.is_broadcast()
                || address.is_unspecified()
                // 0.0.0.0/8 — this network.
                || octets[0] == 0
                // 100.64.0.0/10 — carrier-grade NAT, unreachable through a tunnel.
                || (octets[0] == 100 && (octets[1] & 0xC0) == 0x40)
                // 192.0.0.0/24 — IETF protocol assignments.
                || (octets[0] == 192 && octets[1] == 0 && octets[2] == 0)
                // Documentation ranges.
                || matches!(
                    octets,
                    [192, 0, 2, _] | [198, 51, 100, _] | [203, 0, 113, _]
                )
                // 198.18.0.0/15 — benchmarking.
                || (octets[0] == 198 && (octets[1] & 0xFE) == 18)
                // 240.0.0.0/4 — reserved.
                || octets[0] >= 240)
        }
        IpAddr::V6(address) => {
            !(address.is_loopback()
                || address.is_multicast()
                || address.is_unspecified()
                || address.is_unicast_link_local()
                || address.is_unique_local()
                // 2001:db8::/32 — documentation.
                || (address.segments()[0] == 0x2001 && address.segments()[1] == 0x0db8))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn the_mode_names_match_what_the_cli_and_the_trail_speak() {
        for (name, mode) in [
            ("auto", Mode::Auto),
            ("warp", Mode::Warp),
            ("tor", Mode::Tor),
            ("direct", Mode::Direct),
        ] {
            assert_eq!(mode.to_string(), name);
            assert_eq!(serde_json::to_string(&mode).unwrap(), format!("\"{name}\""));
        }
    }

    #[test]
    fn destinations_a_tunnel_cannot_carry_are_never_tunneled() {
        for address in [
            Ipv4Addr::new(10, 1, 2, 3),
            Ipv4Addr::LOCALHOST,
            Ipv4Addr::new(169, 254, 1, 1),
            Ipv4Addr::new(100, 64, 1, 1),
            Ipv4Addr::new(198, 18, 0, 1),
            Ipv4Addr::new(192, 0, 2, 1),
            Ipv4Addr::new(240, 1, 2, 3),
            Ipv4Addr::BROADCAST,
        ] {
            assert!(!is_public(address.into()), "{address} must not be tunneled");
        }
        for address in [Ipv4Addr::new(1, 1, 1, 1), Ipv4Addr::new(162, 159, 192, 8)] {
            assert!(
                is_public(address.into()),
                "{address} belongs on a transport"
            );
        }
    }

    #[test]
    fn a_failing_transport_is_direct_under_auto_and_down_under_strict() {
        let reason: Arc<str> = Arc::from("no wireguard handshake");
        assert_eq!(
            route_of(&Link::Unavailable(Arc::clone(&reason)), Mode::Auto).0,
            Route::Direct
        );
        assert_eq!(
            route_of(&Link::Retrying(Arc::clone(&reason)), Mode::Auto).0,
            Route::Direct
        );
        assert_eq!(
            route_of(&Link::Unavailable(Arc::clone(&reason)), Mode::Warp).0,
            Route::Down
        );
        assert_eq!(
            route_of(&Link::Retrying(Arc::clone(&reason)), Mode::Tor).0,
            Route::Down
        );
        assert_eq!(route_of(&Link::Connecting, Mode::Auto).0, Route::Down);
        assert_eq!(route_of(&Link::Bare, Mode::Direct).0, Route::Direct);
    }
}
