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
    path::{Path, PathBuf},
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
    /// Route egress through the strongest anonymizing transport that can be raised —
    /// Tor first, WARP when Tor cannot be — and refuse connections while neither is
    /// up. A red team session's posture: it must never leak the machine's address.
    ///
    /// Not offered as an `--egress` value on the host: the composite is reached
    /// through `--redteam`, which gates it behind the authorization attestation.
    /// The gateway accepts it by name, because the session's machine is already
    /// past that gate by the time the flag is read.
    #[value(skip)]
    Redteam,
    /// Take every connection out directly; no tunnel is attempted.
    Direct,
}

impl Mode {
    /// The transports this mode wants, most preferred first.
    fn wants(self) -> &'static [TransportKind] {
        match self {
            Self::Auto | Self::Warp => &[TransportKind::Warp],
            Self::Tor => &[TransportKind::Tor],
            Self::Redteam => &[TransportKind::Tor, TransportKind::Warp],
            Self::Direct => &[],
        }
    }

    /// Whether a connection may go out directly when the wanted transport is down.
    ///
    /// Public because the host relies on the strict modes' `false`: it is the
    /// property provisioning verifies against the machine's own audit trail before
    /// a session opens, since the mode travels to the guest as a request it can
    /// silently fail to honour.
    #[must_use]
    pub fn permits_fallback(self) -> bool {
        matches!(self, Self::Auto | Self::Direct)
    }
}

impl std::fmt::Display for Mode {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::Auto => "auto",
            Self::Warp => "warp",
            Self::Tor => "tor",
            Self::Redteam => "redteam",
            Self::Direct => "direct",
        })
    }
}

/// A string that names no egress mode.
#[derive(Debug, thiserror::Error)]
#[error("`{0}` is not an egress mode; expected one of: auto, warp, tor, redteam, direct")]
pub struct NotAMode(String);

impl std::str::FromStr for Mode {
    type Err = NotAMode;

    /// Parses the name [`Display`](std::fmt::Display) writes, including the modes the
    /// host's `--egress` flag does not offer: the gateway takes the mode by name
    /// because the session record it reads it from was already settled.
    fn from_str(value: &str) -> Result<Self, Self::Err> {
        for mode in [
            Self::Auto,
            Self::Warp,
            Self::Tor,
            Self::Redteam,
            Self::Direct,
        ] {
            if mode.to_string() == value {
                return Ok(mode);
            }
        }
        Err(NotAMode(value.to_owned()))
    }
}

/// Which tunnel, when a mode wants one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TransportKind {
    Warp,
    Tor,
}

impl TransportKind {
    /// The transport's name in logs, matching the audit trail's route names.
    fn name(self) -> &'static str {
        match self {
            Self::Warp => "warp",
            Self::Tor => "tor",
        }
    }
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
        let wants = mode.wants();
        let (sender, link) = watch::channel(if wants.is_empty() {
            Link::Bare
        } else {
            Link::Connecting
        });
        let supervisor = if wants.is_empty() {
            None
        } else {
            Some(tokio::spawn(supervise(
                state_dir.to_path_buf(),
                resolver,
                sender,
                wants,
            )))
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

/// Raises transports in `preference` order, forever, publishing each verdict to `link`.
///
/// The list is walked from the top of every round: a composite mode whose fallback
/// transport dies goes back to its preferred one rather than camping on what is left.
/// A transport that raises but has no driver — Tor — keeps itself alive for as long
/// as the published handle is held, so publishing `Up` is the whole of its service.
async fn supervise(
    state_dir: PathBuf,
    resolver: SocketAddrV4,
    link: watch::Sender<Link>,
    preference: &'static [TransportKind],
) {
    let mut backoff = Duration::from_secs(5);
    let mut last_failure: Option<Arc<str>> = None;
    loop {
        for &kind in preference {
            let _ = link.send(match &last_failure {
                // A first attempt asks connections to wait; a retry must not — modes
                // that allow fallback keep going direct on the last verdict while
                // this runs.
                Some(reason) => Link::Retrying(Arc::clone(reason)),
                None => Link::Connecting,
            });
            match raise(kind, &state_dir, resolver).await {
                Ok((transport, driver)) => {
                    backoff = Duration::from_secs(5);
                    tracing::info!(transport = kind.name(), "the egress transport is up");
                    let _ = link.send(Link::Up(transport));
                    let Some(driver) = driver else { return };
                    match driver.await {
                        Ok(Ok(())) => {
                            tracing::info!(transport = kind.name(), "the egress transport closed");
                        }
                        Ok(Err(error)) => tracing::warn!(
                            transport = kind.name(),
                            %error,
                            "the egress transport died"
                        ),
                        Err(error) => tracing::warn!(
                            transport = kind.name(),
                            %error,
                            "the egress transport's driver failed"
                        ),
                    }
                    // Publish the death now, not after the backoff: the link still
                    // says `Up` otherwise, and the audit trail would show a route
                    // that is already refusing connections.
                    let reason: Arc<str> = Arc::from("the transport went down");
                    last_failure = Some(Arc::clone(&reason));
                    let _ = link.send(Link::Unavailable(reason));
                    break;
                }
                Err(reason) => {
                    tracing::warn!(
                        transport = kind.name(),
                        %reason,
                        "the egress transport is unavailable"
                    );
                    last_failure = Some(Arc::clone(&reason));
                    let _ = link.send(Link::Unavailable(reason));
                }
            }
        }
        tokio::time::sleep(backoff).await;
        backoff = (backoff * 2).min(Duration::from_secs(60));
    }
}

/// Raises one transport kind. The returned task, when the kind has one, is the
/// transport's lifetime: its exit means the transport died and must be re-raised.
#[cfg_attr(
    not(any(feature = "warp", feature = "tor")),
    allow(clippy::unused_async)
)]
async fn raise(
    kind: TransportKind,
    state_dir: &Path,
    resolver: SocketAddrV4,
) -> Result<(Transport, Option<JoinHandle<io::Result<()>>>), Arc<str>> {
    match kind {
        #[cfg(feature = "warp")]
        TransportKind::Warp => warp::establish(state_dir, resolver)
            .await
            .map(|(stack, driver)| (Transport::Warp(stack), Some(driver)))
            .map_err(|error| Arc::from(error.to_string())),
        #[cfg(feature = "tor")]
        TransportKind::Tor => tor::establish(state_dir)
            .await
            .map(|tor| (Transport::Tor(tor), None))
            .map_err(|error| Arc::from(error.to_string())),
        // A kind whose feature is off reports as unavailable rather than unreachable:
        // a mode may list it and still be asked to run on a build without it.
        #[allow(unreachable_patterns)]
        _ => {
            let _ = (state_dir, resolver);
            Err(Arc::from("the transport is not compiled in"))
        }
    }
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
            ("redteam", Mode::Redteam),
            ("direct", Mode::Direct),
        ] {
            assert_eq!(mode.to_string(), name);
            assert_eq!(serde_json::to_string(&mode).unwrap(), format!("\"{name}\""));
            assert_eq!(
                name.parse::<Mode>().unwrap(),
                mode,
                "the gateway parses the mode by the name the record and trail write"
            );
        }
        assert!("cloudflare".parse::<Mode>().is_err());
    }

    #[test]
    fn the_host_flag_does_not_offer_the_gated_mode() {
        use clap::ValueEnum as _;
        assert!(
            Mode::value_variants()
                .iter()
                .all(|mode| *mode != Mode::Redteam),
            "`redteam` is reached through `--redteam`, which gates it behind the \
             attestation — it is not a value `--egress` can be handed"
        );
    }

    #[test]
    fn redteam_prefers_tor_and_never_falls_back_to_direct() {
        assert_eq!(
            Mode::Redteam.wants(),
            &[TransportKind::Tor, TransportKind::Warp],
            "Tor is tried before WARP, every round"
        );
        assert!(
            !Mode::Redteam.permits_fallback(),
            "a red team session must never leak the machine's own address"
        );
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
        assert_eq!(
            route_of(&Link::Unavailable(Arc::clone(&reason)), Mode::Redteam).0,
            Route::Down,
            "redteam is strict: an unavailable transport is silence, never a direct leak"
        );
        assert_eq!(route_of(&Link::Connecting, Mode::Auto).0, Route::Down);
        assert_eq!(route_of(&Link::Bare, Mode::Direct).0, Route::Direct);
    }
}
