//! The transparent UDP relay.
//!
//! Non-DNS datagrams reach this socket through `TPROXY`, not NAT: a mangle rule
//! marks them and a policy route hands them to the loopback stack, where this
//! listener — bound `IP_TRANSPARENT` — picks them up with the destination they
//! were written to. TPROXY rather than `REDIRECT` because there is no
//! translation to collide over: conntrack's reply tuple stays one per remote,
//! where a DNAT to a single port would give every flow sharing a client's
//! source port the identical reply tuple and netfilter would drop all but the
//! first before a datagram ever arrived here — a transparent proxy may not be
//! one that loses flows it never saw.
//!
//! The `*ORIGDSTADDR` control message on `recvmsg` names the remote each
//! datagram was aimed at, a session table holds one upstream socket per flow,
//! and replies leave through a per-session socket bound to that remote's
//! address — `IP_TRANSPARENT` again, which is what lets a socket claim a source
//! that is not local — so the client sees an ordinary answer from the peer it
//! dialled.
//!
//! A leg that cannot carry datagrams — `tor` as the mode, or the `torsion` uid
//! under any mode — is refused by the packet filter rather than arriving here,
//! which is what the client feels as an ICMP error. A refusal that arrives
//! anyway, because transport state races the policy, is recorded, not silenced.

use std::{
    collections::HashMap,
    io,
    net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6},
    os::fd::AsRawFd,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    time::{Duration, Instant},
};

use fishbowl_audit::{AuditEvent, BlockReason, Blocked, Connect, Endpoint, Transport};
use fishbowl_egress::{Egress, Leg, UdpUpstream};
use nix::libc;
use nix::sys::socket::{
    AddressFamily, ControlMessageOwned, MsgFlags, SockFlag, SockType, SockaddrStorage, recvmsg,
    setsockopt, sockopt,
};
use tokio::io::unix::AsyncFd;

use crate::{
    audit::AuditSink,
    error::{GatewayError, Result},
    peer::{Udp, owner_of},
};

/// The largest datagram the relay buffers — the UDP maximum minus its headers.
const MAX_DATAGRAM: usize = 65_507;

/// How long a silent flow keeps its upstream session before being reaped.
///
/// UDP has no close, so silence is the only signal — a minute idle is generous
/// for a relayed flow and still bounds what a forgotten port scan would leave
/// behind.
const SESSION_IDLE: Duration = Duration::from_secs(60);

/// How often the table is swept for sessions past [`SESSION_IDLE`].
const SWEEP_INTERVAL: Duration = Duration::from_secs(15);

/// The most flows held open at once. A sweep of `nmap -sU` opens one flow per
/// port probe and the ceiling is what bounds that, not the cost of a session.
const SESSIONS_MAX: usize = 1024;

/// The sessions shared between the listeners, their pumps and the sweeper.
type Table = Arc<tokio::sync::Mutex<HashMap<Flow, Session>>>;

/// Relays transparently proxied datagrams until a listening socket fails.
///
/// Binds one listener per address family — `127.0.0.1` for IPv4, `::1` for
/// IPv6 — sharing the one session table, since a flow's identity is its client
/// and remote, not the family it arrived on.
///
/// # Errors
/// Fails when a listening socket cannot be bound or breaks; a failure on one
/// datagram or session is recorded and the loop continues.
pub async fn serve(
    port: u16,
    egress: Arc<Egress>,
    sink: AuditSink,
    torsion_uid: u32,
) -> Result<()> {
    let table: Table = Arc::new(tokio::sync::Mutex::new(HashMap::new()));
    let sweeper = {
        let table = Arc::clone(&table);
        let sink = sink.clone();
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(SWEEP_INTERVAL).await;
                let closed = sweep(&mut *table.lock().await);
                for (flow, session) in closed {
                    record(&sink, flow, &session).await;
                }
            }
        })
    };

    let mut tasks = tokio::task::JoinSet::new();
    for address in [
        SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, port)),
        SocketAddr::V6(SocketAddrV6::new(Ipv6Addr::LOCALHOST, port, 0, 0)),
    ] {
        let listener = Arc::new(Listener::bind(address)?);
        tasks.spawn(relay_loop(
            listener,
            Arc::clone(&table),
            Arc::clone(&egress),
            sink.clone(),
            torsion_uid,
        ));
    }
    // A listener task only ends on a socket error; any one dying is serve's error.
    let result = match tasks.join_next().await {
        Some(outcome) => outcome
            .map_err(|source| GatewayError::Socket {
                context: "joining a UDP listener",
                source: io::Error::other(source.to_string()),
            })
            .and_then(|result| result),
        None => unreachable!("the listener set is never empty"),
    };
    sweeper.abort();
    result
}

/// Creates a datagram socket allowed to claim an address that is not local —
/// both what `TPROXY` delivers to and what a reply socket spoofs a source with.
fn transparent_socket(address: &SocketAddr) -> Result<std::net::UdpSocket> {
    let fd = nix::sys::socket::socket(
        match address {
            SocketAddr::V4(_) => AddressFamily::Inet,
            SocketAddr::V6(_) => AddressFamily::Inet6,
        },
        SockType::Datagram,
        SockFlag::SOCK_NONBLOCK | SockFlag::SOCK_CLOEXEC,
        None,
    )
    .map_err(socket_error("creating a transparent socket"))?;
    setsockopt(&fd, sockopt::ReuseAddr, &true)
        .map_err(socket_error("sharing a transparent socket's address"))?;
    match address {
        SocketAddr::V4(_) => setsockopt(&fd, sockopt::IpTransparent, &true)
            .map_err(socket_error("arming transparent proxying"))?,
        SocketAddr::V6(_) => setsockopt(&fd, Ipv6Transparent, &true)
            .map_err(socket_error("arming IPv6 transparent proxying"))?,
    }
    nix::sys::socket::bind(fd.as_raw_fd(), &SockaddrStorage::from(*address))
        .map_err(socket_error("binding a transparent socket"))?;
    Ok(std::net::UdpSocket::from(fd))
}

/// `IPV6_TRANSPARENT`, which nix does not wrap — declared through nix's own
/// sockopt helper, so the unsafe stays inside nix where it belongs.
#[derive(Clone)]
struct Ipv6Transparent;
nix::setsockopt_impl!(
    Ipv6Transparent,
    nix::libc::IPPROTO_IPV6,
    nix::libc::IPV6_TRANSPARENT,
    bool,
    nix::sys::socket::sockopt::SetBool
);

/// Turns a nix errno into a gateway socket error under `context`.
fn socket_error(context: &'static str) -> impl Fn(nix::errno::Errno) -> GatewayError {
    move |errno| GatewayError::Socket {
        context,
        source: io::Error::from_raw_os_error(errno as i32),
    }
}

/// Sends `data` to `to` on a nonblocking datagram socket, waiting out a full
/// send queue.
async fn send(
    socket: &AsyncFd<std::net::UdpSocket>,
    data: &[u8],
    to: SocketAddr,
) -> io::Result<()> {
    loop {
        let mut guard = socket.writable().await?;
        match guard.try_io(|fd| fd.get_ref().send_to(data, to).map(|_| ())) {
            Ok(result) => return result,
            Err(_would_block) => {}
        }
    }
}

/// One bound relay socket with its original-destination control message armed.
struct Listener {
    socket: AsyncFd<std::net::UdpSocket>,
}

impl Listener {
    /// Binds a transparent socket and arms the original-destination control
    /// message on it — `TPROXY` delivers to transparent sockets only.
    ///
    /// # Errors
    /// Fails when the socket cannot be created or armed.
    fn bind(address: SocketAddr) -> Result<Self> {
        let socket = transparent_socket(&address)?;
        match address {
            SocketAddr::V4(_) => setsockopt(&socket, sockopt::Ipv4OrigDstAddr, &true).map_err(
                socket_error("arming the original-destination control message"),
            )?,
            SocketAddr::V6(_) => setsockopt(&socket, sockopt::Ipv6OrigDstAddr, &true).map_err(
                socket_error("arming the original-destination control message"),
            )?,
        }
        Ok(Self {
            socket: AsyncFd::new(socket).map_err(|source| GatewayError::Socket {
                context: "registering the relay socket for polling",
                source,
            })?,
        })
    }

    /// Reads one datagram and the destination it was aimed at.
    ///
    /// Returns `Ok(None)` for a datagram whose destination could not be told —
    /// there is nothing to relay to, so it is nobody's business.
    ///
    /// # Errors
    /// Fails when the socket itself breaks.
    async fn recv(&self, buffer: &mut [u8]) -> io::Result<Option<Datagram>> {
        // The control buffer and the iovec outlive the `RecvMsg` that parses them:
        // nix hands back pointers into both allocations, so they are created here
        // rather than inside the closure that performs the call.
        let mut space = nix::cmsg_space!(nix::libc::sockaddr_in6);
        let mut iov = [io::IoSliceMut::new(&mut *buffer)];
        loop {
            let mut guard = self.socket.readable().await?;
            let outcome = guard.try_io(|fd| {
                recvmsg::<SockaddrStorage>(
                    fd.get_ref().as_raw_fd(),
                    &mut iov,
                    Some(space.as_mut_slice()),
                    MsgFlags::empty(),
                )
                .map_err(|errno| io::Error::from_raw_os_error(errno as i32))
            });
            let message = match outcome {
                Ok(Ok(message)) => message,
                Ok(Err(error)) => return Err(error),
                Err(_would_block) => continue,
            };
            let intended = match message.cmsgs() {
                Ok(mut cmsgs) => cmsgs.find_map(|control| match control {
                    ControlMessageOwned::Ipv4OrigDstAddr(address) => {
                        Some(SocketAddr::V4(SocketAddrV4::new(
                            Ipv4Addr::from(u32::from_be(address.sin_addr.s_addr)),
                            u16::from_be(address.sin_port),
                        )))
                    }
                    ControlMessageOwned::Ipv6OrigDstAddr(address) => {
                        Some(SocketAddr::V6(SocketAddrV6::new(
                            Ipv6Addr::from(address.sin6_addr.s6_addr),
                            u16::from_be(address.sin6_port),
                            u32::from_be(address.sin6_flowinfo),
                            address.sin6_scope_id,
                        )))
                    }
                    _ => None,
                }),
                Err(_) => None,
            };
            let client = message.address.as_ref().and_then(socket_addr);
            return Ok(match (intended, client) {
                (Some(remote), Some(client)) => Some(Datagram {
                    client,
                    remote,
                    length: message.bytes,
                }),
                _ => None,
            });
        }
    }
}

/// One session's answer socket, bound to the remote the client dialled.
///
/// A reply through the listening socket would leave with the relay's address,
/// which is nobody the client wrote to — under TPROXY nothing rewrites the
/// source on the way back, because nothing rewrote the destination on the way
/// in. This socket is bound to the remote's own address instead, which
/// `IP_TRANSPARENT` permits despite it not being local: the answer arrives from
/// exactly the peer the client expected, and conntrack counts it against the
/// flow's real reply tuple.
struct Reply {
    socket: AsyncFd<std::net::UdpSocket>,
}

impl Reply {
    /// Binds a transparent socket to `remote` — the address this session's
    /// answers will carry.
    ///
    /// # Errors
    /// Fails when the socket cannot be created or bound.
    fn bind(remote: SocketAddr) -> Result<Self> {
        Ok(Self {
            socket: AsyncFd::new(transparent_socket(&remote)?).map_err(|source| {
                GatewayError::Socket {
                    context: "registering a reply socket for polling",
                    source,
                }
            })?,
        })
    }

    /// Sends `data` to the flow's client, from the address it dialled.
    ///
    /// # Errors
    /// Fails when the socket breaks; a full send queue waits and retries.
    async fn send_to(&self, client: SocketAddr, data: &[u8]) -> io::Result<()> {
        send(&self.socket, data, client).await
    }
}

/// One received datagram: who sent it, where it was meant, how much arrived.
struct Datagram {
    /// The client inside the sandbox.
    client: SocketAddr,
    /// The destination the client addressed.
    remote: SocketAddr,
    /// How many bytes of the read buffer the datagram filled.
    length: usize,
}

/// A flow's key in the session table: the client inside and the remote outside.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct Flow {
    /// The sandbox socket the datagrams come from.
    client: SocketAddr,
    /// The destination they were aimed at.
    remote: SocketAddr,
}

/// One live UDP session: the upstream socket and the bookkeeping the trail needs.
struct Session {
    /// The transport's connected datagram socket.
    upstream: Arc<UdpUpstream>,
    /// The task forwarding remote datagrams back to the client.
    pump: tokio::task::AbortHandle,
    /// When the flow last moved a packet in either direction.
    touched: Instant,
    /// When the session was opened, for the volume record's elapsed time.
    started: Instant,
    /// Bytes the client sent upstream.
    bytes_out: u64,
    /// Bytes the remote sent back, counted by the pump task.
    bytes_in: Arc<AtomicU64>,
}

/// Removes the sessions idle past [`SESSION_IDLE`], aborting their pump tasks and
/// returning them so the caller can write each one's volume record — after the lock
/// is dropped, not while it is held.
fn sweep(sessions: &mut HashMap<Flow, Session>) -> Vec<(Flow, Session)> {
    let now = Instant::now();
    let (closed, kept): (Vec<_>, Vec<_>) = sessions
        .drain()
        .partition(|(_, session)| now.duration_since(session.touched) >= SESSION_IDLE);
    sessions.extend(kept);
    for (_, session) in &closed {
        session.pump.abort();
    }
    closed
}

/// A session's volume record, written when the flow ends for any reason.
async fn record(sink: &AuditSink, flow: Flow, session: &Session) {
    sink.record(AuditEvent::Connect(Connect {
        transport: Transport::Udp,
        destination: Endpoint {
            ip: flow.remote.ip(),
            port: flow.remote.port(),
        },
        resolved_from: None,
        bytes_out: session.bytes_out,
        bytes_in: session.bytes_in.load(Ordering::Relaxed),
        elapsed_ms: elapsed(session.started),
    }))
    .await;
}

/// Milliseconds since `started`, saturating rather than wrapping.
fn elapsed(started: Instant) -> u64 {
    u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX)
}

/// One listener's read loop: look up or open the flow, then forward the datagram.
async fn relay_loop(
    listener: Arc<Listener>,
    table: Table,
    egress: Arc<Egress>,
    sink: AuditSink,
    torsion_uid: u32,
) -> Result<()> {
    let mut buffer = vec![0_u8; MAX_DATAGRAM];
    loop {
        let Some(datagram) =
            listener
                .recv(&mut buffer)
                .await
                .map_err(|source| GatewayError::Socket {
                    context: "receiving a proxied datagram",
                    source,
                })?
        else {
            continue;
        };
        let flow = Flow {
            client: datagram.client,
            remote: datagram.remote,
        };
        let payload = buffer[..datagram.length].to_vec();

        // The lock is never held across an await: on a hit it lends the upstream
        // socket, on a miss the session is opened unlocked and then claimed.
        let upstream = {
            let hit = {
                let mut sessions = table.lock().await;
                sessions.get_mut(&flow).map(|session| {
                    session.touched = Instant::now();
                    session.bytes_out += payload.len() as u64;
                    Arc::clone(&session.upstream)
                })
            };
            match hit {
                Some(upstream) => upstream,
                None => {
                    match open(&table, &egress, &sink, flow, payload.len(), torsion_uid).await {
                        Some(upstream) => upstream,
                        None => continue,
                    }
                }
            }
        };
        if let Err(error) = upstream.send(&payload).await {
            tracing::debug!(%error, remote = %flow.remote, "a datagram on a dead upstream was dropped");
        }
    }
}

/// Opens a session for a flow the table has never seen: attributes the datagram's
/// owner for the leg decision, asks the egress for the route that leg permits,
/// and only a flow that can be both carried and answered — upstream connected,
/// reply socket bound — becomes a session. Returns the upstream socket to send
/// the triggering datagram on, or `None` when the flow was refused and recorded.
async fn open(
    table: &Table,
    egress: &Egress,
    sink: &AuditSink,
    flow: Flow,
    initial: usize,
    torsion_uid: u32,
) -> Option<Arc<UdpUpstream>> {
    if table.lock().await.len() >= SESSIONS_MAX {
        tracing::warn!(client = %flow.client, remote = %flow.remote, "the UDP session table is full");
        return None;
    }
    let owner = match owner_of::<Udp>(flow.client).await {
        Ok(owner) => owner,
        Err(error) => {
            tracing::debug!(%error, client = %flow.client, "a datagram's owner could not be attributed");
            None
        }
    };
    let leg = if owner == Some(torsion_uid) {
        Leg::Torsion
    } else {
        Leg::Base
    };
    let blocked = |reason| Blocked {
        transport: Transport::Udp,
        destination: Endpoint {
            ip: flow.remote.ip(),
            port: flow.remote.port(),
        },
        reason,
    };
    let upstream = match egress.udp_connect(flow.remote, leg).await {
        Ok(upstream) => Arc::new(upstream),
        Err(source) => {
            sink.attributed_to(owner)
                .record(AuditEvent::Blocked(blocked(match source.kind() {
                    io::ErrorKind::Unsupported => BlockReason::NoRoute,
                    io::ErrorKind::ConnectionAborted => BlockReason::EgressUnavailable,
                    _ => BlockReason::UpstreamUnreachable,
                })))
                .await;
            tracing::debug!(%source, remote = %flow.remote, "a UDP flow was refused");
            return None;
        }
    };
    // The answer socket is bound to the remote's own address; a flow that cannot
    // be answered from that address is no flow at all.
    let reply = match Reply::bind(flow.remote) {
        Ok(reply) => reply,
        Err(error) => {
            sink.attributed_to(owner)
                .record(AuditEvent::Blocked(blocked(
                    BlockReason::UpstreamUnreachable,
                )))
                .await;
            tracing::warn!(%error, remote = %flow.remote, "a UDP flow's reply socket could not be bound");
            return None;
        }
    };
    let bytes_in = Arc::new(AtomicU64::new(0));
    let pump = spawn_pump(
        reply,
        Arc::clone(&upstream),
        Arc::clone(&bytes_in),
        Arc::clone(table),
        sink.clone(),
        flow,
    );
    let session = Session {
        upstream: Arc::clone(&upstream),
        pump,
        touched: Instant::now(),
        started: Instant::now(),
        bytes_out: initial as u64,
        bytes_in,
    };
    // A datagram that arrived while this session was opening may have claimed the
    // flow first; the displaced session is retired with its record intact rather
    // than silently orphaned.
    let displaced = table.lock().await.insert(flow, session);
    if let Some(previous) = displaced {
        previous.pump.abort();
        record(sink, flow, &previous).await;
    }
    Some(upstream)
}

/// Spawns the remote→client half of a session: upstream datagrams are answered
/// through the session's own reply socket, which carries the remote's address.
/// A dead upstream retires the flow so the client's next datagram opens a fresh
/// session — a UDP retransmission must not wait out the idle timeout on a corpse.
fn spawn_pump(
    reply: Reply,
    upstream: Arc<UdpUpstream>,
    bytes_in: Arc<AtomicU64>,
    table: Table,
    sink: AuditSink,
    flow: Flow,
) -> tokio::task::AbortHandle {
    tokio::spawn(async move {
        let mut buffer = vec![0_u8; MAX_DATAGRAM];
        loop {
            match upstream.recv(&mut buffer).await {
                Ok(length) => {
                    bytes_in.fetch_add(length as u64, Ordering::Relaxed);
                    if let Err(error) = reply.send_to(flow.client, &buffer[..length]).await {
                        tracing::debug!(%error, client = %flow.client, "a relayed reply could not be delivered");
                        break;
                    }
                }
                Err(error) => {
                    tracing::debug!(%error, remote = %flow.remote, "a UDP session's upstream died");
                    break;
                }
            }
        }
        // Retire only this session: a younger one may already hold the flow, and
        // removing it would hand its datagrams a dead route. The handle the
        // session holds is this task's own — there is nothing left to abort.
        let closed = {
            let mut sessions = table.lock().await;
            match sessions.get(&flow) {
                Some(session) if Arc::ptr_eq(&session.upstream, &upstream) => {
                    sessions.remove(&flow)
                }
                _ => None,
            }
        };
        if let Some(session) = closed {
            record(&sink, flow, &session).await;
        }
    })
    .abort_handle()
}

/// Decodes a `recvmsg` peer address into a socket address of whichever family it is.
fn socket_addr(address: &SockaddrStorage) -> Option<SocketAddr> {
    if let Some(v4) = address.as_sockaddr_in() {
        return Some(SocketAddr::V4(SocketAddrV4::new(v4.ip(), v4.port())));
    }
    address.as_sockaddr_in6().map(|v6| {
        SocketAddr::V6(SocketAddrV6::new(
            v6.ip(),
            v6.port(),
            v6.flowinfo(),
            v6.scope_id(),
        ))
    })
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use super::*;

    fn v4() -> SocketAddr {
        SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(192, 0, 2, 1), 53_000))
    }

    fn v6() -> SocketAddr {
        SocketAddr::V6(SocketAddrV6::new(
            "2001:db8::1".parse().unwrap(),
            53_000,
            0,
            0,
        ))
    }

    /// A session standing in for a live flow: a real datagram socket upstream and a
    /// pending pump task, so nothing about it is fabricated for the sweeper.
    async fn session() -> Session {
        let upstream = tokio::net::UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .unwrap();
        Session {
            upstream: Arc::new(UdpUpstream::Direct(upstream)),
            pump: tokio::spawn(std::future::pending::<()>()).abort_handle(),
            touched: Instant::now(),
            started: Instant::now(),
            bytes_out: 0,
            bytes_in: Arc::new(AtomicU64::new(0)),
        }
    }

    #[test]
    fn a_peer_address_decodes_for_either_family() {
        for address in [v4(), v6()] {
            let storage = SockaddrStorage::from(address);
            assert_eq!(socket_addr(&storage), Some(address));
        }
    }

    #[tokio::test]
    async fn the_sweeper_retires_only_idle_sessions() {
        let flow = Flow {
            client: v4(),
            remote: v4(),
        };
        let stale_flow = Flow {
            client: v4(),
            remote: v6(),
        };
        let mut table = HashMap::from([
            (flow, session().await),
            (stale_flow, {
                let mut session = session().await;
                session.touched = Instant::now()
                    .checked_sub(SESSION_IDLE + Duration::from_secs(1))
                    .unwrap();
                session
            }),
        ]);
        let closed = sweep(&mut table);
        assert_eq!(table.len(), 1);
        assert!(table.contains_key(&flow));
        assert_eq!(closed.len(), 1);
        assert_eq!(closed[0].0, stale_flow);
    }
}
