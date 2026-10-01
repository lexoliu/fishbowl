//! The tunnel's event loop.
//!
//! One task owns the three things that must serialize: the `boringtun` state machine,
//! the `smoltcp` interface, and the UDP socket that carries `WireGuard` datagrams.
//! Everything the socket wrappers do — reads, writes, new connections — funnels through
//! the shared [`SocketSet`] plus the `wake`/`requests` channels this loop selects on.

use std::{
    collections::VecDeque,
    io,
    net::SocketAddrV4,
    sync::{Arc, Mutex},
    time::Duration,
};

use boringtun::noise::{Tunn, TunnResult};
use smoltcp::{
    iface::{Config, Interface, SocketHandle, SocketSet},
    phy::{Device, DeviceCapabilities, Medium, RxToken, TxToken},
    socket::{Socket, tcp},
    time::Instant as SmolInstant,
    wire::{
        HardwareAddress, IpAddress, IpCidr, IpEndpoint, IpListenEndpoint, Ipv4Address, Ipv6Address,
    },
};
use tokio::{
    net::UdpSocket,
    sync::{Notify, mpsc, oneshot},
};

use super::{
    HANDSHAKE_TIMEOUT, SESSION_STALE, TIMER_TICK,
    registration::Device as Registration,
    socket_set,
    sockets::{Death, ephemeral_port},
};

/// The tunnel's MTU: the `WireGuard` overhead leaves room under a 1280-byte wire packet.
const MTU: usize = 1280;

/// How many IP packets wait to be encapsulated or delivered; TCP backpressure handles
/// overflow, so the queue is a shock absorber, not a buffer.
const QUEUE_DEPTH: usize = 512;

/// `WireGuard` datagrams and decrypted packets fit in one network frame.
const WIRE_SIZE: usize = 2048;

/// A `smoltcp` TCP socket's buffers.
const TCP_RX_BUFFER: usize = 64 * 1024;
const TCP_TX_BUFFER: usize = 64 * 1024;

/// How long a connection attempt may sit unanswered inside the tunnel.
const CONNECT_TIMEOUT: smoltcp::time::Duration = smoltcp::time::Duration::from_secs(20);

/// The request a [`super::Stack`] makes of the driver — TCP connects need the interface
/// context, which only the driver holds.
pub enum Request {
    /// Begin a TCP connection through the tunnel; replies with the socket's handle once
    /// the SYN is staged.
    Connect {
        /// Where the stream goes.
        remote: IpEndpoint,
        /// The outcome: the handle, or why the connect could not be staged.
        reply: oneshot::Sender<io::Result<SocketHandle>>,
    },
}

/// The `smoltcp` `Device` that hands decrypted packets to the stack and collects the
/// stack's for encapsulation.
struct Packets {
    /// Packets decapsulated from `WireGuard`, waiting for `Interface::poll`.
    inbound: VecDeque<Vec<u8>>,
    /// Packets the stack emitted, waiting for `Tunn::encapsulate`.
    outbound: VecDeque<Vec<u8>>,
}

impl Device for Packets {
    type RxToken<'a>
        = PacketRx
    where
        Self: 'a;
    type TxToken<'a>
        = PacketTx<'a>
    where
        Self: 'a;

    fn receive(
        &mut self,
        _timestamp: SmolInstant,
    ) -> Option<(Self::RxToken<'_>, Self::TxToken<'_>)> {
        let packet = self.inbound.pop_front()?;
        Some((PacketRx(packet), PacketTx(&mut self.outbound)))
    }

    fn transmit(&mut self, _timestamp: SmolInstant) -> Option<Self::TxToken<'_>> {
        (self.outbound.len() < QUEUE_DEPTH).then_some(PacketTx(&mut self.outbound))
    }

    fn capabilities(&self) -> DeviceCapabilities {
        let mut capabilities = DeviceCapabilities::default();
        capabilities.medium = Medium::Ip;
        capabilities.max_transmission_unit = MTU;
        capabilities.max_burst_size = Some(4);
        capabilities
    }
}

struct PacketRx(Vec<u8>);
struct PacketTx<'a>(&'a mut VecDeque<Vec<u8>>);

impl RxToken for PacketRx {
    fn consume<R, F>(self, sink: F) -> R
    where
        F: FnOnce(&[u8]) -> R,
    {
        sink(&self.0)
    }
}

impl TxToken for PacketTx<'_> {
    fn consume<R, F>(self, length: usize, sink: F) -> R
    where
        F: FnOnce(&mut [u8]) -> R,
    {
        let mut packet = vec![0_u8; length];
        let result = sink(&mut packet);
        self.0.push_back(packet);
        result
    }
}

/// Everything the loop owns.
pub struct Driver {
    tunn: Tunn,
    /// The one UDP socket the transport shows the network — connected to the peer.
    udp: UdpSocket,
    /// The peer's address, for `decapsulate`'s source attribution.
    endpoint: SocketAddrV4,
    iface: Interface,
    device: Packets,
    sockets: Arc<Mutex<SocketSet<'static>>>,
    wake: Arc<Notify>,
    retired: Arc<Mutex<Vec<SocketHandle>>>,
    dead: Arc<Death>,
    requests: mpsc::Receiver<Request>,
    established: Option<oneshot::Sender<()>>,
    started: tokio::time::Instant,
}

impl Driver {
    /// Builds the driver: the `Tunn` state machine and the `smoltcp` interface bound to
    /// the registered addresses.
    ///
    /// # Panics
    /// Panics if `smoltcp` rejects the interface configuration — the addresses come from
    /// a checked registration, so they are well-formed.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        registration: &Registration,
        udp: UdpSocket,
        sockets: Arc<Mutex<SocketSet<'static>>>,
        wake: Arc<Notify>,
        retired: Arc<Mutex<Vec<SocketHandle>>>,
        dead: Arc<Death>,
        requests: mpsc::Receiver<Request>,
        established: oneshot::Sender<()>,
    ) -> Self {
        let tunn = Tunn::new(
            boringtun::x25519::StaticSecret::from(registration.private_key),
            boringtun::x25519::PublicKey::from(registration.peer_public_key),
            None,
            Some(25),
            0,
            None,
        );

        let mut config = Config::new(HardwareAddress::Ip);
        let mut seed = [0_u8; 8];
        getrandom::fill(&mut seed).expect("the OS random source is available");
        config.random_seed = u64::from_be_bytes(seed);

        let mut device = Packets {
            inbound: VecDeque::with_capacity(QUEUE_DEPTH),
            outbound: VecDeque::with_capacity(QUEUE_DEPTH),
        };
        let mut iface = Interface::new(config, &mut device, SmolInstant::now());
        iface.update_ip_addrs(|addresses| {
            addresses
                .push(IpCidr::new(IpAddress::Ipv4(registration.address_v4), 32))
                .expect("the interface address list has room");
            addresses
                .push(IpCidr::new(IpAddress::Ipv6(registration.address_v6), 128))
                .expect("the interface address list has room");
        });
        iface
            .routes_mut()
            .add_default_ipv4_route(Ipv4Address::UNSPECIFIED)
            .expect("the route table has room");
        iface
            .routes_mut()
            .add_default_ipv6_route(Ipv6Address::UNSPECIFIED)
            .expect("the route table has room");

        Self {
            tunn,
            udp,
            endpoint: registration.endpoint,
            iface,
            device,
            sockets,
            wake,
            retired,
            dead,
            requests,
            established: Some(established),
            started: tokio::time::Instant::now(),
        }
    }

    /// Runs the loop until the tunnel dies or every `Stack` handle is gone; always
    /// publishes the death notice on the way out.
    pub async fn run(mut self) -> io::Result<()> {
        let result = self.drive().await;
        let reason: Arc<str> = match &result {
            Ok(()) => Arc::from("the driver stopped"),
            Err(error) => Arc::from(error.to_string()),
        };
        self.dead.die(reason);
        result
    }

    async fn drive(&mut self) -> io::Result<()> {
        let mut wire = vec![0_u8; WIRE_SIZE];
        let mut datagram = vec![0_u8; WIRE_SIZE];
        let mut tick = tokio::time::interval(TIMER_TICK);
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

        // The handshake cannot be driven by traffic that has not arrived yet.
        if let TunnResult::WriteToNetwork(initiation) =
            self.tunn.format_handshake_initiation(&mut wire, false)
        {
            self.udp.send(initiation).await?;
        }

        loop {
            self.collect_retired();

            let now = SmolInstant::now();
            let next_poll = {
                let mut set = socket_set(&self.sockets);
                self.iface.poll(now, &mut self.device, &mut set);
                self.iface.poll_delay(now, &set)
            };
            self.flush_tunnel(&mut wire).await?;

            if let Some(age) = self.tunn.time_since_last_handshake() {
                if let Some(confirm) = self.established.take() {
                    let _ = confirm.send(());
                }
                if age > SESSION_STALE {
                    return Err(io::Error::new(
                        io::ErrorKind::TimedOut,
                        "the WireGuard session expired and could not be re-established",
                    ));
                }
            } else if self.started.elapsed() > HANDSHAKE_TIMEOUT {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "the WireGuard handshake did not complete",
                ));
            }

            let poll_at = next_poll.map(|delay| {
                tokio::time::Instant::now() + Duration::from_micros(delay.total_micros())
            });
            tokio::select! {
                biased;
                request = self.requests.recv() => {
                    match request {
                        Some(request) => self.handle(request),
                        None => return Ok(()),
                    }
                }
                received = self.udp.recv(&mut datagram) => {
                    let length = received?;
                    self.decapsulate(&datagram[..length], &mut wire).await?;
                }
                () = self.wake.notified() => {}
                _ = tick.tick() => {
                    if let TunnResult::WriteToNetwork(packet) =
                        self.tunn.update_timers(&mut wire)
                    {
                        self.udp.send(packet).await?;
                    }
                }
                () = async {
                    match poll_at {
                        Some(instant) => tokio::time::sleep_until(instant).await,
                        None => std::future::pending::<()>().await,
                    }
                } => {}
            }
        }
    }

    /// A staged connect: allocate a socket, point it at the destination, hand the handle
    /// back so the caller can await `Established`.
    fn handle(&mut self, request: Request) {
        let Request::Connect { remote, reply } = request;
        let mut set = socket_set(&self.sockets);
        let mut socket = tcp::Socket::new(
            tcp::SocketBuffer::new(vec![0_u8; TCP_RX_BUFFER]),
            tcp::SocketBuffer::new(vec![0_u8; TCP_TX_BUFFER]),
        );
        socket.set_timeout(Some(CONNECT_TIMEOUT));
        let port = ephemeral_port(&set);
        let handle = set.add(socket);
        let outcome = set
            .get_mut::<tcp::Socket>(handle)
            .connect(self.iface.context(), remote, IpListenEndpoint::from(port))
            .map(|()| handle)
            .map_err(|error| io::Error::other(format!("staging a tunnel connection: {error}")));
        drop(set);
        let _ = reply.send(outcome);
    }

    /// Feeds one `WireGuard` datagram through `decapsulate`, sending any reply datagrams
    /// and queueing any plaintext packets for the stack.
    async fn decapsulate(&mut self, datagram: &[u8], wire: &mut [u8]) -> io::Result<()> {
        let mut datagram = datagram;
        loop {
            match self
                .tunn
                .decapsulate(Some((*self.endpoint.ip()).into()), datagram, wire)
            {
                TunnResult::Done => return Ok(()),
                TunnResult::Err(error) => {
                    tracing::debug!(?error, "a WireGuard datagram was dropped");
                    return Ok(());
                }
                TunnResult::WriteToNetwork(reply) => {
                    self.udp.send(reply).await?;
                    // The contract: keep calling with an empty datagram until Done.
                    datagram = &[];
                }
                TunnResult::WriteToTunnelV4(packet, _) | TunnResult::WriteToTunnelV6(packet, _) => {
                    if self.device.inbound.len() < QUEUE_DEPTH {
                        self.device.inbound.push_back(packet.to_vec());
                    }
                    return Ok(());
                }
            }
        }
    }

    /// Encapsulates whatever the stack emitted since the last pass.
    async fn flush_tunnel(&mut self, wire: &mut [u8]) -> io::Result<()> {
        while let Some(packet) = self.device.outbound.pop_front() {
            if let TunnResult::WriteToNetwork(datagram) = self.tunn.encapsulate(&packet, wire) {
                self.udp.send(datagram).await?;
            }
            // `Done` covers the packet queued for after the handshake; errors are
            // dropped — the stack retransmits what it must.
        }
        Ok(())
    }

    /// Removes sockets the wrappers released, once they can no longer emit: a closing
    /// TCP socket keeps its handle until the state machine reaches `Closed` so its FIN
    /// actually reaches the wire.
    fn collect_retired(&mut self) {
        let mut retired = self
            .retired
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if retired.is_empty() {
            return;
        }
        let mut set = socket_set(&self.sockets);
        retired.retain(|handle| {
            let done = set
                .iter()
                .find(|(held, _)| held == handle)
                .is_none_or(|(_, socket)| match socket {
                    Socket::Tcp(tcp) => matches!(tcp.state(), tcp::State::Closed),
                    Socket::Udp(_) => true,
                });
            if done {
                set.remove(*handle);
            }
            !done
        });
    }
}
