//! The async socket handles a live tunnel hands out.
//!
//! A [`Tcp`] or [`Udp`] is a [`SocketHandle`] into the shared set plus the means to be
//! woken: the driver's [`Notify`], and `dead`, whose waker list the driver drains with
//! its last breath so pending reads and connects cannot hang on a corpse.

use std::{
    collections::BTreeSet,
    io,
    net::SocketAddrV4,
    pin::Pin,
    sync::{Arc, Mutex},
    task::{Context, Poll, Waker},
    time::Duration,
};

use smoltcp::{
    iface::{SocketHandle, SocketSet},
    socket::{Socket, tcp, udp},
    storage::PacketBuffer,
    wire::IpEndpoint,
};
use tokio::{
    io::{AsyncRead, AsyncWrite, ReadBuf},
    sync::Notify,
};

use super::socket_set;

/// How long a DNS exchange inside the tunnel may take.
const DNS_TIMEOUT: Duration = Duration::from_secs(5);

/// A UDP socket's packet buffers: small queues, one packet is a whole DNS message.
const UDP_PACKETS: usize = 8;
const UDP_BUFFER: usize = 8 * 1024;

/// The death notice every tunnel socket shares.
///
/// A `watch` cannot be polled inside another `poll_*` method, so death is a reason plus
/// a list of wakers the driver drains as it exits.
pub(super) struct Death {
    reason: Mutex<Option<Arc<str>>>,
    wakers: Mutex<Vec<Waker>>,
}

impl Death {
    pub(super) fn new() -> Self {
        Self {
            reason: Mutex::new(None),
            wakers: Mutex::new(Vec::new()),
        }
    }

    /// Why the tunnel died, if it did.
    pub(super) fn reason(&self) -> Option<Arc<str>> {
        self.reason
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
    }

    /// Registers `waker` to be woken when the driver dies.
    pub(super) fn watch(&self, waker: &Waker) {
        let mut wakers = self
            .wakers
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if !wakers.iter().any(|woken| woken.will_wake(waker)) {
            wakers.push(waker.clone());
        }
    }

    /// The driver's last act: record the reason and wake every pending operation.
    pub(super) fn die(&self, reason: Arc<str>) {
        *self
            .reason
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(reason);
        let wakers: Vec<Waker> = self
            .wakers
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .drain(..)
            .collect();
        for waker in wakers {
            waker.wake();
        }
    }

    /// The error pending operations resolve to.
    fn error(&self) -> io::Error {
        io::Error::new(
            io::ErrorKind::ConnectionAborted,
            self.reason().map_or_else(
                || "the WARP tunnel is down".to_string(),
                |reason| format!("the WARP tunnel is down: {reason}"),
            ),
        )
    }

    /// Registers for the wake and returns the error if death already happened.
    fn check(&self, context: &Context<'_>) -> io::Result<()> {
        self.watch(context.waker());
        self.reason().map_or(Ok(()), |_| Err(self.error()))
    }
}

/// A TCP stream through the tunnel.
pub struct Tcp {
    sockets: Arc<Mutex<SocketSet<'static>>>,
    handle: SocketHandle,
    wake: Arc<Notify>,
    retired: Arc<Mutex<Vec<SocketHandle>>>,
    dead: Arc<Death>,
}

impl Tcp {
    pub(super) fn new(
        sockets: Arc<Mutex<SocketSet<'static>>>,
        handle: SocketHandle,
        wake: Arc<Notify>,
        retired: Arc<Mutex<Vec<SocketHandle>>>,
        dead: Arc<Death>,
    ) -> Self {
        Self {
            sockets,
            handle,
            wake,
            retired,
            dead,
        }
    }

    /// Waits out `SynSent`/`SynReceived` until the connection is established or refused.
    ///
    /// # Errors
    /// Fails when the destination refuses, smoltcp's connect timeout fires, or the tunnel
    /// dies mid-connect.
    pub(super) async fn established(&self) -> io::Result<()> {
        std::future::poll_fn(|context| {
            self.dead.check(context)?;
            let mut set = socket_set(&self.sockets);
            let socket = set.get_mut::<tcp::Socket>(self.handle);
            match socket.state() {
                tcp::State::Established => Poll::Ready(Ok(())),
                tcp::State::SynSent | tcp::State::SynReceived => {
                    socket.register_send_waker(context.waker());
                    socket.register_recv_waker(context.waker());
                    Poll::Pending
                }
                _ => Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::ConnectionRefused,
                    "the tunnel destination refused or did not answer",
                ))),
            }
        })
        .await
    }
}

impl AsyncRead for Tcp {
    fn poll_read(
        self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if let Err(error) = self.dead.check(context) {
            return Poll::Ready(Err(error));
        }
        let mut set = socket_set(&self.sockets);
        let socket = set.get_mut::<tcp::Socket>(self.handle);
        if socket.can_recv() {
            let data = buf.initialize_unfilled();
            match socket.recv_slice(data) {
                Ok(0) | Err(tcp::RecvError::Finished) => Poll::Ready(Ok(())),
                Ok(length) => {
                    buf.advance(length);
                    self.wake.notify_one();
                    Poll::Ready(Ok(()))
                }
                Err(error) => Poll::Ready(Err(io::Error::other(format!(
                    "reading a tunnel stream: {error}"
                )))),
            }
        } else if socket.may_recv() {
            socket.register_recv_waker(context.waker());
            Poll::Pending
        } else {
            // The remote closed and nothing is left to read: end of stream.
            Poll::Ready(Ok(()))
        }
    }
}

impl AsyncWrite for Tcp {
    fn poll_write(
        self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        if let Err(error) = self.dead.check(context) {
            return Poll::Ready(Err(error));
        }
        let mut set = socket_set(&self.sockets);
        let socket = set.get_mut::<tcp::Socket>(self.handle);
        if !socket.may_send() {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "the tunnel stream is closed",
            )));
        }
        if socket.can_send() {
            match socket.send_slice(buf) {
                Ok(length) => {
                    self.wake.notify_one();
                    Poll::Ready(Ok(length))
                }
                Err(error) => Poll::Ready(Err(io::Error::other(format!(
                    "writing a tunnel stream: {error}"
                )))),
            }
        } else {
            socket.register_send_waker(context.waker());
            Poll::Pending
        }
    }

    fn poll_flush(self: Pin<&mut Self>, _context: &mut Context<'_>) -> Poll<io::Result<()>> {
        // What the kernel does for a real socket: the data is staged, the driver puts it
        // on the wire — flush means "out of our hands", not "acknowledged".
        self.wake.notify_one();
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _context: &mut Context<'_>) -> Poll<io::Result<()>> {
        let mut set = socket_set(&self.sockets);
        set.get_mut::<tcp::Socket>(self.handle).close();
        self.wake.notify_one();
        Poll::Ready(Ok(()))
    }
}

impl Drop for Tcp {
    fn drop(&mut self) {
        {
            let mut set = socket_set(&self.sockets);
            // Graceful close — the driver removes the socket once its FIN is on the wire
            // or the state machine has run out.
            set.get_mut::<tcp::Socket>(self.handle).close();
        }
        self.retired
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .push(self.handle);
        self.wake.notify_one();
    }
}

/// A UDP socket through the tunnel — used for DNS exchanges, one query at a time.
pub struct Udp {
    sockets: Arc<Mutex<SocketSet<'static>>>,
    handle: SocketHandle,
    wake: Arc<Notify>,
    retired: Arc<Mutex<Vec<SocketHandle>>>,
    dead: Arc<Death>,
}

impl Udp {
    /// Binds a fresh UDP socket to an ephemeral port.
    ///
    /// # Errors
    /// Fails only if the ephemeral port space is somehow exhausted.
    pub(super) fn bind(
        sockets: Arc<Mutex<SocketSet<'static>>>,
        wake: Arc<Notify>,
        retired: Arc<Mutex<Vec<SocketHandle>>>,
        dead: Arc<Death>,
    ) -> io::Result<Self> {
        let mut set = socket_set(&sockets);
        let mut socket = udp::Socket::new(
            PacketBuffer::new(
                vec![udp::PacketMetadata::EMPTY; UDP_PACKETS],
                vec![0_u8; UDP_BUFFER],
            ),
            PacketBuffer::new(
                vec![udp::PacketMetadata::EMPTY; UDP_PACKETS],
                vec![0_u8; UDP_BUFFER],
            ),
        );
        let port = ephemeral_port(&set);
        socket
            .bind(port)
            .map_err(|error| io::Error::other(format!("binding a tunnel DNS socket: {error}")))?;
        let handle = set.add(socket);
        drop(set);
        Ok(Self {
            sockets,
            handle,
            wake,
            retired,
            dead,
        })
    }

    /// Sends `query` to `resolver` and returns the answer it gives.
    ///
    /// # Errors
    /// Fails on timeout or if the tunnel dies mid-exchange.
    pub(super) async fn exchange(
        &self,
        resolver: SocketAddrV4,
        query: &[u8],
    ) -> io::Result<Vec<u8>> {
        {
            let mut set = socket_set(&self.sockets);
            let socket = set.get_mut::<udp::Socket>(self.handle);
            socket
                .send_slice(query, IpEndpoint::from(resolver))
                .map_err(|error| {
                    io::Error::other(format!("sending a DNS query through the tunnel: {error}"))
                })?;
        }
        self.wake.notify_one();

        let mut answer = vec![0_u8; 4096];
        let received = std::future::poll_fn(|context| {
            self.dead.check(context)?;
            let mut set = socket_set(&self.sockets);
            let socket = set.get_mut::<udp::Socket>(self.handle);
            match socket.recv_slice(&mut answer) {
                Ok((length, _meta)) => Poll::Ready(Ok(answer[..length].to_vec())),
                Err(udp::RecvError::Exhausted) => {
                    socket.register_recv_waker(context.waker());
                    Poll::Pending
                }
                Err(error) => Poll::Ready(Err(io::Error::other(format!(
                    "receiving a DNS answer through the tunnel: {error}"
                )))),
            }
        });
        tokio::time::timeout(DNS_TIMEOUT, received)
            .await
            .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "the resolver did not answer"))?
    }
}

impl Drop for Udp {
    fn drop(&mut self) {
        self.retired
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .push(self.handle);
        self.wake.notify_one();
    }
}

/// A port the socket set is not using.
pub(super) fn ephemeral_port(set: &SocketSet<'static>) -> u16 {
    let used: BTreeSet<u16> = set
        .iter()
        .filter_map(|(_, socket)| match socket {
            Socket::Tcp(tcp) => tcp.local_endpoint().map(|endpoint| endpoint.port),
            Socket::Udp(udp) => Some(udp.endpoint().port),
        })
        .collect();
    let mut bytes = [0_u8; 2];
    getrandom::fill(&mut bytes).expect("the OS random source is available");
    let start = 49152 + u16::from_be_bytes(bytes) % (65535 - 49152);
    (start..=65535)
        .chain(49152..start)
        .find(|port| !used.contains(port))
        .expect("the ephemeral port space is not exhausted")
}
