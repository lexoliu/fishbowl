//! Recovery of the destination a redirected connection was originally aimed at.
//!
//! The egress policy sends every TCP connection through `iptables -t nat REDIRECT`, which
//! rewrites the destination before the gateway ever sees it. `SO_ORIGINAL_DST` is the only
//! place the pre-translation address survives.

use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};

use nix::sys::socket::{getsockopt, sockopt::OriginalDst};
use tokio::net::TcpStream;

use crate::error::{GatewayError, Result};

/// Reads the address the peer meant to reach before netfilter redirected it.
///
/// # Errors
/// Fails when the connection did not arrive through a NAT redirect, or when it is not
/// IPv4 — the egress policy drops IPv6 entirely, so an IPv6 arrival means the policy is
/// not the one this gateway was built for.
pub fn original_destination(stream: &TcpStream) -> Result<SocketAddr> {
    let peer = stream.peer_addr().map_err(|source| GatewayError::Socket {
        context: "reading the peer address of a redirected connection",
        source,
    })?;
    if !peer.is_ipv4() {
        return Err(GatewayError::NotIpv4 { peer });
    }
    let address = getsockopt(stream, OriginalDst)
        .map_err(|_| GatewayError::NoOriginalDestination { peer })?;
    Ok(SocketAddr::V4(SocketAddrV4::new(
        Ipv4Addr::from(u32::from_be(address.sin_addr.s_addr)),
        u16::from_be(address.sin_port),
    )))
}
