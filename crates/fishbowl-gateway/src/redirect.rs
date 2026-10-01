//! Recovery of the destination a redirected connection was originally aimed at.
//!
//! The egress policy sends every TCP connection through `REDIRECT`, which rewrites
//! the destination before the gateway ever sees it. The original survives only in
//! conntrack, exposed per family: `SO_ORIGINAL_DST` for IPv4, `IP6T_SO_ORIGINAL_DST`
//! for IPv6.

use std::net::{SocketAddr, SocketAddrV4, SocketAddrV6};

use nix::sys::socket::{
    getsockopt,
    sockopt::{Ip6tOriginalDst, OriginalDst},
};
use tokio::net::TcpStream;

use crate::error::{GatewayError, Result};

/// Reads the address the peer meant to reach before netfilter redirected it.
///
/// # Errors
/// Fails when the connection did not arrive through a NAT redirect — the answer
/// would be the gateway's own loopback port, which is no destination at all.
pub fn original_destination(stream: &TcpStream) -> Result<SocketAddr> {
    let peer = stream.peer_addr().map_err(|source| GatewayError::Socket {
        context: "reading the peer address of a redirected connection",
        source,
    })?;
    match peer {
        SocketAddr::V4(_) => {
            let original = getsockopt(stream, OriginalDst)
                .map_err(|_| GatewayError::NoOriginalDestination { peer })?;
            Ok(SocketAddr::V4(SocketAddrV4::new(
                std::net::Ipv4Addr::from(u32::from_be(original.sin_addr.s_addr)),
                u16::from_be(original.sin_port),
            )))
        }
        SocketAddr::V6(_) => {
            let original = getsockopt(stream, Ip6tOriginalDst)
                .map_err(|_| GatewayError::NoOriginalDestination { peer })?;
            Ok(SocketAddr::V6(SocketAddrV6::new(
                std::net::Ipv6Addr::from(original.sin6_addr.s6_addr),
                u16::from_be(original.sin6_port),
                u32::from_be(original.sin6_flowinfo),
                original.sin6_scope_id,
            )))
        }
    }
}
