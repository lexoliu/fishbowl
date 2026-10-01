//! Attribution of redirected traffic to the account inside the sandbox that produced it.
//!
//! The whole egress policy is written in terms of uids — the gateway's own traffic leaves
//! directly, everything else is redirected here — so an audit trail that cannot name the
//! account behind a connection describes only half of what the packet filter decided.
//! Netfilter hands the uid over for the packets it refuses, but a redirected connection
//! arrives as an ordinary accepted socket with no such marking.
//!
//! What it does carry is its source address and port, and the kernel publishes the owner
//! of every socket under `/proc/net` — one table per protocol per address family. Looking
//! the peer up there is therefore the one place the account survives, and it has to happen
//! while the socket is still open, which is why every caller does it before it does
//! anything else with the connection.

use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};

use crate::error::{GatewayError, Result};

/// One of the kernel's per-protocol socket tables.
///
/// A marker rather than a parameter: the tables share a layout and differ in which
/// sockets they list, and a caller holding a TCP connection must not be able to search
/// the UDP table by passing the wrong value.
pub trait SocketTable {
    /// Where `/proc` publishes the IPv4 table.
    const PATH_V4: &'static str;
    /// Where `/proc` publishes the IPv6 table.
    const PATH_V6: &'static str;
}

/// The tables listing TCP sockets.
#[derive(Debug, Clone, Copy)]
pub struct Tcp;

impl SocketTable for Tcp {
    const PATH_V4: &'static str = "/proc/net/tcp";
    const PATH_V6: &'static str = "/proc/net/tcp6";
}

/// The tables listing UDP sockets.
#[derive(Debug, Clone, Copy)]
pub struct Udp;

impl SocketTable for Udp {
    const PATH_V4: &'static str = "/proc/net/udp";
    const PATH_V6: &'static str = "/proc/net/udp6";
}

/// The uid owning the socket bound to `local`.
///
/// `None` means the kernel no longer lists that socket: a short-lived client can be gone
/// before the gateway finishes accepting its connection, and an unattributed record is a
/// truthful answer where an invented uid would not be.
///
/// # Errors
/// Fails when the table cannot be read, which means the gateway is not running on the
/// Linux it was built for.
pub async fn owner_of<T: SocketTable>(local: SocketAddr) -> Result<Option<u32>> {
    let path = match local {
        SocketAddr::V4(_) => T::PATH_V4,
        SocketAddr::V6(_) => T::PATH_V6,
    };
    let table = tokio::fs::read_to_string(path)
        .await
        .map_err(|source| GatewayError::Socket {
            context: "reading the kernel's socket table to attribute a connection",
            source,
        })?;
    Ok(owner_in(&table, local))
}

/// Finds the owner of `local` in the text of one `/proc/net` table.
fn owner_in(table: &str, local: SocketAddr) -> Option<u32> {
    table.lines().skip(1).find_map(|line| {
        let mut fields = line.split_whitespace().skip(1);
        let listed = endpoint_of(fields.next()?)?;
        if listed != local {
            return None;
        }
        // What follows the local address: rem_address, st, the two queues, the timer, the
        // retransmit count, and then the uid.
        fields.nth(5)?.parse().ok()
    })
}

/// Decodes one `address:port` cell of a `/proc/net` table.
///
/// The kernel prints the address as machine words rather than in network order: the v4
/// tables write one word, the v6 tables four, and each word is host-endian hexadecimal —
/// a swap per word on the little-endian machines this runs on and a no-op anywhere else,
/// which is exactly the transformation the kernel applied when it printed them.
fn endpoint_of(cell: &str) -> Option<SocketAddr> {
    let (address, port) = cell.split_once(':')?;
    let port = u16::from_str_radix(port, 16).ok()?;
    if address.len() == 8 {
        let word = u32::from_str_radix(address, 16).ok()?;
        Some(SocketAddr::V4(SocketAddrV4::new(
            Ipv4Addr::from(word.to_be()),
            port,
        )))
    } else if address.len() == 32 {
        let mut bytes = [0_u8; 16];
        for (index, word) in (0..32).step_by(8).enumerate() {
            let word = u32::from_str_radix(address.get(word..word + 8)?, 16).ok()?;
            bytes[index * 4..index * 4 + 4].copy_from_slice(&word.swap_bytes().to_be_bytes());
        }
        Some(SocketAddr::V6(SocketAddrV6::new(
            Ipv6Addr::from(bytes),
            port,
            0,
            0,
        )))
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Two rows as `/proc/net/tcp` prints them, taken from a sandbox mid-connection.
    const TABLE: &str = concat!(
        "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n",
        "   0: 2041A8C0:C1B4 9F0512AC:01BB 01 00000000:00000000 02:00000000 00000000  1000        0 24601 2 0000000000000000 20 4 30 10 -1\n",
        "   1: 0100007F:3A98 00000000:0000 0A 00000000:00000000 00:00000000 00000000   999        0 24580 1 0000000000000000 100 0 0 10 0\n",
    );

    /// Two rows as `/proc/net/tcp6` prints them.
    const TABLE6: &str = concat!(
        "  sl  local_address                         remote_address                        st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n",
        "   0: 00000000000000000000000001000000:3858 00000000000000000000000000000000:0000 0A 00000000:00000000 00:00000000 00000000  1000        0 34567 1 0000000000000000 100 0 0 10 0\n",
        "   1: 00462226064080FE07B4BDFFFE9040F0:9C40 00000000000000000000000000000000:0000 0A 00000000:00000000 00:00000000 00000000   999        0 34568 1 0000000000000000 100 0 0 10 0\n",
    );

    #[test]
    fn a_connection_is_attributed_to_the_account_that_opened_it() {
        let researcher = SocketAddrV4::new(Ipv4Addr::new(192, 168, 65, 32), 49588);
        assert_eq!(owner_in(TABLE, researcher.into()), Some(1000));
    }

    #[test]
    fn the_gateways_own_listener_is_attributed_to_the_gateway() {
        let listener = SocketAddrV4::new(Ipv4Addr::LOCALHOST, 15000);
        assert_eq!(owner_in(TABLE, listener.into()), Some(999));
    }

    #[test]
    fn a_socket_the_kernel_no_longer_lists_is_left_unattributed() {
        let gone = SocketAddrV4::new(Ipv4Addr::new(192, 168, 65, 32), 1);
        assert_eq!(owner_in(TABLE, gone.into()), None);
    }

    #[test]
    fn a_v6_socket_is_attributed_from_its_own_table() {
        let loopback = SocketAddrV6::new(Ipv6Addr::LOCALHOST, 0x3858, 0, 0);
        assert_eq!(owner_in(TABLE6, loopback.into()), Some(1000));
    }

    #[test]
    fn a_v6_global_address_decodes_word_by_word() {
        // Each printed word is a stored __be32 read host-endian: a byte swap per
        // word lands `2622:4600:fe80:4006:ffbd:b407:f040:90fe`.
        let global = SocketAddrV6::new(
            "2622:4600:fe80:4006:ffbd:b407:f040:90fe".parse().unwrap(),
            0x9c40,
            0,
            0,
        );
        assert_eq!(owner_in(TABLE6, global.into()), Some(999));
    }
}
