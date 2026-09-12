//! The record of what the packet filter refused.
//!
//! Everything the egress policy cannot audit — QUIC, raw sockets, any transport the
//! gateway does not terminate — is dropped, and dropped traffic is still traffic worth
//! knowing about. The filter copies each refused packet to an NFLOG group, and this reader
//! turns it into an audit record naming the account that sent it.

use etherparse::{NetHeaders, PacketHeaders, TransportHeader};
use fishbowl_audit::{AuditEvent, BlockReason, Blocked, Endpoint, Transport};
use netlink_packet_core::{NLM_F_ACK, NLM_F_REQUEST, NetlinkMessage, NetlinkPayload};
use netlink_packet_netfilter::{
    NetfilterMessage, NetfilterMessageInner, NetfilterProtoFamily,
    nflog::{ConfigCmd, ConfigMode, ConfigNla, PacketNla, ULogMessage, config_request},
};
use netlink_sys::{
    AsyncSocket, AsyncSocketExt, SocketAddr as NetlinkAddr, TokioSocket,
    protocols::NETLINK_NETFILTER,
};

use crate::{
    audit::AuditSink,
    error::{GatewayError, Result},
};

/// Bytes of each refused packet the kernel copies to userspace.
///
/// The gateway only needs the headers to say what was attempted, and copying no more than
/// that keeps a flood of refused packets from becoming a flood of memory.
const COPY_RANGE: u32 = 128;

/// Reads refused packets from `group` until the netlink socket fails.
///
/// # Errors
/// Fails when the netlink socket cannot be opened or bound to the group — which is what
/// happens when the gateway is started without `CAP_NET_ADMIN`, and is a configuration
/// error rather than something to continue past.
pub async fn watch(group: u16, sink: AuditSink) -> Result<()> {
    let mut socket =
        TokioSocket::new(NETLINK_NETFILTER).map_err(|source| GatewayError::Socket {
            context: "opening the netfilter netlink socket",
            source,
        })?;
    socket
        .socket_mut()
        .bind_auto()
        .map_err(|source| GatewayError::Socket {
            context: "binding the netfilter netlink socket",
            source,
        })?;

    send(
        &mut socket,
        config_request(
            NetfilterProtoFamily::IPv4,
            group,
            vec![ConfigNla::Cmd(ConfigCmd::PfBind)],
        ),
    )
    .await?;
    send(
        &mut socket,
        config_request(
            NetfilterProtoFamily::IPv4,
            group,
            vec![ConfigNla::Cmd(ConfigCmd::Bind)],
        ),
    )
    .await?;
    send(
        &mut socket,
        config_request(
            NetfilterProtoFamily::IPv4,
            group,
            vec![ConfigNla::Mode(ConfigMode::new_packet(COPY_RANGE))],
        ),
    )
    .await?;

    loop {
        let (bytes, _) = socket
            .recv_from_full()
            .await
            .map_err(|source| GatewayError::Socket {
                context: "reading a refused packet from the netfilter log",
                source,
            })?;
        let mut offset = 0;
        while offset < bytes.len() {
            let Ok(message) = NetlinkMessage::<NetfilterMessage>::deserialize(&bytes[offset..])
            else {
                break;
            };
            let length = message.header.length as usize;
            if length == 0 {
                break;
            }
            offset += length;
            if let NetlinkPayload::InnerMessage(NetfilterMessage {
                inner: NetfilterMessageInner::ULog(ULogMessage::Packet(attributes)),
                ..
            }) = message.payload
            {
                report(&attributes, &sink).await;
            }
        }
    }
}

async fn send(
    socket: &mut TokioSocket,
    mut message: NetlinkMessage<NetfilterMessage>,
) -> Result<()> {
    message.header.flags = NLM_F_REQUEST | NLM_F_ACK;
    message.finalize();
    let mut buffer = vec![0_u8; message.buffer_len()];
    message.serialize(&mut buffer);
    socket
        .send_to(&buffer, &NetlinkAddr::new(0, 0))
        .await
        .map(drop)
        .map_err(|source| GatewayError::Socket {
            context: "configuring the netfilter log group",
            source,
        })
}

async fn report(attributes: &[PacketNla], sink: &AuditSink) {
    let mut uid = None;
    let mut payload = None;
    for attribute in attributes {
        match attribute {
            PacketNla::Uid(value) => uid = Some(*value),
            PacketNla::Payload(bytes) => payload = Some(bytes.as_slice()),
            _ => {}
        }
    }
    let Some(payload) = payload else {
        return;
    };
    let Ok(headers) = PacketHeaders::from_ip_slice(payload) else {
        tracing::debug!("a refused packet could not be parsed");
        return;
    };
    let Some(destination) = destination_of(&headers) else {
        return;
    };
    sink.attributed_to(uid)
        .record(AuditEvent::Blocked(Blocked {
            transport: transport_of(&headers),
            destination,
            reason: BlockReason::UnauditableTransport,
        }))
        .await;
}

fn destination_of(headers: &PacketHeaders<'_>) -> Option<Endpoint> {
    let ip = match headers.net.as_ref()? {
        NetHeaders::Ipv4(header, _) => std::net::IpAddr::from(header.destination),
        NetHeaders::Ipv6(header, _) => std::net::IpAddr::from(header.destination),
        NetHeaders::Arp(_) => return None,
    };
    let port = match headers.transport.as_ref() {
        Some(TransportHeader::Tcp(header)) => header.destination_port,
        Some(TransportHeader::Udp(header)) => header.destination_port,
        _ => 0,
    };
    Some(Endpoint { ip, port })
}

fn transport_of(headers: &PacketHeaders<'_>) -> Transport {
    match headers.transport.as_ref() {
        Some(TransportHeader::Tcp(_)) => Transport::Tcp,
        Some(TransportHeader::Udp(_)) => Transport::Udp,
        _ => Transport::Other,
    }
}
