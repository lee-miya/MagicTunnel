//! Control-plane message types exchanged on the reliable QUIC stream at connection setup.
//! The data plane carries one raw IP packet per QUIC datagram and has no framing of its own.

use std::net::{Ipv4Addr, SocketAddr};

use serde::{Deserialize, Serialize};

pub const ALPN: &[u8] = b"magictunnel/1";
pub const PROTOCOL_VERSION: u16 = 1;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Hop {
    pub addr: SocketAddr,
    pub server_name: String,
}

/// Sent by the dialing side. `remaining` lists the hops after the receiver; empty means the
/// receiver is the exit.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Hello {
    pub version: u16,
    pub remaining: Vec<Hop>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum HelloReply {
    Ok {
        tunnel_ip: Ipv4Addr,
        prefix_len: u8,
        mtu: u16,
    },
    Err {
        reason: String,
    },
}
