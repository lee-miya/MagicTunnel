//! Control-plane message types exchanged on the reliable QUIC stream at connection setup.
//! The data plane carries one raw IP packet per QUIC datagram and has no framing of its own,
//! apart from one-byte heartbeats on every link.

use std::net::{Ipv4Addr, SocketAddr};

use serde::{Deserialize, Serialize};

pub const ALPN: &[u8] = b"magictunnel/1";
/// 3: both ends of every link ping it and give it up once they hear nothing. Version 2 dialers
/// wait for answers to their pings, which version 3 nodes do not send; version 1 nodes
/// neither ping nor answer.
pub const PROTOCOL_VERSION: u16 = 3;
/// Longest route, exit included. Bounds the connections and handshake time one client can
/// make a path spend.
pub const MAX_HOPS: usize = 8;

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
    /// Set by a reconnecting client and passed along unchanged by relays.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resume: Option<Resume>,
}

/// Asks the exit for the tunnel address of an earlier session. With the token of that session
/// the exit hands the address over even while the old connection is still registered;
/// without it, the address is only granted if it is free.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Resume {
    pub tunnel_ip: Ipv4Addr,
    pub token: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum HelloReply {
    Ok {
        tunnel_ip: Ipv4Addr,
        prefix_len: u8,
        /// Largest IP packet the path beyond the first hop carries; the client clamps its
        /// TUN MTU to it.
        mtu: u16,
        /// Proves ownership of `tunnel_ip` when resuming; see [`Resume`].
        #[serde(default, skip_serializing_if = "Option::is_none")]
        token: Option<String>,
    },
    Err {
        reason: String,
    },
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn optional_fields_are_backwards_compatible() {
        let old = r#"{"version":1,"remaining":[]}"#;
        let hello: Hello = serde_json::from_str(old).unwrap();
        assert_eq!(hello.resume, None);
        assert_eq!(serde_json::to_string(&hello).unwrap(), old);

        let old = r#"{"Ok":{"tunnel_ip":"10.88.0.2","prefix_len":24,"mtu":1200}}"#;
        let reply: HelloReply = serde_json::from_str(old).unwrap();
        assert!(matches!(reply, HelloReply::Ok { token: None, .. }));
        assert_eq!(serde_json::to_string(&reply).unwrap(), old);
    }
}
