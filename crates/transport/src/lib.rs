//! QUIC transport for magicTunnel: mTLS endpoint configuration, the XOR-obfuscating
//! `AsyncUdpSocket` wrapper, the reliable control stream, and datagram relay primitives.

pub mod control;
pub mod datagram;
pub mod endpoint;
pub mod error;
pub mod obfs;
pub mod tls;

pub use control::{
    ControlStream, HANDSHAKE_TIMEOUT, HOP_CONNECT_TIMEOUT, HOP_SETUP_BUDGET, accept_hello, hello,
    hello_timeout,
};
pub use datagram::{
    FRAG_NEEDED_SENT, OVERSIZED_DROPS, Sent, recv_packet, recv_packets, relay, send_packet,
    send_packet_wait, too_large_reply,
};
pub use endpoint::{bind_obfuscated, client_endpoint, connect, server_endpoint, transport_config};
pub use error::{Error, Result};
pub use obfs::{XorKey, XorSocket};
pub use quinn;
pub use tls::TlsMaterial;
