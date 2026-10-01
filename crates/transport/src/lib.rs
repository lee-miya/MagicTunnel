//! QUIC transport for magicTunnel: mTLS endpoint configuration, the XOR-obfuscating
//! `AsyncUdpSocket` wrapper, the reliable control stream, and datagram relay primitives.

pub mod control;
pub mod datagram;
pub mod endpoint;
pub mod error;
pub mod obfs;
pub mod tls;

pub use control::{ControlStream, accept_hello, hello};
pub use datagram::{recv_packet, relay, send_packet};
pub use endpoint::{bind_obfuscated, client_endpoint, connect, server_endpoint, transport_config};
pub use error::{Error, Result};
pub use obfs::{XorKey, XorSocket};
pub use quinn;
pub use tls::TlsMaterial;
