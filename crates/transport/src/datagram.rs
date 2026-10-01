//! Data plane: one raw IP packet per unreliable QUIC datagram.

use bytes::Bytes;
use quinn::{Connection, SendDatagramError};

use crate::{Error, Result};

/// Sends one IP packet. A packet too large for the current path is dropped, as an IP router
/// would; tunneled TCP recovers through its own retransmits and PMTU handling. Only errors that
/// make the connection unusable are returned.
pub fn send_packet(conn: &Connection, packet: Bytes) -> Result<()> {
    match conn.send_datagram(packet) {
        Err(SendDatagramError::TooLarge) => {
            tracing::trace!(max = ?conn.max_datagram_size(), "dropping oversized packet");
            Ok(())
        }
        res => Ok(res?),
    }
}

pub async fn recv_packet(conn: &Connection) -> Result<Bytes> {
    Ok(conn.read_datagram().await?)
}

/// Forwards datagrams between two hop connections in both directions, passing payloads through
/// untouched, until either connection fails. Returns the error that stopped it; the caller is
/// responsible for closing the other connection.
pub async fn relay(a: &Connection, b: &Connection) -> Error {
    async fn pump(from: &Connection, to: &Connection) -> Error {
        loop {
            if let Err(e) = async { send_packet(to, recv_packet(from).await?) }.await {
                return e;
            }
        }
    }
    tokio::select! {
        e = pump(a, b) => e,
        e = pump(b, a) => e,
    }
}
