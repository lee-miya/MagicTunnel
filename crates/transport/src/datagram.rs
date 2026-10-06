//! Data plane: one raw IP packet per unreliable QUIC datagram.

use std::pin::pin;
use std::sync::Arc;
use std::task::{Context, Poll, Waker};
use std::time::Duration;

use bytes::Bytes;
use magictunnel_common::ip::frag_needed;
use magictunnel_common::metrics::{Counter, Traffic};
use quinn::{Connection, SendDatagramError};
use tokio::task::JoinSet;

use crate::heartbeat;
use crate::{Error, Result};

/// Packets dropped because they did not fit one datagram on the current path.
pub static OVERSIZED_DROPS: Counter = Counter::new();
/// ICMP "fragmentation needed" errors sent back for such packets.
pub static FRAG_NEEDED_SENT: Counter = Counter::new();

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Sent {
    Queued,
    /// Dropped, as an IP router would drop a packet too big for the next link.
    TooLarge,
}

/// Queues one IP packet without waiting. When the send buffer is full the oldest queued
/// datagrams make room (head drop: the loss tunnelled TCP notices soonest), so a sender
/// serving many connections never stalls on one. Only errors that make the connection
/// unusable are returned.
pub fn send_packet(conn: &Connection, packet: Bytes) -> Result<Sent> {
    sent(conn, conn.send_datagram(packet))
}

/// Like [`send_packet`], but waits for buffer space instead of dropping. For a sender with a
/// queue of its own behind it (the client's TUN): congestion then backs up into the kernel,
/// which paces the local sockets instead of losing their packets.
pub async fn send_packet_wait(conn: &Connection, packet: Bytes) -> Result<Sent> {
    sent(conn, conn.send_datagram_wait(packet).await)
}

fn sent(conn: &Connection, result: Result<(), SendDatagramError>) -> Result<Sent> {
    match result {
        Ok(()) => Ok(Sent::Queued),
        Err(SendDatagramError::TooLarge) => {
            OVERSIZED_DROPS.inc();
            tracing::trace!(max = ?conn.max_datagram_size(), "dropping oversized packet");
            Ok(Sent::TooLarge)
        }
        Err(e) => Err(e.into()),
    }
}

/// The ICMP error telling the sender of `packet`, which did not fit a datagram on `conn`, to
/// lower its path MTU; `None` where a router would not send one. Counted as sent.
pub fn too_large_reply(conn: &Connection, packet: &[u8]) -> Option<Bytes> {
    let mtu = conn.max_datagram_size().unwrap_or(0);
    let reply = frag_needed(packet, u16::try_from(mtu).unwrap_or(u16::MAX))?;
    FRAG_NEEDED_SENT.inc();
    Some(reply.into())
}

pub async fn recv_packet(conn: &Connection) -> Result<Bytes> {
    Ok(conn.read_datagram().await?)
}

/// Waits for one datagram, then appends it and whatever else is already queued, up to `max`
/// in total, to `out`. Batches let the receiver write them to the TUN in one go.
pub async fn recv_packets(conn: &Connection, out: &mut Vec<Bytes>, max: usize) -> Result<()> {
    out.push(conn.read_datagram().await?);
    let mut cx = Context::from_waker(Waker::noop());
    while out.len() < max {
        match pin!(conn.read_datagram()).poll(&mut cx) {
            Poll::Ready(Ok(packet)) => out.push(packet),
            // Pending, or an error the next call reports once this batch is delivered.
            _ => break,
        }
    }
    Ok(())
}

/// Forwards datagrams between the connection `upstream` that was accepted and the one
/// `downstream` dialed for it, passing payloads through untouched, until either connection
/// fails or nothing arrives on one of them for `heartbeat_timeout`. Heartbeats belong to one
/// link and are not forwarded. Each direction runs as its own task, so both can use a core. A
/// packet too big for the onward link is answered with ICMP "fragmentation needed" back the
/// way it came, so the path MTU stays discoverable end to end. Returns the error that stopped
/// it; the caller is responsible for closing the connections.
pub async fn relay(
    upstream: Connection,
    downstream: Connection,
    up: Arc<Traffic>,
    down: Arc<Traffic>,
    heartbeat_timeout: Duration,
) -> Error {
    async fn pump(from: Connection, to: Connection, meter: Arc<Traffic>) -> Error {
        loop {
            let packet = match recv_packet(&from).await {
                Ok(packet) => packet,
                Err(e) => return e,
            };
            if heartbeat::is_heartbeat(&packet) {
                continue;
            }
            match send_packet(&to, packet.clone()) {
                Ok(Sent::Queued) => meter.record(packet.len()),
                Ok(Sent::TooLarge) => {
                    if let Some(reply) = too_large_reply(&to, &packet) {
                        let _ = send_packet(&from, reply);
                    }
                }
                Err(e) => return e,
            }
        }
    }
    let mut tasks = JoinSet::new();
    tasks.spawn(pump(upstream.clone(), downstream.clone(), up));
    tasks.spawn(pump(downstream.clone(), upstream.clone(), down));
    for link in [upstream, downstream] {
        tasks.spawn(async move { heartbeat::watch(&link, heartbeat_timeout).await });
    }
    // Dropping the set aborts the others.
    match tasks.join_next().await.expect("tasks were spawned") {
        Ok(e) => e,
        Err(e) => std::panic::resume_unwind(e.into_panic()),
    }
}
