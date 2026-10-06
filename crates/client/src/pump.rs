//! Data pump between the TUN device and the tunnel connection: one IP packet per datagram.
//! Each direction runs as its own task, so both can use a core.

use std::convert::Infallible;
use std::sync::Arc;
use std::time::Duration;

use magictunnel_common::ip::{ipv4_addrs, is_ipv4};
use magictunnel_transport::quinn::Connection;
use magictunnel_transport::{Liveness, Sent, recv_packets, send_packet_wait, too_large_reply};
use magictunnel_tunio::{Arena, BATCH, TunReader, TunWriter};
use tokio::task::JoinSet;
use tun_rs::AsyncDevice;

use crate::metrics::{DOWN, DROP_NOT_IPV4, TUN_WRITE_ERRORS, UP};

/// Why the pumps stopped.
#[derive(Debug)]
pub enum Stop {
    /// The tunnel connection failed; a new session can take over the same TUN.
    Tunnel(anyhow::Error),
    /// The TUN device failed, so reconnecting would not help.
    Tun(anyhow::Error),
}

/// Runs both directions until one fails or the first hop stops answering heartbeats for
/// `heartbeat_timeout`, returning why. `max_mtu` bounds the TUN MTU over the device's lifetime.
pub async fn run(
    dev: &Arc<AsyncDevice>,
    conn: &Connection,
    max_mtu: u16,
    heartbeat_timeout: Duration,
) -> Stop {
    let liveness = Arc::new(Liveness::default());
    let mut tasks = JoinSet::new();
    tasks.spawn(uplink(Arc::clone(dev), conn.clone(), max_mtu));
    tasks.spawn(downlink(
        conn.clone(),
        Arc::clone(dev),
        Arc::clone(&liveness),
    ));
    let watched = conn.clone();
    tasks.spawn(async move {
        let e = liveness.watch(&watched, heartbeat_timeout).await;
        Err(Stop::Tunnel(
            anyhow::Error::new(e).context("tunnel heartbeat"),
        ))
    });
    let stop = match tasks.join_next().await.expect("tasks were spawned") {
        Ok(Err(stop)) => stop,
        Ok(Ok(never)) => match never {},
        Err(e) => std::panic::resume_unwind(e.into_panic()),
    };
    // A reconnect starts new pumps on the same TUN; the old ones must be gone by then.
    tasks.shutdown().await;
    stop
}

/// TUN to tunnel. Waits for room in the connection's send buffer rather than dropping, so
/// congestion pushes back on the local senders through the TUN queue.
async fn uplink(dev: Arc<AsyncDevice>, conn: Connection, max_mtu: u16) -> Result<Infallible, Stop> {
    let mut reader = TunReader::new(Arc::clone(&dev), max_mtu);
    let mut icmp = TunWriter::new(dev);
    let mut arena = Arena::default();
    loop {
        let packets = reader
            .recv()
            .await
            .map_err(|e| Stop::Tun(anyhow::Error::new(e).context("reading from TUN")))?;
        for packet in packets {
            // The tunnel only carries IPv4; anything else the kernel emits on the TUN (e.g.
            // IPv6 router solicitations) is dropped here instead of being sent to the exit.
            if !is_ipv4(packet) {
                tracing::trace!(len = packet.len(), "dropping non-IPv4 packet from TUN");
                DROP_NOT_IPV4.inc();
                continue;
            }
            let sent = send_packet_wait(&conn, arena.copy(packet))
                .await
                .map_err(|e| Stop::Tunnel(anyhow::Error::new(e).context("sending to tunnel")))?;
            match sent {
                Sent::Queued => UP.record(packet.len()),
                // The path shrank below the TUN MTU: tell the sender, as a router would, so
                // TCP lowers its segment size.
                Sent::TooLarge => {
                    if let Some(reply) = too_large_reply(&conn, packet) {
                        let _ = icmp.send(&[reply]).await;
                    }
                }
            }
        }
    }
}

/// Tunnel to TUN, in batches of whatever has arrived, so offload can coalesce them. Pongs go
/// to `liveness` instead.
async fn downlink(
    conn: Connection,
    dev: Arc<AsyncDevice>,
    liveness: Arc<Liveness>,
) -> Result<Infallible, Stop> {
    let mut writer = TunWriter::new(dev);
    let mut batch = Vec::with_capacity(BATCH);
    loop {
        batch.clear();
        recv_packets(&conn, &mut batch, BATCH)
            .await
            .map_err(|e| Stop::Tunnel(anyhow::Error::new(e).context("receiving from tunnel")))?;
        batch.retain(|packet| {
            if liveness.observe(packet) {
                return false;
            }
            let ok = ipv4_addrs(packet).is_some();
            if ok {
                DOWN.record(packet.len());
            } else {
                DROP_NOT_IPV4.inc();
            }
            ok
        });
        // The kernel rejects malformed packets per write; that must not end the session.
        if let Err(e) = writer.send(&batch).await {
            TUN_WRITE_ERRORS.inc();
            tracing::debug!(error = %e, "TUN rejected packet");
        }
    }
}
