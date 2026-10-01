//! Relay mode: the connection from the previous hop is spliced onto a new connection to the
//! next hop named in its handshake. Every link is its own QUIC + mTLS + XOR session, so each
//! datagram is decrypted here and re-encrypted for the next link, and a node only ever learns
//! its two neighbours: the rest of the route is passed on, not kept.

use std::sync::Arc;
use std::time::Instant;

use anyhow::anyhow;
use magictunnel_common::metrics::Traffic;
use magictunnel_common::proto::{HelloReply, Hop, Resume};
use magictunnel_transport::quinn::{Connection, Endpoint, VarInt};
use magictunnel_transport::{ControlStream, HOP_CONNECT_TIMEOUT, connect, hello};

use crate::metrics::{RELAY_DOWN, RELAY_SESSIONS, RELAY_SESSIONS_TOTAL, RELAY_UP};
use crate::node::reject;

/// Runs one relayed tunnel: sets up the next link, passes the exit's reply back, then forwards
/// datagrams both ways until either side goes away. Only setup failures are returned.
pub async fn run(
    endpoint: &Endpoint,
    upstream: Connection,
    mut control: ControlStream,
    next: &Hop,
    rest: &[Hop],
    resume: Option<Resume>,
) -> anyhow::Result<()> {
    let peer = upstream.remote_address();
    let name = &next.server_name;
    let (downstream, _next_control, reply) = match dial(endpoint, next, rest, resume).await {
        Ok(link) => link,
        Err(e) => {
            let reason = format!("cannot reach {name} ({}): {e:#}", next.addr);
            return reject(&upstream, control, &reason).await;
        }
    };
    let (tunnel_ip, prefix_len, mtu, token) = match reply {
        HelloReply::Ok {
            tunnel_ip,
            prefix_len,
            mtu,
            token,
        } => (tunnel_ip, prefix_len, mtu, token),
        HelloReply::Err { reason } => {
            downstream.close(VarInt::from_u32(0), b"tunnel rejected");
            // Prefixing the sender's name makes the reason read as the path to the failure.
            return reject(&upstream, control, &format!("{name}: {reason}")).await;
        }
    };
    // Packets must also fit the link to the next hop; the client clamps to its own link.
    let next_link = downstream
        .max_datagram_size()
        .map_or(0, |max| u16::try_from(max).unwrap_or(u16::MAX));
    let mtu = mtu.min(next_link);
    let reply = HelloReply::Ok {
        tunnel_ip,
        prefix_len,
        mtu,
        token,
    };
    if let Err(e) = control.send(&reply).await {
        downstream.close(VarInt::from_u32(0), b"previous hop gone");
        return Err(anyhow::Error::new(e).context("relaying handshake reply"));
    }
    RELAY_SESSIONS_TOTAL.inc();
    RELAY_SESSIONS.inc();
    tracing::info!(%peer, next = %name, next_addr = %next.addr, %tunnel_ip, mtu, "relay up");

    let started = Instant::now();
    let up = Arc::new(Traffic::child_of(&RELAY_UP));
    let down = Arc::new(Traffic::child_of(&RELAY_DOWN));
    let e = magictunnel_transport::relay(
        upstream.clone(),
        downstream.clone(),
        Arc::clone(&up),
        Arc::clone(&down),
    )
    .await;
    upstream.close(VarInt::from_u32(0), b"relay closed");
    downstream.close(VarInt::from_u32(0), b"relay closed");
    RELAY_SESSIONS.dec();
    tracing::info!(
        %peer,
        next = %name,
        %tunnel_ip,
        secs = started.elapsed().as_secs(),
        up_packets = up.packets(),
        up_bytes = up.bytes(),
        down_packets = down.packets(),
        down_bytes = down.bytes(),
        "relay down: {:#}",
        anyhow::Error::new(e)
    );
    Ok(())
}

/// Connects to `next` and hands it the rest of the route; returns the link, its control
/// stream (to be kept open), and the reply from beyond it.
async fn dial(
    endpoint: &Endpoint,
    next: &Hop,
    rest: &[Hop],
    resume: Option<Resume>,
) -> anyhow::Result<(Connection, ControlStream, HelloReply)> {
    let conn = tokio::time::timeout(
        HOP_CONNECT_TIMEOUT,
        connect(endpoint, next.addr, &next.server_name),
    )
    .await
    .map_err(|_| anyhow!("no answer within {}s", HOP_CONNECT_TIMEOUT.as_secs()))??;
    match hello(&conn, rest.to_vec(), resume).await {
        Ok((control, reply)) => Ok((conn, control, reply)),
        Err(e) => {
            conn.close(VarInt::from_u32(0), b"tunnel handshake failed");
            Err(e.into())
        }
    }
}
