//! Per-connection entry point: authenticates the peer, reads its handshake, and either ends
//! the tunnel here (exit) or carries it on to the next hop of the route (relay).

use std::time::Duration;

use anyhow::{Context, bail};
use magictunnel_common::proto::{HelloReply, MAX_HOPS};
use magictunnel_transport::quinn::rustls::pki_types::CertificateDer;
use magictunnel_transport::quinn::{Connection, Endpoint, Incoming, VarInt};
use magictunnel_transport::{ControlStream, accept_hello};

use crate::exit::ExitHandle;
use crate::metrics::{HANDSHAKE_FAILURES, SETUP_FAILURES};
use crate::relay;

/// How long a rejected peer gets to read the reason before the connection is dropped.
const REJECT_GRACE: Duration = Duration::from_secs(3);

/// Serves every connection accepted on `endpoint` until it closes. Relays dial their next hop
/// from the same endpoint. Every link is given up after `heartbeat_timeout` without a packet
/// from its peer.
pub async fn accept(
    endpoint: &Endpoint,
    exit: Option<ExitHandle>,
    heartbeat_timeout: Duration,
) -> anyhow::Error {
    while let Some(incoming) = endpoint.accept().await {
        tokio::spawn(serve(
            incoming,
            endpoint.clone(),
            exit.clone(),
            heartbeat_timeout,
        ));
    }
    anyhow::anyhow!("endpoint closed")
}

async fn serve(
    incoming: Incoming,
    endpoint: Endpoint,
    exit: Option<ExitHandle>,
    heartbeat_timeout: Duration,
) {
    let peer = incoming.remote_address();
    let conn = match incoming.await {
        Ok(conn) => conn,
        Err(e) => {
            HANDSHAKE_FAILURES.inc();
            tracing::debug!(%peer, error = %e, "QUIC handshake failed");
            return;
        }
    };
    if let Err(e) = session(conn, &endpoint, exit.as_ref(), heartbeat_timeout).await {
        SETUP_FAILURES.inc();
        tracing::warn!(%peer, "tunnel setup failed: {e:#}");
    }
}

/// Runs one tunnel through this node. Only setup failures are returned.
async fn session(
    conn: Connection,
    endpoint: &Endpoint,
    exit: Option<&ExitHandle>,
    heartbeat_timeout: Duration,
) -> anyhow::Result<()> {
    if !has_client_cert(&conn) {
        conn.close(VarInt::from_u32(0), b"client certificate required");
        bail!("peer presented no client certificate");
    }
    let (control, hello) = accept_hello(&conn).await.context("tunnel handshake")?;
    if hello.remaining.len() >= MAX_HOPS {
        let reason = format!("route is longer than {MAX_HOPS} hops");
        return reject(&conn, control, &reason).await;
    }
    match (hello.remaining.split_first(), exit) {
        (None, Some(exit)) => {
            exit.tunnel(conn, control, hello.resume, heartbeat_timeout)
                .await
        }
        (None, None) => reject(&conn, control, "this node is not an exit").await,
        (Some((next, rest)), _) => {
            relay::run(
                endpoint,
                conn,
                control,
                next,
                rest,
                hello.resume,
                heartbeat_timeout,
            )
            .await
        }
    }
}

/// Answers the handshake with `reason`, waits for the peer to hang up, and returns the
/// rejection as an error.
pub async fn reject(
    conn: &Connection,
    mut control: ControlStream,
    reason: &str,
) -> anyhow::Result<()> {
    control
        .send(&HelloReply::Err {
            reason: reason.into(),
        })
        .await?;
    control.finish();
    // The peer closes once it has read the reply; closing first could discard it.
    let _ = tokio::time::timeout(REJECT_GRACE, conn.closed()).await;
    bail!("rejected: {reason}")
}

fn has_client_cert(conn: &Connection) -> bool {
    conn.peer_identity()
        .and_then(|id| id.downcast::<Vec<CertificateDer<'static>>>().ok())
        .is_some_and(|chain| !chain.is_empty())
}
