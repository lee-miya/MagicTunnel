//! Exit mode: each authenticated client leases a tunnel address; its packets are written to
//! the exit TUN, where the kernel routes them and NAT masquerades them onto the internet.
//! Replies come back out of the TUN and are sent to the session owning the destination.
//!
//! On Linux the TUN can be multi-queue: the kernel spreads flows over the queues and each is
//! read by its own task, so the downlink scales across cores like the per-session uplinks.

use std::convert::Infallible;
use std::net::Ipv4Addr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::Context;
use magictunnel_common::config::{ExitConfig, ExitTunConfig};
use magictunnel_common::ip::ipv4_addrs;
use magictunnel_common::metrics::Traffic;
use magictunnel_common::proto::{HelloReply, Resume};
use magictunnel_transport::quinn::{Connection, VarInt};
use magictunnel_transport::{
    ControlStream, Sent, heartbeat, recv_packets, send_packet, too_large_reply,
};
use magictunnel_tunio::{Arena, BATCH, TunReader, TunWriter, offload_enabled};
use tokio::task::JoinSet;
use tun_rs::{AsyncDevice, DeviceBuilder};

use crate::metrics::{
    DROP_FILTERED, DROP_NO_SESSION, DROP_NOT_IPV4, EXIT_DOWN, EXIT_SESSIONS, EXIT_SESSIONS_TOTAL,
    EXIT_UP, RESUMED_SESSIONS, TUN_WRITE_ERRORS,
};
use crate::nat::NatGuard;
use crate::node::reject;
use crate::pool::IpPool;
use crate::sessions::Sessions;

pub struct Exit {
    // Fields drop in order: the NAT rules go before the TUN they refer to.
    _nat: NatGuard,
    shared: Arc<Shared>,
}

struct Shared {
    queues: Vec<Arc<AsyncDevice>>,
    sessions: Arc<Sessions<Peer>>,
    mtu: u16,
}

/// What the downlink needs to reach a session.
#[derive(Clone)]
pub struct Peer {
    conn: Connection,
    down: Arc<Traffic>,
}

impl Exit {
    /// Creates the exit TUN and installs NAT. Needs root or `CAP_NET_ADMIN`.
    pub fn start(cfg: &ExitConfig) -> anyhow::Result<Self> {
        let pool = IpPool::new(cfg.pool);
        let (net, gateway, capacity) = (pool.net(), pool.gateway(), pool.capacity());
        let queues = open_queues(&cfg.tun, gateway, net.prefix_len())?;
        let nat = NatGuard::install(&cfg.tun.name, net)?;
        tracing::info!(
            tun = %cfg.tun.name,
            addr = %gateway,
            pool = %net,
            capacity,
            mtu = cfg.tun.mtu,
            queues = queues.len(),
            offload = offload_enabled(&queues[0]),
            "exit TUN up"
        );
        Ok(Self {
            _nat: nat,
            shared: Arc::new(Shared {
                queues,
                sessions: Sessions::new(pool),
                mtu: cfg.tun.mtu,
            }),
        })
    }

    /// What connection tasks use to end tunnels here.
    pub fn handle(&self) -> ExitHandle {
        ExitHandle(Arc::clone(&self.shared))
    }

    pub fn sessions(&self) -> Arc<Sessions<Peer>> {
        Arc::clone(&self.shared.sessions)
    }

    /// Delivers packets coming back out of the exit TUN, one task per queue, until reading
    /// one of them fails.
    pub async fn run(&self) -> anyhow::Error {
        let mut tasks = JoinSet::new();
        for queue in &self.shared.queues {
            tasks.spawn(downlink(Arc::clone(&self.shared), Arc::clone(queue)));
        }
        match tasks.join_next().await.expect("at least one queue") {
            Ok(Err(e)) => e,
            Ok(Ok(never)) => match never {},
            Err(e) => std::panic::resume_unwind(e.into_panic()),
        }
    }
}

fn open_queues(
    cfg: &ExitTunConfig,
    addr: Ipv4Addr,
    prefix_len: u8,
) -> anyhow::Result<Vec<Arc<AsyncDevice>>> {
    let wanted = match cfg.queues {
        0 => std::thread::available_parallelism().map_or(1, usize::from),
        n => n,
    };
    let builder = DeviceBuilder::new()
        .name(&cfg.name)
        .ipv4(addr, prefix_len, None)
        .mtu(cfg.mtu);
    #[cfg(target_os = "linux")]
    let builder = builder.offload(cfg.offload).multi_queue(wanted > 1);
    let first = builder.build_async().with_context(|| {
        format!(
            "creating TUN device {} (needs root or CAP_NET_ADMIN)",
            cfg.name
        )
    })?;
    let mut queues = vec![Arc::new(first)];
    #[cfg(target_os = "linux")]
    for _ in 1..wanted {
        let queue = queues[0]
            .try_clone()
            .context("opening another exit TUN queue")?;
        queues.push(Arc::new(queue));
    }
    Ok(queues)
}

/// Shared access to the exit TUN and session table; keeps the TUN open but not the NAT rules.
#[derive(Clone)]
pub struct ExitHandle(Arc<Shared>);

impl ExitHandle {
    /// Runs one client session whose route ends here: address lease, handshake reply, then
    /// the uplink until the connection ends or nothing arrives on it for `heartbeat_timeout`.
    /// Only setup failures are returned.
    pub async fn tunnel(
        &self,
        conn: Connection,
        mut control: ControlStream,
        resume: Option<Resume>,
        heartbeat_timeout: Duration,
    ) -> anyhow::Result<()> {
        let shared = &*self.0;
        let peer = conn.remote_address();
        let Some(max_datagram) = conn.max_datagram_size() else {
            return reject(&conn, control, "datagrams are required").await;
        };
        let down = Arc::new(Traffic::child_of(&EXIT_DOWN));
        let me = Peer {
            conn: conn.clone(),
            down: Arc::clone(&down),
        };
        let Some(grant) = shared.sessions.register(me, resume.as_ref()) else {
            return reject(&conn, control, "tunnel address pool exhausted").await;
        };
        let tunnel_ip = grant.lease.addr();
        if let Some(old) = grant.displaced {
            tracing::info!(old_peer = %old.conn.remote_address(), %tunnel_ip, "session resumed, closing its old connection");
            old.conn
                .close(VarInt::from_u32(0), b"session resumed elsewhere");
        }

        let mtu = shared
            .mtu
            .min(u16::try_from(max_datagram).unwrap_or(u16::MAX));
        control
            .send(&HelloReply::Ok {
                tunnel_ip,
                prefix_len: shared.sessions.net().prefix_len(),
                mtu,
                token: Some(grant.token),
            })
            .await
            .context("sending handshake reply")?;
        EXIT_SESSIONS_TOTAL.inc();
        if grant.resumed {
            RESUMED_SESSIONS.inc();
        }
        EXIT_SESSIONS.inc();
        tracing::info!(%peer, %tunnel_ip, mtu, resumed = grant.resumed, "tunnel up");

        let started = Instant::now();
        let up = Traffic::child_of(&EXIT_UP);
        // Pinning a session's writes to one queue keeps its packets in order.
        let queue = &shared.queues[u32::from(tunnel_ip) as usize % shared.queues.len()];
        let e = tokio::select! {
            e = uplink(&conn, shared, tunnel_ip, &up, Arc::clone(queue)) => e,
            e = heartbeat::watch(&conn, heartbeat_timeout) => e.into(),
        };
        EXIT_SESSIONS.dec();
        tracing::info!(
            %peer,
            %tunnel_ip,
            secs = started.elapsed().as_secs(),
            up_packets = up.packets(),
            up_bytes = up.bytes(),
            down_packets = down.packets(),
            down_bytes = down.bytes(),
            "tunnel down: {e:#}"
        );
        drop(grant.lease);
        Ok(())
    }
}

impl Shared {
    /// Clients reach anything outside the pool plus the exit itself, never each other.
    fn allowed_dst(&self, dst: Ipv4Addr) -> bool {
        dst == self.sessions.gateway() || !self.sessions.net().contains(&dst)
    }
}

/// Client to TUN. Packets must come from the client's own tunnel address, so one client can
/// neither spoof another nor have replies routed to someone else.
async fn uplink(
    conn: &Connection,
    shared: &Shared,
    tunnel_ip: Ipv4Addr,
    meter: &Traffic,
    queue: Arc<AsyncDevice>,
) -> anyhow::Error {
    let mut writer = TunWriter::new(queue);
    let mut batch = Vec::with_capacity(BATCH);
    loop {
        batch.clear();
        if let Err(e) = recv_packets(conn, &mut batch, BATCH).await {
            return e.into();
        }
        batch.retain(|packet| match ipv4_addrs(packet) {
            Some(addrs) if addrs.src == tunnel_ip && shared.allowed_dst(addrs.dst) => {
                meter.record(packet.len());
                true
            }
            _ if heartbeat::is_heartbeat(packet) => false,
            addrs => {
                tracing::trace!(%tunnel_ip, ?addrs, len = packet.len(), "dropping client packet");
                DROP_FILTERED.inc();
                false
            }
        });
        // The kernel rejects malformed packets per write; that must not end the session.
        if let Err(e) = writer.send(&batch).await {
            TUN_WRITE_ERRORS.inc();
            tracing::debug!(%tunnel_ip, error = %e, "TUN rejected packet");
        }
    }
}

/// TUN to clients: every packet goes to the session that leased its destination address.
/// One too big for the session's link is answered with ICMP "fragmentation needed", which the
/// kernel NATs back to the sender like any reply from the client.
async fn downlink(shared: Arc<Shared>, queue: Arc<AsyncDevice>) -> anyhow::Result<Infallible> {
    let mut reader = TunReader::new(Arc::clone(&queue), shared.mtu);
    let mut icmp = TunWriter::new(queue);
    let mut errors = Vec::new();
    let mut arena = Arena::default();
    loop {
        let packets = reader.recv().await.context("reading from exit TUN")?;
        // Segments of one super-packet share a destination: look it up once per read.
        let mut last: Option<(Ipv4Addr, Option<Peer>)> = None;
        for packet in packets {
            let Some(addrs) = ipv4_addrs(packet) else {
                DROP_NOT_IPV4.inc();
                continue;
            };
            if last.as_ref().is_none_or(|(dst, _)| *dst != addrs.dst) {
                last = Some((addrs.dst, shared.sessions.lookup(addrs.dst)));
            }
            let Some((_, Some(peer))) = &last else {
                tracing::trace!(dst = %addrs.dst, len = packet.len(), "no session for packet from TUN");
                DROP_NO_SESSION.inc();
                continue;
            };
            match send_packet(&peer.conn, arena.copy(packet)) {
                Ok(Sent::Queued) => peer.down.record(packet.len()),
                Ok(Sent::TooLarge) => errors.extend(too_large_reply(&peer.conn, packet)),
                Err(e) => {
                    tracing::debug!(dst = %addrs.dst, error = %e, "dropping packet for closing session")
                }
            }
        }
        if !errors.is_empty() {
            let _ = icmp.send(&errors).await;
            errors.clear();
        }
    }
}
