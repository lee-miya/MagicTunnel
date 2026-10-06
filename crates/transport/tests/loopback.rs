//! End-to-end transport tests over loopback UDP with throwaway certificates.

use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering::Relaxed};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use bytes::Bytes;
use magictunnel_common::config::{DEFAULT_TUN_MTU, QuicConfig};
use magictunnel_common::metrics::Traffic;
use magictunnel_common::proto::{HelloReply, Hop};
use magictunnel_transport::quinn::{self, Endpoint};
use magictunnel_transport::{
    Error, Sent, TlsMaterial, XorKey, accept_hello, client_endpoint, connect, heartbeat, hello,
    recv_packet, recv_packets, relay, send_packet, send_packet_wait, server_endpoint,
};
use rcgen::{
    BasicConstraints, CertificateParams, DnType, ExtendedKeyUsagePurpose, IsCa, Issuer, KeyPair,
    KeyUsagePurpose,
};
use rustls_pki_types::{CertificateDer, PrivateKeyDer};
use tokio::net::UdpSocket;
use tokio::sync::mpsc;

const KEY: &[u8] = b"loopback-test-key";
const NO_CONNECT_WAIT: Duration = Duration::from_secs(2);
const HEARTBEAT_TIMEOUT: Duration = Duration::from_secs(30);
/// Short enough for a test, long enough for several pings.
const SHORT_HEARTBEAT: Duration = Duration::from_secs(2);

struct Ca {
    der: CertificateDer<'static>,
    issuer: Issuer<'static, KeyPair>,
}

impl Ca {
    fn new(name: &str) -> Self {
        let mut params = CertificateParams::default();
        params.distinguished_name.push(DnType::CommonName, name);
        params.is_ca = IsCa::Ca(BasicConstraints::Constrained(0));
        params.key_usages = vec![
            KeyUsagePurpose::KeyCertSign,
            KeyUsagePurpose::DigitalSignature,
        ];
        let key = KeyPair::generate().unwrap();
        let cert = params.self_signed(&key).unwrap();
        Self {
            der: cert.der().clone(),
            issuer: Issuer::new(params, key),
        }
    }

    fn node(&self, name: &str) -> TlsMaterial {
        self.node_trusting(name, self)
    }

    /// A node whose certificate is issued by `self` but which trusts `roots`.
    fn node_trusting(&self, name: &str, roots: &Ca) -> TlsMaterial {
        let mut params = CertificateParams::new(vec![name.to_owned()]).unwrap();
        params.distinguished_name.push(DnType::CommonName, name);
        params.extended_key_usages = vec![
            ExtendedKeyUsagePurpose::ServerAuth,
            ExtendedKeyUsagePurpose::ClientAuth,
        ];
        let key = KeyPair::generate().unwrap();
        let cert = params.signed_by(&key, &self.issuer).unwrap();
        TlsMaterial::new(
            vec![roots.der.clone()],
            vec![cert.der().clone()],
            PrivateKeyDer::Pkcs8(key.serialize_der().into()),
        )
        .unwrap()
    }
}

fn xor_key(key: &[u8]) -> Arc<XorKey> {
    Arc::new(XorKey::new(key).unwrap())
}

fn localhost() -> SocketAddr {
    "127.0.0.1:0".parse().unwrap()
}

fn tunnel_reply() -> HelloReply {
    HelloReply::Ok {
        tunnel_ip: "10.88.0.2".parse().unwrap(),
        prefix_len: 24,
        mtu: DEFAULT_TUN_MTU,
        token: None,
    }
}

/// Exit node: completes the handshake with each peer, then echoes every datagram but
/// heartbeats. Peers that fail the handshake are skipped, as the negative tests expect.
fn spawn_exit(tls: &TlsMaterial) -> SocketAddr {
    spawn_exit_with(tls, HEARTBEAT_TIMEOUT).0
}

/// [`spawn_exit`] that gives a session up once nothing arrives on it for `heartbeat_timeout`,
/// and reports why each session ended.
fn spawn_exit_with(
    tls: &TlsMaterial,
    heartbeat_timeout: Duration,
) -> (SocketAddr, mpsc::UnboundedReceiver<Error>) {
    let endpoint = server_endpoint(localhost(), xor_key(KEY), tls, &QuicConfig::default()).unwrap();
    let addr = endpoint.local_addr().unwrap();
    let (ended, sessions) = mpsc::unbounded_channel();
    tokio::spawn(async move {
        while let Some(incoming) = endpoint.accept().await {
            let Ok(conn) = incoming.await else { continue };
            let Ok((mut control, hello)) = accept_hello(&conn).await else {
                continue;
            };
            assert!(hello.remaining.is_empty());
            control.send(&tunnel_reply()).await.unwrap();
            let ended = ended.clone();
            tokio::spawn(async move {
                let _control = control;
                let echo = async {
                    loop {
                        let packet = match recv_packet(&conn).await {
                            Ok(packet) => packet,
                            Err(e) => return e,
                        };
                        if heartbeat::is_heartbeat(&packet) {
                            continue;
                        }
                        if let Err(e) = send_packet(&conn, packet) {
                            return e;
                        }
                    }
                };
                let e = tokio::select! {
                    e = echo => e,
                    e = heartbeat::watch(&conn, heartbeat_timeout) => e,
                };
                let _ = ended.send(e);
            });
        }
    });
    (addr, sessions)
}

/// A UDP forwarder in front of `server` for one client, whose two directions can be cut, as on
/// a path that breaks one way only.
struct Path {
    addr: SocketAddr,
    up: Arc<AtomicBool>,
    down: Arc<AtomicBool>,
}

async fn spawn_path(server: SocketAddr) -> Path {
    let front = Arc::new(UdpSocket::bind(localhost()).await.unwrap());
    let back = Arc::new(UdpSocket::bind(localhost()).await.unwrap());
    back.connect(server).await.unwrap();
    let client = Arc::new(Mutex::new(None));
    let path = Path {
        addr: front.local_addr().unwrap(),
        up: Arc::new(AtomicBool::new(true)),
        down: Arc::new(AtomicBool::new(true)),
    };
    let (rx, tx, from, open) = (
        Arc::clone(&front),
        Arc::clone(&back),
        Arc::clone(&client),
        Arc::clone(&path.up),
    );
    tokio::spawn(async move {
        let mut buf = vec![0; 65536];
        loop {
            let Ok((len, peer)) = rx.recv_from(&mut buf).await else {
                continue;
            };
            *from.lock().unwrap() = Some(peer);
            if open.load(Relaxed) {
                let _ = tx.send(&buf[..len]).await;
            }
        }
    });
    let open = Arc::clone(&path.down);
    tokio::spawn(async move {
        let mut buf = vec![0; 65536];
        loop {
            let Ok(len) = back.recv(&mut buf).await else {
                continue;
            };
            let to = *client.lock().unwrap();
            if let Some(to) = to
                && open.load(Relaxed)
            {
                let _ = front.send_to(&buf[..len], to).await;
            }
        }
    });
    path
}

/// Relay node: dials the next hop named in the handshake, relays the reply back, then
/// forwards datagrams in both directions until either side fails or the next hop stops
/// answering heartbeats for `heartbeat_timeout`; then closes both links.
fn spawn_relay(tls: &TlsMaterial, heartbeat_timeout: Duration) -> SocketAddr {
    let endpoint = server_endpoint(localhost(), xor_key(KEY), tls, &QuicConfig::default()).unwrap();
    let addr = endpoint.local_addr().unwrap();
    tokio::spawn(async move {
        let upstream = endpoint.accept().await.unwrap().await.unwrap();
        let (mut control, request) = accept_hello(&upstream).await.unwrap();
        let (next, rest) = request.remaining.split_first().unwrap();
        let downstream = connect(&endpoint, next.addr, &next.server_name)
            .await
            .unwrap();
        let (_next_control, reply) = hello(&downstream, rest.to_vec(), None).await.unwrap();
        control.send(&reply).await.unwrap();
        let meter = || Arc::new(Traffic::new());
        let links = (upstream.clone(), downstream.clone());
        relay(upstream, downstream, meter(), meter(), heartbeat_timeout).await;
        links.0.close(0u32.into(), b"relay closed");
        links.1.close(0u32.into(), b"relay closed");
        endpoint.wait_idle().await;
    });
    addr
}

fn exit_route(exit: SocketAddr) -> Vec<Hop> {
    vec![Hop {
        addr: exit,
        server_name: "exit1".into(),
    }]
}

async fn assert_echo(conn: &quinn::Connection) {
    let max = conn.max_datagram_size().unwrap();
    assert!(
        max >= usize::from(DEFAULT_TUN_MTU),
        "max datagram {max} < TUN MTU {DEFAULT_TUN_MTU}"
    );
    for i in 0..10u8 {
        let packet = Bytes::from(vec![i; usize::from(DEFAULT_TUN_MTU)]);
        assert_eq!(send_packet(conn, packet.clone()).unwrap(), Sent::Queued);
        let echoed = tokio::time::timeout(Duration::from_secs(5), recv_data(conn))
            .await
            .expect("echo timed out")
            .unwrap();
        assert_eq!(echoed, packet);
    }
}

/// The next datagram that is not the peer's heartbeat.
async fn recv_data(conn: &quinn::Connection) -> magictunnel_transport::Result<Bytes> {
    loop {
        let packet = recv_packet(conn).await?;
        if !heartbeat::is_heartbeat(&packet) {
            return Ok(packet);
        }
    }
}

async fn dial(
    tls: &TlsMaterial,
    key: &[u8],
    addr: SocketAddr,
    server_name: &str,
) -> (Endpoint, magictunnel_transport::Result<quinn::Connection>) {
    let endpoint = client_endpoint(addr, xor_key(key), tls, &QuicConfig::default()).unwrap();
    let conn = connect(&endpoint, addr, server_name).await;
    (endpoint, conn)
}

#[tokio::test]
async fn single_hop_handshake_and_datagrams() {
    let ca = Ca::new("test CA");
    let exit = spawn_exit(&ca.node("exit1"));

    let (_endpoint, conn) = dial(&ca.node("client1"), KEY, exit, "exit1").await;
    let conn = conn.unwrap();
    let (_control, reply) = hello(&conn, vec![], None).await.unwrap();
    assert_eq!(reply, tunnel_reply());
    assert_echo(&conn).await;
}

#[tokio::test]
async fn two_hop_relay() {
    let ca = Ca::new("test CA");
    let exit = spawn_exit(&ca.node("exit1"));
    let relay = spawn_relay(&ca.node("relay1"), HEARTBEAT_TIMEOUT);

    let (_endpoint, conn) = dial(&ca.node("client1"), KEY, relay, "relay1").await;
    let conn = conn.unwrap();
    let (_control, reply) = hello(&conn, exit_route(exit), None).await.unwrap();
    assert_eq!(reply, tunnel_reply());
    assert_echo(&conn).await;
}

#[tokio::test]
async fn three_hop_relay() {
    let ca = Ca::new("test CA");
    let exit = spawn_exit(&ca.node("exit1"));
    let relay2 = spawn_relay(&ca.node("relay2"), HEARTBEAT_TIMEOUT);
    let relay1 = spawn_relay(&ca.node("relay1"), HEARTBEAT_TIMEOUT);

    let (_endpoint, conn) = dial(&ca.node("client1"), KEY, relay1, "relay1").await;
    let conn = conn.unwrap();
    let route = vec![
        Hop {
            addr: relay2,
            server_name: "relay2".into(),
        },
        Hop {
            addr: exit,
            server_name: "exit1".into(),
        },
    ];
    let (_control, reply) = hello(&conn, route, None).await.unwrap();
    assert_eq!(reply, tunnel_reply());
    assert_echo(&conn).await;
}

#[tokio::test]
async fn rejects_client_from_foreign_ca() {
    let ca = Ca::new("test CA");
    let rogue = Ca::new("rogue CA");
    let exit = spawn_exit(&ca.node("exit1"));

    // TLS 1.3 lets the client finish before the server checks its certificate, so the
    // rejection may only surface once the control stream is used.
    let client = rogue.node_trusting("client1", &ca);
    let (_endpoint, conn) = dial(&client, KEY, exit, "exit1").await;
    let result = async { hello(&conn?, vec![], None).await }.await;
    assert!(
        result.is_err(),
        "server accepted a client from a foreign CA"
    );
}

#[tokio::test]
async fn rejects_untrusted_server() {
    let ca = Ca::new("test CA");
    let rogue = Ca::new("rogue CA");
    let exit = spawn_exit(&rogue.node("exit1"));

    let (_endpoint, conn) = dial(&ca.node("client1"), KEY, exit, "exit1").await;
    assert!(conn.is_err(), "client accepted a server from a foreign CA");
}

#[tokio::test]
async fn rejects_wrong_server_name() {
    let ca = Ca::new("test CA");
    let exit = spawn_exit(&ca.node("exit1"));

    let (_endpoint, conn) = dial(&ca.node("client1"), KEY, exit, "relay1").await;
    assert!(
        conn.is_err(),
        "client accepted a certificate for another name"
    );
}

#[tokio::test]
async fn xor_key_mismatch_never_connects() {
    let ca = Ca::new("test CA");
    let exit = spawn_exit(&ca.node("exit1"));
    let client = ca.node("client1");

    let attempt = tokio::time::timeout(NO_CONNECT_WAIT, dial(&client, b"other-key", exit, "exit1"));
    match attempt.await {
        Err(_elapsed) => {}
        Ok((_, conn)) => assert!(conn.is_err()),
    }
}

#[tokio::test]
async fn plain_quic_client_never_connects() {
    let ca = Ca::new("test CA");
    let exit = spawn_exit(&ca.node("exit1"));

    let mut endpoint = Endpoint::client(localhost()).unwrap();
    endpoint.set_default_client_config(
        ca.node("client1")
            .client_config(&QuicConfig::default())
            .unwrap(),
    );
    let attempt = tokio::time::timeout(NO_CONNECT_WAIT, connect(&endpoint, exit, "exit1"));
    match attempt.await {
        Err(_elapsed) => {}
        Ok(conn) => assert!(conn.is_err()),
    }
}

#[tokio::test]
async fn random_probes_get_no_reply() {
    let ca = Ca::new("test CA");
    let exit = spawn_exit(&ca.node("exit1"));
    let socket = tokio::net::UdpSocket::bind(localhost()).await.unwrap();
    socket.connect(exit).await.unwrap();

    // Without the key every probe decodes to random bytes; before long headers of foreign
    // versions were dropped, about 1 in 300 of these drew a Version Negotiation reply.
    let mut state = 0x9e37_79b9_7f4a_7c15u64;
    let mut probe = vec![0u8; 1400];
    for round in 0..30 {
        for _ in 0..100 {
            for chunk in probe.chunks_mut(8) {
                state ^= state << 13;
                state ^= state >> 7;
                state ^= state << 17;
                chunk.copy_from_slice(&state.to_le_bytes()[..chunk.len()]);
            }
            socket.send(&probe).await.unwrap();
        }
        tokio::time::sleep(Duration::from_millis(5)).await;
        let mut reply = [0u8; 2048];
        assert!(
            socket.try_recv(&mut reply).is_err(),
            "probe round {round} drew a reply"
        );
    }
    let mut reply = [0u8; 2048];
    let late = tokio::time::timeout(Duration::from_millis(500), socket.recv(&mut reply)).await;
    assert!(late.is_err(), "a probe drew a reply");
}

#[tokio::test]
async fn batches_queued_datagrams_and_waits_for_buffer_space() {
    let ca = Ca::new("test CA");
    let exit = spawn_exit(&ca.node("exit1"));
    let (_endpoint, conn) = dial(&ca.node("client1"), KEY, exit, "exit1").await;
    let conn = conn.unwrap();
    let (_control, _) = hello(&conn, vec![], None).await.unwrap();

    let count = 50u8;
    for i in 0..count {
        let packet = Bytes::from(vec![i; 1000]);
        assert_eq!(send_packet_wait(&conn, packet).await.unwrap(), Sent::Queued);
    }
    let oversized = Bytes::from(vec![0; 64 * 1024]);
    assert_eq!(
        send_packet_wait(&conn, oversized).await.unwrap(),
        Sent::TooLarge
    );

    let mut got = Vec::new();
    while got.len() < usize::from(count) {
        tokio::time::timeout(Duration::from_secs(5), recv_packets(&conn, &mut got, 128))
            .await
            .expect("echo timed out")
            .unwrap();
        got.retain(|packet| !heartbeat::is_heartbeat(packet));
    }
    // Loopback does not reorder or lose, so the echoes arrive in order.
    let firsts: Vec<u8> = got.iter().map(|p| p[0]).collect();
    assert_eq!(firsts, (0..count).collect::<Vec<_>>());
}

fn closed_with(e: &quinn::ConnectionError, reason: &[u8]) -> bool {
    matches!(e, quinn::ConnectionError::ApplicationClosed(close) if close.reason[..] == *reason)
}

#[tokio::test]
async fn heartbeats_keep_an_idle_link() {
    let ca = Ca::new("test CA");
    let (exit, mut ended) = spawn_exit_with(&ca.node("exit1"), SHORT_HEARTBEAT);
    let (_endpoint, conn) = dial(&ca.node("client1"), KEY, exit, "exit1").await;
    let conn = conn.unwrap();
    let (_control, _) = hello(&conn, vec![], None).await.unwrap();

    // Keep-alives come far less often than this: only the pings carry the link.
    let watch = heartbeat::watch(&conn, SHORT_HEARTBEAT);
    let gave_up = tokio::time::timeout(SHORT_HEARTBEAT * 3, watch).await;
    assert!(gave_up.is_err(), "the client gave up: {gave_up:?}");
    assert!(ended.try_recv().is_err(), "the exit gave up");
}

#[tokio::test]
async fn the_far_end_closes_a_link_whose_uplink_went_dark() {
    let ca = Ca::new("test CA");
    let (exit, mut ended) = spawn_exit_with(&ca.node("exit1"), SHORT_HEARTBEAT);
    let path = spawn_path(exit).await;
    let (_endpoint, conn) = dial(&ca.node("client1"), KEY, path.addr, "exit1").await;
    let conn = conn.unwrap();
    let (_control, _) = hello(&conn, vec![], None).await.unwrap();

    path.up.store(false, Relaxed);
    let started = Instant::now();
    // The client still hears the exit, so only the exit can tell; its close gets through.
    let closed = tokio::time::timeout(SHORT_HEARTBEAT * 2, conn.closed())
        .await
        .expect("the client was not told");
    assert!(
        started.elapsed() >= SHORT_HEARTBEAT,
        "after {:?}",
        started.elapsed()
    );
    assert!(closed_with(&closed, heartbeat::SILENT_PEER), "{closed}");
    let why = ended.recv().await.unwrap();
    assert!(
        matches!(why, Error::Unresponsive(t) if t == SHORT_HEARTBEAT),
        "{why}"
    );
}

#[tokio::test]
async fn the_near_end_gives_up_a_link_whose_downlink_went_dark() {
    let ca = Ca::new("test CA");
    let (exit, mut ended) = spawn_exit_with(&ca.node("exit1"), SHORT_HEARTBEAT);
    let path = spawn_path(exit).await;
    let (_endpoint, conn) = dial(&ca.node("client1"), KEY, path.addr, "exit1").await;
    let conn = conn.unwrap();
    let (_control, _) = hello(&conn, vec![], None).await.unwrap();

    path.down.store(false, Relaxed);
    let started = Instant::now();
    let watch = heartbeat::watch(&conn, SHORT_HEARTBEAT);
    let why = tokio::time::timeout(SHORT_HEARTBEAT * 2, watch)
        .await
        .expect("the client did not give up");
    assert!(
        started.elapsed() >= SHORT_HEARTBEAT,
        "after {:?}",
        started.elapsed()
    );
    assert!(
        matches!(why, Error::Unresponsive(t) if t == SHORT_HEARTBEAT),
        "{why}"
    );
    // The exit still hears the client, so it learns from the client's close.
    let why = tokio::time::timeout(Duration::from_secs(1), ended.recv())
        .await
        .expect("the exit was not told")
        .unwrap();
    assert!(
        matches!(&why, Error::Connection(e) if closed_with(e, heartbeat::SILENT_PEER)),
        "{why}"
    );
}

#[tokio::test]
async fn relay_tears_the_path_down_when_its_next_link_goes_dark() {
    let ca = Ca::new("test CA");
    let (exit, mut ended) = spawn_exit_with(&ca.node("exit1"), SHORT_HEARTBEAT);
    let path = spawn_path(exit).await;
    let relay = spawn_relay(&ca.node("relay1"), SHORT_HEARTBEAT);
    let (_endpoint, conn) = dial(&ca.node("client1"), KEY, relay, "relay1").await;
    let conn = conn.unwrap();
    let (_control, _) = hello(&conn, exit_route(path.addr), None).await.unwrap();
    assert_echo(&conn).await;

    path.up.store(false, Relaxed);
    // The exit notices, tells the relay, and the relay closes the client's link.
    let closed = tokio::time::timeout(SHORT_HEARTBEAT * 2, conn.closed())
        .await
        .expect("the path was not torn down");
    assert!(closed_with(&closed, b"relay closed"), "{closed}");
    let why = ended.recv().await.unwrap();
    assert!(matches!(why, Error::Unresponsive(_)), "{why}");
}
