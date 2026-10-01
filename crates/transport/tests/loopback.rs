//! End-to-end transport tests over loopback UDP with throwaway certificates.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use magictunnel_common::config::DEFAULT_TUN_MTU;
use magictunnel_common::proto::{HelloReply, Hop};
use magictunnel_transport::quinn::{self, Endpoint};
use magictunnel_transport::{
    TlsMaterial, XorKey, accept_hello, client_endpoint, connect, hello, recv_packet, relay,
    send_packet, server_endpoint,
};
use rcgen::{
    BasicConstraints, CertificateParams, DnType, ExtendedKeyUsagePurpose, IsCa, Issuer, KeyPair,
    KeyUsagePurpose,
};
use rustls_pki_types::{CertificateDer, PrivateKeyDer};

const KEY: &[u8] = b"loopback-test-key";
const NO_CONNECT_WAIT: Duration = Duration::from_secs(2);

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
    }
}

/// Exit node: completes the handshake with each peer, then echoes every datagram. Peers that
/// fail the handshake are skipped, as the negative tests expect.
fn spawn_exit(tls: &TlsMaterial) -> SocketAddr {
    let endpoint = server_endpoint(localhost(), xor_key(KEY), tls).unwrap();
    let addr = endpoint.local_addr().unwrap();
    tokio::spawn(async move {
        while let Some(incoming) = endpoint.accept().await {
            let Ok(conn) = incoming.await else { continue };
            let Ok((mut control, hello)) = accept_hello(&conn).await else {
                continue;
            };
            assert!(hello.remaining.is_empty());
            control.send(&tunnel_reply()).await.unwrap();
            while let Ok(packet) = recv_packet(&conn).await {
                send_packet(&conn, packet).unwrap();
            }
        }
    });
    addr
}

/// Relay node: dials the next hop named in the handshake, relays the reply back, then
/// forwards datagrams in both directions.
fn spawn_relay(tls: &TlsMaterial) -> SocketAddr {
    let endpoint = server_endpoint(localhost(), xor_key(KEY), tls).unwrap();
    let addr = endpoint.local_addr().unwrap();
    tokio::spawn(async move {
        let upstream = endpoint.accept().await.unwrap().await.unwrap();
        let (mut control, hello) = accept_hello(&upstream).await.unwrap();
        let (next, rest) = hello.remaining.split_first().unwrap();
        let downstream = connect(&endpoint, next.addr, &next.server_name)
            .await
            .unwrap();
        let (_next_control, reply) = magictunnel_transport::hello(&downstream, rest.to_vec())
            .await
            .unwrap();
        control.send(&reply).await.unwrap();
        relay(&upstream, &downstream).await;
        drop(endpoint);
    });
    addr
}

async fn assert_echo(conn: &quinn::Connection) {
    let max = conn.max_datagram_size().unwrap();
    assert!(
        max >= usize::from(DEFAULT_TUN_MTU),
        "max datagram {max} < TUN MTU {DEFAULT_TUN_MTU}"
    );
    for i in 0..10u8 {
        let packet = Bytes::from(vec![i; usize::from(DEFAULT_TUN_MTU)]);
        send_packet(conn, packet.clone()).unwrap();
        let echoed = tokio::time::timeout(Duration::from_secs(5), recv_packet(conn))
            .await
            .expect("echo timed out")
            .unwrap();
        assert_eq!(echoed, packet);
    }
}

async fn dial(
    tls: &TlsMaterial,
    key: &[u8],
    addr: SocketAddr,
    server_name: &str,
) -> (Endpoint, magictunnel_transport::Result<quinn::Connection>) {
    let endpoint = client_endpoint(addr, xor_key(key), tls).unwrap();
    let conn = connect(&endpoint, addr, server_name).await;
    (endpoint, conn)
}

#[tokio::test]
async fn single_hop_handshake_and_datagrams() {
    let ca = Ca::new("test CA");
    let exit = spawn_exit(&ca.node("exit1"));

    let (_endpoint, conn) = dial(&ca.node("client1"), KEY, exit, "exit1").await;
    let conn = conn.unwrap();
    let (_control, reply) = hello(&conn, vec![]).await.unwrap();
    assert_eq!(reply, tunnel_reply());
    assert_echo(&conn).await;
}

#[tokio::test]
async fn two_hop_relay() {
    let ca = Ca::new("test CA");
    let exit = spawn_exit(&ca.node("exit1"));
    let relay = spawn_relay(&ca.node("relay1"));

    let (_endpoint, conn) = dial(&ca.node("client1"), KEY, relay, "relay1").await;
    let conn = conn.unwrap();
    let route = vec![Hop {
        addr: exit,
        server_name: "exit1".into(),
    }];
    let (_control, reply) = hello(&conn, route).await.unwrap();
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
    let result = async { hello(&conn?, vec![]).await }.await;
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
    endpoint.set_default_client_config(ca.node("client1").client_config().unwrap());
    let attempt = tokio::time::timeout(NO_CONNECT_WAIT, connect(&endpoint, exit, "exit1"));
    match attempt.await {
        Err(_elapsed) => {}
        Ok(conn) => assert!(conn.is_err()),
    }
}
