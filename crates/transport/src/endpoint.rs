use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use magictunnel_common::config::{Congestion, QuicConfig};
use quinn::congestion::{BbrConfig, CubicConfig, NewRenoConfig};
use quinn::{
    Connection, Endpoint, EndpointConfig, IdleTimeout, MtuDiscoveryConfig, Runtime, TokioRuntime,
    TransportConfig, VarInt,
};

use crate::heartbeat;
use crate::obfs::{XorKey, XorSocket};
use crate::tls::TlsMaterial;
use crate::{Error, Result};

/// UDP payload size assumed before MTU discovery. Large enough that a `DEFAULT_TUN_MTU` packet
/// fits in one datagram from the first packet on; plus `NONCE_LEN` and IPv6/UDP headers it
/// still fits a 1500-byte path.
pub const INITIAL_MTU: u16 = 1280;
/// Must stay at least `NONCE_LEN` below quinn's default `max_udp_payload_size` (1472), which
/// also sizes the receive buffers: peers send up to this much plus the nonce.
const MTU_UPPER_BOUND: u16 = 1452;
/// Incoming datagrams wait here until the data pump reads them; it only lags during bursts.
const DATAGRAM_RECEIVE_BUFFER: usize = 2 * 1024 * 1024;
/// Outgoing datagrams wait here for congestion window. Every byte queued is latency for the
/// tunnelled flows, so this is kept to a few milliseconds at the speeds a link sustains;
/// beyond it the oldest datagram is dropped (or, on the client uplink, the TUN is no longer
/// read, so the kernel queues and paces the local senders).
const DATAGRAM_SEND_BUFFER: usize = 512 * 1024;
/// Enough to read ahead a full batch of super-packet segments.
const SOCKET_BUFFER: usize = 4 * 1024 * 1024;

/// Transport parameters shared by every magicTunnel connection: datagrams on, exactly one
/// bidirectional control stream (opened by the dialer), no unidirectional streams.
pub fn transport_config(quic: &QuicConfig) -> TransportConfig {
    let mut mtud = MtuDiscoveryConfig::default();
    mtud.upper_bound(MTU_UPPER_BOUND);

    let mut config = TransportConfig::default();
    config
        .max_concurrent_bidi_streams(VarInt::from_u32(1))
        .max_concurrent_uni_streams(VarInt::from_u32(0))
        .keep_alive_interval(Some(Duration::from_secs(quic.keepalive_secs)))
        .max_idle_timeout(Some(idle_timeout(quic)))
        .initial_mtu(INITIAL_MTU)
        // Black-hole detection falls back to this, not to the initial MTU; at quinn's default
        // (1200) a full `DEFAULT_TUN_MTU` packet would no longer fit one datagram.
        .min_mtu(INITIAL_MTU)
        .mtu_discovery_config(Some(mtud))
        .datagram_receive_buffer_size(Some(DATAGRAM_RECEIVE_BUFFER))
        .datagram_send_buffer_size(DATAGRAM_SEND_BUFFER);
    match quic.congestion {
        Congestion::Cubic => config.congestion_controller_factory(Arc::new(CubicConfig::default())),
        Congestion::Bbr => config.congestion_controller_factory(Arc::new(BbrConfig::default())),
        Congestion::NewReno => {
            config.congestion_controller_factory(Arc::new(NewRenoConfig::default()))
        }
    };
    config
}

fn idle_timeout(quic: &QuicConfig) -> IdleTimeout {
    // Config validation caps the timeout far below VarInt's range.
    let millis = heartbeat::quic_idle_timeout(quic)
        .as_millis()
        .min(u128::from(u32::MAX));
    IdleTimeout::from(VarInt::from_u32(millis as u32))
}

/// Binds a UDP socket at `addr`, wraps it in [`XorSocket`], and builds a quinn endpoint on it.
pub fn bind_obfuscated(
    addr: SocketAddr,
    key: Arc<XorKey>,
    server_config: Option<quinn::ServerConfig>,
) -> Result<Endpoint> {
    let socket = std::net::UdpSocket::bind(addr)?;
    grow_socket_buffers(&socket);
    let runtime: Arc<dyn Runtime> = Arc::new(TokioRuntime);
    let inner = runtime.wrap_udp_socket(socket)?;
    let socket = Arc::new(XorSocket::new(inner, key));
    Ok(Endpoint::new_with_abstract_socket(
        EndpointConfig::default(),
        server_config,
        socket,
        runtime,
    )?)
}

/// Best effort: Linux caps the request at `net.core.{r,w}mem_max` (see the deployment docs).
fn grow_socket_buffers(socket: &std::net::UdpSocket) {
    let Ok(state) = quinn::udp::UdpSocketState::new(socket.into()) else {
        return;
    };
    let _ = state.set_recv_buffer_size(socket.into(), SOCKET_BUFFER);
    let _ = state.set_send_buffer_size(socket.into(), SOCKET_BUFFER);
    tracing::debug!(
        recv = ?state.recv_buffer_size(socket.into()),
        send = ?state.send_buffer_size(socket.into()),
        "UDP socket buffers"
    );
}

/// Endpoint for a server node: accepts mTLS peers on `listen` and dials the next hop from the
/// same socket.
pub fn server_endpoint(
    listen: SocketAddr,
    key: Arc<XorKey>,
    tls: &TlsMaterial,
    quic: &QuicConfig,
) -> Result<Endpoint> {
    let mut endpoint = bind_obfuscated(listen, key, Some(tls.server_config(quic)?))?;
    endpoint.set_default_client_config(tls.client_config(quic)?);
    Ok(endpoint)
}

/// Dial-only endpoint on an ephemeral port of the same address family as `first_hop`.
pub fn client_endpoint(
    first_hop: SocketAddr,
    key: Arc<XorKey>,
    tls: &TlsMaterial,
    quic: &QuicConfig,
) -> Result<Endpoint> {
    let bind = match first_hop {
        SocketAddr::V4(_) => SocketAddr::from((Ipv4Addr::UNSPECIFIED, 0)),
        SocketAddr::V6(_) => SocketAddr::from((Ipv6Addr::UNSPECIFIED, 0)),
    };
    let mut endpoint = bind_obfuscated(bind, key, None)?;
    endpoint.set_default_client_config(tls.client_config(quic)?);
    Ok(endpoint)
}

/// Dials `addr` with the endpoint's default client config, verifying the peer certificate
/// against `server_name`.
pub async fn connect(
    endpoint: &Endpoint,
    addr: SocketAddr,
    server_name: &str,
) -> Result<Connection> {
    let conn = endpoint.connect(addr, server_name)?.await?;
    if conn.max_datagram_size().is_none() {
        conn.close(VarInt::from_u32(0), b"datagrams required");
        return Err(Error::DatagramsUnsupported);
    }
    Ok(conn)
}
