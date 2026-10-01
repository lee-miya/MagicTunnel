use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use quinn::{
    Connection, Endpoint, EndpointConfig, IdleTimeout, MtuDiscoveryConfig, Runtime, TokioRuntime,
    TransportConfig, VarInt,
};

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
const KEEP_ALIVE_INTERVAL: Duration = Duration::from_secs(10);
const IDLE_TIMEOUT: VarInt = VarInt::from_u32(30_000);
const DATAGRAM_BUFFER: usize = 2 * 1024 * 1024;

/// Transport parameters shared by every magicTunnel connection: datagrams on, exactly one
/// bidirectional control stream (opened by the dialer), no unidirectional streams.
pub fn transport_config() -> TransportConfig {
    let mut mtud = MtuDiscoveryConfig::default();
    mtud.upper_bound(MTU_UPPER_BOUND);

    let mut config = TransportConfig::default();
    config
        .max_concurrent_bidi_streams(VarInt::from_u32(1))
        .max_concurrent_uni_streams(VarInt::from_u32(0))
        .keep_alive_interval(Some(KEEP_ALIVE_INTERVAL))
        .max_idle_timeout(Some(IdleTimeout::from(IDLE_TIMEOUT)))
        .initial_mtu(INITIAL_MTU)
        .mtu_discovery_config(Some(mtud))
        .datagram_receive_buffer_size(Some(DATAGRAM_BUFFER))
        .datagram_send_buffer_size(DATAGRAM_BUFFER);
    config
}

/// Binds a UDP socket at `addr`, wraps it in [`XorSocket`], and builds a quinn endpoint on it.
pub fn bind_obfuscated(
    addr: SocketAddr,
    key: Arc<XorKey>,
    server_config: Option<quinn::ServerConfig>,
) -> Result<Endpoint> {
    let socket = std::net::UdpSocket::bind(addr)?;
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

/// Endpoint for a server node: accepts mTLS peers on `listen` and dials the next hop from the
/// same socket.
pub fn server_endpoint(
    listen: SocketAddr,
    key: Arc<XorKey>,
    tls: &TlsMaterial,
) -> Result<Endpoint> {
    let mut endpoint = bind_obfuscated(listen, key, Some(tls.server_config()?))?;
    endpoint.set_default_client_config(tls.client_config()?);
    Ok(endpoint)
}

/// Dial-only endpoint on an ephemeral port of the same address family as `first_hop`.
pub fn client_endpoint(
    first_hop: SocketAddr,
    key: Arc<XorKey>,
    tls: &TlsMaterial,
) -> Result<Endpoint> {
    let bind = match first_hop {
        SocketAddr::V4(_) => SocketAddr::from((Ipv4Addr::UNSPECIFIED, 0)),
        SocketAddr::V6(_) => SocketAddr::from((Ipv6Addr::UNSPECIFIED, 0)),
    };
    let mut endpoint = bind_obfuscated(bind, key, None)?;
    endpoint.set_default_client_config(tls.client_config()?);
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
