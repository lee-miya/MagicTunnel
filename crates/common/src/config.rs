use std::net::{Ipv4Addr, SocketAddr};
use std::path::{Path, PathBuf};

use ipnet::Ipv4Net;
use serde::Deserialize;
use serde::de::DeserializeOwned;

use crate::proto::MAX_HOPS;
use crate::{Error, Result};

/// macOS only allows `utunN` names; a bare `utun` lets the kernel pick a free unit.
#[cfg(target_os = "macos")]
pub const DEFAULT_TUN_NAME: &str = "utun";
#[cfg(not(target_os = "macos"))]
pub const DEFAULT_TUN_NAME: &str = "mt0";
/// Conservative default that leaves room for QUIC + UDP + IP headers on a 1500-byte path.
pub const DEFAULT_TUN_MTU: u16 = 1200;
/// QUIC caps the idle timeout far higher, but a dead hop should not hold a tunnel for long.
const MAX_IDLE_TIMEOUT_SECS: u64 = 600;
/// Linux's own limit on TUN queues is 256; beyond a few per core there is nothing to gain.
const MAX_TUN_QUEUES: usize = 64;
/// glibc's resolver ignores nameservers past the third.
pub const MAX_DNS_SERVERS: usize = 3;

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LogConfig {
    #[serde(default = "default_log_level")]
    pub level: String,
}

impl Default for LogConfig {
    fn default() -> Self {
        Self {
            level: default_log_level(),
        }
    }
}

/// mTLS material: the CA used to verify peers, plus this node's own certificate and key.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TlsConfig {
    pub ca: PathBuf,
    pub cert: PathBuf,
    pub key: PathBuf,
}

/// UDP-level XOR obfuscation. This is not encryption; QUIC/TLS provides confidentiality.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ObfsConfig {
    pub xor_key: String,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HopConfig {
    pub addr: SocketAddr,
    /// Must match a SAN in the hop's certificate.
    pub server_name: String,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TunConfig {
    #[serde(default = "default_tun_name")]
    pub name: String,
    #[serde(default = "default_tun_mtu")]
    pub mtu: u16,
    /// Linux only: exchange TSO/GRO super-packets with the kernel (virtio-net header), so
    /// bulk TCP crosses the TUN in a fraction of the syscalls. Ignored elsewhere.
    #[serde(default = "default_offload")]
    pub offload: bool,
}

impl Default for TunConfig {
    fn default() -> Self {
        Self {
            name: default_tun_name(),
            mtu: default_tun_mtu(),
            offload: default_offload(),
        }
    }
}

/// QUIC settings of every link a node dials or accepts. Both ends of a link use the smaller
/// idle timeout.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct QuicConfig {
    /// How often an otherwise idle link sends a keep-alive.
    #[serde(default = "default_keepalive_secs")]
    pub keepalive_secs: u64,
    /// Silence after which a link counts as dead.
    #[serde(default = "default_idle_timeout_secs")]
    pub idle_timeout_secs: u64,
    #[serde(default)]
    pub congestion: Congestion,
}

impl Default for QuicConfig {
    fn default() -> Self {
        Self {
            keepalive_secs: default_keepalive_secs(),
            idle_timeout_secs: default_idle_timeout_secs(),
            congestion: Congestion::default(),
        }
    }
}

impl QuicConfig {
    fn validate(&self) -> Result<()> {
        if self.keepalive_secs == 0 || self.keepalive_secs >= self.idle_timeout_secs {
            return Err(Error::InvalidConfig(format!(
                "quic.keepalive_secs ({}) must be at least 1 and below quic.idle_timeout_secs ({})",
                self.keepalive_secs, self.idle_timeout_secs
            )));
        }
        if self.idle_timeout_secs > MAX_IDLE_TIMEOUT_SECS {
            return Err(Error::InvalidConfig(format!(
                "quic.idle_timeout_secs must be at most {MAX_IDLE_TIMEOUT_SECS}"
            )));
        }
        Ok(())
    }
}

/// Congestion controller of each QUIC link.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Congestion {
    #[default]
    Cubic,
    /// Loss-tolerant; usually faster on lossy long-distance links. quinn marks it
    /// experimental.
    Bbr,
    NewReno,
}

/// Prometheus endpoint and periodic stats log.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MetricsConfig {
    /// Serves `GET /metrics` in the Prometheus text format; disabled when unset. Plain HTTP
    /// without authentication, so keep it on loopback or a private network.
    pub listen: Option<SocketAddr>,
    /// Logs a traffic summary at info level every this many seconds; 0 disables it.
    #[serde(default)]
    pub log_interval_secs: u64,
}

/// Client behaviour when an established tunnel fails.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReconnectConfig {
    /// Keep the TUN and routes (so nothing leaks around the tunnel) and dial the route again
    /// with exponential backoff. When off, the client restores the network and exits.
    #[serde(default = "default_true")]
    pub enabled: bool,
    /// Upper bound of the backoff between attempts.
    #[serde(default = "default_reconnect_max_delay_secs")]
    pub max_delay_secs: u64,
}

impl Default for ReconnectConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            max_delay_secs: default_reconnect_max_delay_secs(),
        }
    }
}

/// Client DNS takeover.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DnsConfig {
    /// While the tunnel is up the system resolves through these, and the route takeover
    /// carries the queries through the tunnel; the previous settings return when the client
    /// stops. IPv4 only, like the tunnel. Empty leaves system DNS alone.
    #[serde(default)]
    pub servers: Vec<Ipv4Addr>,
}

impl DnsConfig {
    fn validate(&self) -> Result<()> {
        if self.servers.len() > MAX_DNS_SERVERS {
            return Err(Error::InvalidConfig(format!(
                "dns.servers has {} entries, at most {MAX_DNS_SERVERS} are allowed",
                self.servers.len()
            )));
        }
        if let Some(bad) = self
            .servers
            .iter()
            .find(|ip| ip.is_unspecified() || ip.is_broadcast() || ip.is_multicast())
        {
            return Err(Error::InvalidConfig(format!(
                "dns.servers: {bad} is not a unicast address"
            )));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClientConfig {
    #[serde(default)]
    pub log: LogConfig,
    pub tls: TlsConfig,
    pub obfs: ObfsConfig,
    #[serde(default)]
    pub tun: TunConfig,
    #[serde(default)]
    pub quic: QuicConfig,
    #[serde(default)]
    pub reconnect: ReconnectConfig,
    #[serde(default)]
    pub metrics: MetricsConfig,
    #[serde(default)]
    pub dns: DnsConfig,
    /// Full path chosen by the client, first hop first; the last hop is the exit.
    #[serde(rename = "route")]
    pub route: Vec<HopConfig>,
}

impl ClientConfig {
    pub fn load(path: impl AsRef<Path>) -> Result<Self> {
        let cfg: Self = load_toml(path)?;
        if cfg.route.is_empty() {
            return Err(Error::InvalidConfig(
                "client config needs at least one [[route]] hop".into(),
            ));
        }
        if cfg.route.len() > MAX_HOPS {
            return Err(Error::InvalidConfig(format!(
                "route has {} hops, at most {MAX_HOPS} are allowed",
                cfg.route.len()
            )));
        }
        if cfg.reconnect.max_delay_secs == 0 {
            return Err(Error::InvalidConfig(
                "reconnect.max_delay_secs must be at least 1".into(),
            ));
        }
        validate_obfs(&cfg.obfs)?;
        cfg.quic.validate()?;
        cfg.dns.validate()?;
        Ok(cfg)
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExitTunConfig {
    #[serde(default = "default_tun_name")]
    pub name: String,
    #[serde(default = "default_tun_mtu")]
    pub mtu: u16,
    /// See [`TunConfig::offload`].
    #[serde(default = "default_offload")]
    pub offload: bool,
    /// Linux multi-queue TUN: the kernel spreads flows over this many queues, each read by
    /// its own task. 0 means one per CPU.
    #[serde(default)]
    pub queues: usize,
}

impl Default for ExitTunConfig {
    fn default() -> Self {
        Self {
            name: default_tun_name(),
            mtu: default_tun_mtu(),
            offload: default_offload(),
            queues: 0,
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExitConfig {
    #[serde(default)]
    pub tun: ExitTunConfig,
    /// Tunnel address pool; the first host address is used by the exit TUN itself.
    pub pool: Ipv4Net,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ServerConfig {
    #[serde(default)]
    pub log: LogConfig,
    pub listen: SocketAddr,
    pub tls: TlsConfig,
    pub obfs: ObfsConfig,
    #[serde(default)]
    pub quic: QuicConfig,
    #[serde(default)]
    pub metrics: MetricsConfig,
    /// Present only on nodes that may act as the exit hop.
    pub exit: Option<ExitConfig>,
}

impl ServerConfig {
    pub fn load(path: impl AsRef<Path>) -> Result<Self> {
        let cfg: Self = load_toml(path)?;
        validate_obfs(&cfg.obfs)?;
        cfg.quic.validate()?;
        if let Some(exit) = &cfg.exit {
            if exit.pool.prefix_len() > 30 {
                return Err(Error::InvalidConfig(format!(
                    "exit.pool {} is too small, need at least a /30",
                    exit.pool
                )));
            }
            if exit.tun.queues > MAX_TUN_QUEUES {
                return Err(Error::InvalidConfig(format!(
                    "exit.tun.queues must be at most {MAX_TUN_QUEUES}"
                )));
            }
        }
        Ok(cfg)
    }
}

fn load_toml<T: DeserializeOwned>(path: impl AsRef<Path>) -> Result<T> {
    let path = path.as_ref();
    let text = std::fs::read_to_string(path).map_err(|source| Error::Io {
        path: path.to_owned(),
        source,
    })?;
    toml::from_str(&text).map_err(|source| Error::ConfigParse {
        path: path.to_owned(),
        source,
    })
}

fn validate_obfs(obfs: &ObfsConfig) -> Result<()> {
    if obfs.xor_key.is_empty() {
        return Err(Error::InvalidConfig(
            "obfs.xor_key must not be empty".into(),
        ));
    }
    Ok(())
}

fn default_log_level() -> String {
    "info".into()
}

fn default_tun_name() -> String {
    DEFAULT_TUN_NAME.into()
}

fn default_tun_mtu() -> u16 {
    DEFAULT_TUN_MTU
}

fn default_offload() -> bool {
    true
}

fn default_true() -> bool {
    true
}

fn default_keepalive_secs() -> u64 {
    10
}

fn default_idle_timeout_secs() -> u64 {
    30
}

fn default_reconnect_max_delay_secs() -> u64 {
    30
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_example_configs() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../config");
        let client = ClientConfig::load(root.join("client.example.toml")).unwrap();
        assert_eq!(client.route.len(), 2);
        assert_eq!(client.tun.mtu, DEFAULT_TUN_MTU);

        let server = ServerConfig::load(root.join("server.example.toml")).unwrap();
        assert!(server.exit.is_some());

        let relay = ServerConfig::load(root.join("relay.example.toml")).unwrap();
        assert!(relay.exit.is_none());
    }

    #[test]
    fn rejects_overlong_route() {
        let hop = "[[route]]\naddr = \"192.0.2.1:4433\"\nserver_name = \"relay1\"\n";
        let base = "[tls]\nca = \"ca\"\ncert = \"c\"\nkey = \"k\"\n[obfs]\nxor_key = \"x\"\n";
        let dir = std::env::temp_dir().join(format!("mt-config-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("client.toml");

        std::fs::write(&path, format!("{base}{}", hop.repeat(MAX_HOPS))).unwrap();
        assert_eq!(ClientConfig::load(&path).unwrap().route.len(), MAX_HOPS);
        std::fs::write(&path, format!("{base}{}", hop.repeat(MAX_HOPS + 1))).unwrap();
        assert!(ClientConfig::load(&path).is_err());
        std::fs::remove_dir_all(&dir).unwrap();
    }

    const CLIENT: &str = "[tls]\nca = \"ca\"\ncert = \"c\"\nkey = \"k\"\n[obfs]\nxor_key = \"x\"\n\
                          [[route]]\naddr = \"192.0.2.1:4433\"\nserver_name = \"exit1\"\n";

    fn load_client(extra: &str) -> Result<ClientConfig> {
        static NEXT: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
        let dir = std::env::temp_dir().join(format!(
            "mt-config-test-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("client.toml");
        std::fs::write(&path, format!("{extra}\n{CLIENT}")).unwrap();
        let cfg = ClientConfig::load(&path);
        std::fs::remove_dir_all(&dir).unwrap();
        cfg
    }

    #[test]
    fn hardening_defaults() {
        let cfg = load_client("").unwrap();
        assert!(cfg.tun.offload);
        assert_eq!(
            (cfg.quic.keepalive_secs, cfg.quic.idle_timeout_secs),
            (10, 30)
        );
        assert_eq!(cfg.quic.congestion, Congestion::Cubic);
        assert!(cfg.reconnect.enabled);
        assert_eq!(cfg.reconnect.max_delay_secs, 30);
        assert!(cfg.metrics.listen.is_none());
        assert_eq!(cfg.metrics.log_interval_secs, 0);
    }

    #[test]
    fn parses_hardening_options() {
        let cfg = load_client(
            "[quic]\nkeepalive_secs = 2\nidle_timeout_secs = 5\ncongestion = \"bbr\"\n\
             [reconnect]\nenabled = false\nmax_delay_secs = 5\n\
             [metrics]\nlisten = \"127.0.0.1:9100\"\nlog_interval_secs = 60\n",
        )
        .unwrap();
        assert_eq!(cfg.quic.congestion, Congestion::Bbr);
        assert!(!cfg.reconnect.enabled);
        assert_eq!(cfg.metrics.listen, Some("127.0.0.1:9100".parse().unwrap()));
        assert!(load_client("[quic]\ncongestion = \"newreno\"\n").is_ok());
        assert!(load_client("[quic]\ncongestion = \"vegas\"\n").is_err());
    }

    #[test]
    fn rejects_inconsistent_timers() {
        for quic in [
            "keepalive_secs = 0",
            "keepalive_secs = 30",
            "keepalive_secs = 10\nidle_timeout_secs = 5",
            "idle_timeout_secs = 601",
        ] {
            assert!(load_client(&format!("[quic]\n{quic}\n")).is_err(), "{quic}");
        }
        assert!(load_client("[reconnect]\nmax_delay_secs = 0\n").is_err());
    }

    #[test]
    fn parses_dns_servers() {
        assert!(load_client("").unwrap().dns.servers.is_empty());
        let cfg = load_client("[dns]\nservers = [\"1.1.1.1\", \"8.8.8.8\"]\n").unwrap();
        assert_eq!(
            cfg.dns.servers,
            [Ipv4Addr::new(1, 1, 1, 1), Ipv4Addr::new(8, 8, 8, 8)]
        );
        for bad in [
            "[\"1.1.1.1\", \"1.0.0.1\", \"8.8.8.8\", \"8.8.4.4\"]",
            "[\"0.0.0.0\"]",
            "[\"255.255.255.255\"]",
            "[\"224.0.0.251\"]",
            "[\"2606:4700::1111\"]",
            "[\"dns.example\"]",
        ] {
            assert!(
                load_client(&format!("[dns]\nservers = {bad}\n")).is_err(),
                "{bad}"
            );
        }
    }
}
