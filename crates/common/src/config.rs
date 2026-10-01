use std::net::SocketAddr;
use std::path::{Path, PathBuf};

use ipnet::Ipv4Net;
use serde::Deserialize;
use serde::de::DeserializeOwned;

use crate::{Error, Result};

pub const DEFAULT_TUN_NAME: &str = "mt0";
/// Conservative default that leaves room for QUIC + UDP + IP headers on a 1500-byte path.
pub const DEFAULT_TUN_MTU: u16 = 1200;

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
}

impl Default for TunConfig {
    fn default() -> Self {
        Self {
            name: default_tun_name(),
            mtu: default_tun_mtu(),
        }
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
        validate_obfs(&cfg.obfs)?;
        Ok(cfg)
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExitConfig {
    #[serde(default)]
    pub tun: TunConfig,
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
    /// Present only on nodes that may act as the exit hop.
    pub exit: Option<ExitConfig>,
}

impl ServerConfig {
    pub fn load(path: impl AsRef<Path>) -> Result<Self> {
        let cfg: Self = load_toml(path)?;
        validate_obfs(&cfg.obfs)?;
        if let Some(exit) = &cfg.exit
            && exit.pool.prefix_len() > 30
        {
            return Err(Error::InvalidConfig(format!(
                "exit.pool {} is too small, need at least a /30",
                exit.pool
            )));
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
    }
}
