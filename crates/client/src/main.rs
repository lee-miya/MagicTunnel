use std::path::PathBuf;

use anyhow::Context;
use clap::Parser;
use magictunnel_common::{config::ClientConfig, logging};

#[derive(Debug, Parser)]
#[command(name = "mt-client", version, about = "magicTunnel client")]
struct Args {
    /// Path to the client TOML config.
    #[arg(short, long, default_value = "client.toml")]
    config: PathBuf,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = Args::parse();
    let cfg = ClientConfig::load(&args.config)
        .with_context(|| format!("loading {}", args.config.display()))?;
    logging::init(&cfg.log.level);

    let path: Vec<_> = cfg.route.iter().map(|h| h.server_name.as_str()).collect();
    tracing::info!(tun = %cfg.tun.name, mtu = cfg.tun.mtu, route = ?path, "config loaded");

    anyhow::bail!("tunnel data plane is not implemented yet")
}
