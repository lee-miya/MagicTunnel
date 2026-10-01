use std::path::PathBuf;

use anyhow::Context;
use clap::Parser;
use magictunnel_common::{config::ServerConfig, logging};

#[derive(Debug, Parser)]
#[command(name = "mt-server", version, about = "magicTunnel relay/exit server")]
struct Args {
    /// Path to the server TOML config.
    #[arg(short, long, default_value = "server.toml")]
    config: PathBuf,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = Args::parse();
    let cfg = ServerConfig::load(&args.config)
        .with_context(|| format!("loading {}", args.config.display()))?;
    logging::init(&cfg.log.level);

    tracing::info!(
        listen = %cfg.listen,
        exit_pool = ?cfg.exit.as_ref().map(|e| e.pool),
        "config loaded"
    );

    anyhow::bail!("relay/exit data plane is not implemented yet")
}
