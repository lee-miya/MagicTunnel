mod exit;
mod metrics;
mod nat;
mod node;
mod pool;
mod relay;
mod sessions;

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use anyhow::Context;
use clap::Parser;
use magictunnel_common::metrics::MetricsServer;
use magictunnel_common::{config::ServerConfig, logging};
use magictunnel_transport::quinn::VarInt;
use magictunnel_transport::{TlsMaterial, XorKey, heartbeat, server_endpoint};

use crate::exit::Exit;

const CLOSE_GRACE: Duration = Duration::from_secs(1);

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
        congestion = ?cfg.quic.congestion,
        "config loaded"
    );
    // Registered before touching the system so a signal can't skip the cleanup below.
    let shutdown = shutdown_signal().context("installing signal handlers")?;
    let tls = TlsMaterial::load(&cfg.tls).context("loading TLS material")?;
    let key = Arc::new(XorKey::new(cfg.obfs.xor_key.as_bytes())?);
    let metrics_server = match cfg.metrics.listen {
        Some(addr) => Some(
            MetricsServer::bind(addr)
                .await
                .with_context(|| format!("binding metrics.listen {addr}"))?,
        ),
        None => None,
    };

    // Pure relays touch neither TUN nor NAT, so they need no privileges.
    let exit = cfg.exit.as_ref().map(Exit::start).transpose()?;
    let endpoint = server_endpoint(cfg.listen, key, &tls, &cfg.quic)
        .with_context(|| format!("listening on {}", cfg.listen))?;
    let role = if exit.is_some() {
        "exit and relay"
    } else {
        "relay"
    };
    tracing::info!(listen = %cfg.listen, role, "accepting tunnels");

    let sessions = exit.as_ref().map(Exit::sessions);
    if let Some(server) = metrics_server {
        tracing::info!(addr = %server.local_addr()?, "serving metrics on /metrics");
        let sessions = sessions.clone();
        tokio::spawn(server.run(move || metrics::render(sessions.as_deref())));
    }
    if cfg.metrics.log_interval_secs > 0 {
        let interval = Duration::from_secs(cfg.metrics.log_interval_secs);
        tokio::spawn(metrics::log_periodically(interval, sessions));
    }

    let exit_downlink = async {
        match &exit {
            Some(exit) => exit.run().await,
            None => std::future::pending().await,
        }
    };
    let heartbeat_timeout = heartbeat::timeout(&cfg.quic);
    let result = tokio::select! {
        e = node::accept(&endpoint, exit.as_ref().map(Exit::handle), heartbeat_timeout) => Err(e),
        e = exit_downlink => Err(e.context("exit failed")),
        signal = shutdown => {
            tracing::info!("received {signal}, shutting down");
            Ok(())
        }
    };

    endpoint.close(VarInt::from_u32(0), b"server shutdown");
    let _ = tokio::time::timeout(CLOSE_GRACE, endpoint.wait_idle()).await;
    // Removes the NAT rules, then the TUN.
    drop(exit);
    result
}

/// Starts listening for shutdown signals immediately; the returned future resolves with the
/// name of the first one received.
fn shutdown_signal() -> std::io::Result<impl Future<Output = &'static str>> {
    use tokio::signal::unix::{SignalKind, signal};
    let mut int = signal(SignalKind::interrupt())?;
    let mut term = signal(SignalKind::terminate())?;
    Ok(async move {
        tokio::select! {
            _ = int.recv() => "SIGINT",
            _ = term.recv() => "SIGTERM",
        }
    })
}
