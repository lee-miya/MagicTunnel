mod metrics;
mod pump;
mod route;
mod session;
mod tun;

use std::hash::{BuildHasher, RandomState};
use std::path::PathBuf;
use std::pin::pin;
use std::time::Duration;

use anyhow::Context;
use clap::Parser;
use magictunnel_common::metrics::MetricsServer;
use magictunnel_common::proto::Resume;
use magictunnel_common::{config::ClientConfig, logging};

use crate::route::RouteGuard;
use crate::session::Session;

const FIRST_RETRY_DELAY: Duration = Duration::from_secs(1);

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
    let metrics_server = match cfg.metrics.listen {
        Some(addr) => Some(
            MetricsServer::bind(addr)
                .await
                .with_context(|| format!("binding metrics.listen {addr}"))?,
        ),
        None => None,
    };
    if let Some(server) = metrics_server {
        tracing::info!(addr = %server.local_addr()?, "serving metrics on /metrics");
        tokio::spawn(server.run(metrics::render));
    }
    if cfg.metrics.log_interval_secs > 0 {
        let interval = Duration::from_secs(cfg.metrics.log_interval_secs);
        tokio::spawn(metrics::log_periodically(interval));
    }

    // A first connection that fails is most likely a configuration problem: report it.
    let session = Session::establish(&cfg, None).await?;
    run(&cfg, session).await
}

/// Brings the tunnel up and pumps packets until shutdown, re-establishing the session when it
/// fails. The TUN and routes stay in place while reconnecting, so traffic waits for the
/// tunnel instead of leaking onto the physical network. Routes are restored and the TUN is
/// removed on every exit path, in that order.
async fn run(cfg: &ClientConfig, mut session: Session) -> anyhow::Result<()> {
    // Registered before touching the system so a signal can't skip the cleanup below.
    let mut shutdown = pin!(shutdown_signal().context("installing signal handlers")?);
    let mut mtu = session_mtu(cfg, &session)?;
    if mtu < cfg.tun.mtu {
        tracing::info!(
            configured = cfg.tun.mtu,
            exit = session.exit_mtu,
            mtu,
            "clamped TUN MTU"
        );
    }

    let tun = tun::create(
        &cfg.tun.name,
        session.tunnel_ip,
        session.prefix_len,
        mtu,
        cfg.tun.offload,
    )?;
    let _routes = RouteGuard::install(&tun, cfg.route[0].addr)?;
    tracing::info!(
        tun = %tun.name,
        index = tun.index,
        addr = %session.tunnel_ip,
        prefix_len = session.prefix_len,
        mtu,
        offload = magictunnel_tunio::offload_enabled(&tun.dev),
        "tunnel up"
    );

    loop {
        metrics::set_current(Some(session.conn.clone()));
        let e = tokio::select! {
            e = pump::run(&tun.dev, &session.conn, cfg.tun.mtu) => e,
            signal = &mut shutdown => {
                tracing::info!("received {signal}, shutting down");
                metrics::set_current(None);
                session.close().await;
                return Ok(());
            }
        };
        metrics::set_current(None);
        if !cfg.reconnect.enabled {
            session.close().await;
            return Err(e.context("tunnel failed"));
        }
        tracing::warn!("tunnel lost, reconnecting: {e:#}");
        let resume = session.resume();
        let old = (session.tunnel_ip, session.prefix_len);
        session.close().await;

        session = tokio::select! {
            s = reconnect(cfg, resume) => s,
            signal = &mut shutdown => {
                tracing::info!("received {signal} while reconnecting, shutting down");
                return Ok(());
            }
        };
        metrics::RECONNECTS.inc();

        if (session.tunnel_ip, session.prefix_len) != old {
            tracing::warn!(
                old = %old.0,
                new = %session.tunnel_ip,
                "exit assigned a new tunnel address; existing connections will break"
            );
            tun.readdress(old.0, session.tunnel_ip, session.prefix_len)?;
        }
        let new_mtu = session_mtu(cfg, &session)?;
        if new_mtu != mtu {
            tun.set_mtu(new_mtu)?;
            tracing::info!(old = mtu, new = new_mtu, "TUN MTU changed");
            mtu = new_mtu;
        }
        tracing::info!(
            tun = %tun.name,
            addr = %session.tunnel_ip,
            mtu,
            reconnects = metrics::RECONNECTS.get(),
            "tunnel restored"
        );
    }
}

/// Dials the route until it works, backing off exponentially (with jitter, so clients of a
/// restarted exit do not return in lockstep) up to `reconnect.max_delay_secs`.
async fn reconnect(cfg: &ClientConfig, resume: Resume) -> Session {
    let max_delay = Duration::from_secs(cfg.reconnect.max_delay_secs);
    let mut delay = FIRST_RETRY_DELAY.min(max_delay);
    let mut attempt = 1u32;
    loop {
        match Session::establish(cfg, Some(resume.clone())).await {
            Ok(session) => return session,
            Err(e) => {
                let wait = jitter(delay);
                tracing::warn!(
                    attempt,
                    retry_in_ms = wait.as_millis() as u64,
                    "reconnect failed: {e:#}"
                );
                tokio::time::sleep(wait).await;
                delay = (delay * 2).min(max_delay);
                attempt += 1;
            }
        }
    }
}

/// `delay` scaled by a random factor in [0.75, 1.25).
fn jitter(delay: Duration) -> Duration {
    let r = RandomState::new().hash_one(delay) % 1000;
    delay.mul_f64(0.75 + r as f64 / 2000.0)
}

fn session_mtu(cfg: &ClientConfig, session: &Session) -> anyhow::Result<u16> {
    let max_datagram = session
        .conn
        .max_datagram_size()
        .context("first hop stopped accepting datagrams")?;
    tun::clamp_mtu(cfg.tun.mtu, session.exit_mtu, max_datagram)
}

/// Starts listening for shutdown signals immediately; the returned future resolves with the
/// name of the first one received.
#[cfg(unix)]
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

/// Closing the console window, logoff and shutdown give the process a few seconds, enough to
/// restore routes.
#[cfg(windows)]
fn shutdown_signal() -> std::io::Result<impl Future<Output = &'static str>> {
    use tokio::signal::windows;
    let mut ctrl_c = windows::ctrl_c()?;
    let mut ctrl_break = windows::ctrl_break()?;
    let mut close = windows::ctrl_close()?;
    let mut logoff = windows::ctrl_logoff()?;
    let mut shutdown = windows::ctrl_shutdown()?;
    Ok(async move {
        tokio::select! {
            _ = ctrl_c.recv() => "Ctrl-C",
            _ = ctrl_break.recv() => "Ctrl-Break",
            _ = close.recv() => "console close",
            _ = logoff.recv() => "logoff",
            _ = shutdown.recv() => "system shutdown",
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn jitter_stays_within_a_quarter() {
        for secs in [1, 2, 30] {
            let d = Duration::from_secs(secs);
            for _ in 0..100 {
                let j = jitter(d);
                assert!(
                    j >= d.mul_f64(0.75) && j < d.mul_f64(1.25),
                    "{j:?} for {d:?}"
                );
            }
        }
    }
}
