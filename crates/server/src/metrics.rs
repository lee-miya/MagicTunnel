//! Process-wide counters of the server, rendered for `GET /metrics` and the periodic stats log.

use std::sync::Arc;
use std::time::{Duration, Instant};

use magictunnel_common::metrics::{Counter, Exposition, Gauge, Traffic};
use magictunnel_transport::{FRAG_NEEDED_SENT, OVERSIZED_DROPS};

use crate::sessions::Sessions;

/// Exit tunnels: up is client to internet (written to the exit TUN), down is the reverse.
pub static EXIT_UP: Traffic = Traffic::new();
pub static EXIT_DOWN: Traffic = Traffic::new();
/// Relayed tunnels: up is towards the next hop.
pub static RELAY_UP: Traffic = Traffic::new();
pub static RELAY_DOWN: Traffic = Traffic::new();

pub static EXIT_SESSIONS: Gauge = Gauge::new();
pub static RELAY_SESSIONS: Gauge = Gauge::new();
pub static EXIT_SESSIONS_TOTAL: Counter = Counter::new();
pub static RELAY_SESSIONS_TOTAL: Counter = Counter::new();
/// Exit sessions that got their previous tunnel address back.
pub static RESUMED_SESSIONS: Counter = Counter::new();
/// QUIC handshakes that failed: wrong XOR key, bad certificate, timeouts.
pub static HANDSHAKE_FAILURES: Counter = Counter::new();
/// Tunnels refused or broken during setup after the QUIC handshake.
pub static SETUP_FAILURES: Counter = Counter::new();

/// Client packets with a source other than the session's address, or for another client.
pub static DROP_FILTERED: Counter = Counter::new();
/// Packets from the exit TUN for an address no session holds.
pub static DROP_NO_SESSION: Counter = Counter::new();
pub static DROP_NOT_IPV4: Counter = Counter::new();
pub static TUN_WRITE_ERRORS: Counter = Counter::new();

pub fn render<C: Clone>(sessions: Option<&Sessions<C>>) -> String {
    let mut out = Exposition::default();
    out.traffic(
        "magictunnel_exit",
        "Tunnelled packets ending at this exit",
        &EXIT_UP,
        &EXIT_DOWN,
    );
    out.traffic(
        "magictunnel_relay",
        "Packets relayed between hops",
        &RELAY_UP,
        &RELAY_DOWN,
    );
    out.family(
        "magictunnel_sessions",
        "gauge",
        "Open tunnels by role",
        &[
            ("role=\"exit\"", EXIT_SESSIONS.get()),
            ("role=\"relay\"", RELAY_SESSIONS.get()),
        ],
    );
    out.family(
        "magictunnel_sessions_total",
        "counter",
        "Tunnels set up by role",
        &[
            ("role=\"exit\"", EXIT_SESSIONS_TOTAL.get()),
            ("role=\"relay\"", RELAY_SESSIONS_TOTAL.get()),
        ],
    );
    out.counter(
        "magictunnel_icmp_frag_needed_sent_total",
        "ICMP fragmentation-needed errors sent back for packets too big for the next link",
        FRAG_NEEDED_SENT.get(),
    );
    out.counter(
        "magictunnel_resumed_sessions_total",
        "Exit sessions that got their previous tunnel address back",
        RESUMED_SESSIONS.get(),
    );
    out.counter(
        "magictunnel_quic_handshake_failures_total",
        "Incoming QUIC handshakes that failed (wrong XOR key, certificate, timeout)",
        HANDSHAKE_FAILURES.get(),
    );
    out.counter(
        "magictunnel_setup_failures_total",
        "Tunnels refused or failed after the QUIC handshake",
        SETUP_FAILURES.get(),
    );
    out.family(
        "magictunnel_dropped_packets_total",
        "counter",
        "Packets dropped by reason",
        &[
            ("reason=\"too_large\"", OVERSIZED_DROPS.get()),
            ("reason=\"filtered\"", DROP_FILTERED.get()),
            ("reason=\"no_session\"", DROP_NO_SESSION.get()),
            ("reason=\"not_ipv4\"", DROP_NOT_IPV4.get()),
            ("reason=\"tun_write\"", TUN_WRITE_ERRORS.get()),
        ],
    );
    if let Some(sessions) = sessions {
        let (leased, capacity) = sessions.usage();
        out.gauge(
            "magictunnel_pool_leased",
            "Tunnel addresses currently leased",
            leased,
        );
        out.gauge(
            "magictunnel_pool_capacity",
            "Tunnel addresses available to clients",
            capacity,
        );
    }
    out.finish()
}

/// Logs a traffic summary every `interval` until cancelled.
pub async fn log_periodically<C: Clone>(interval: Duration, sessions: Option<Arc<Sessions<C>>>) {
    let mut last = Snapshot::take();
    let mut ticker = tokio::time::interval_at(tokio::time::Instant::now() + interval, interval);
    loop {
        ticker.tick().await;
        let now = Snapshot::take();
        let secs = now.at.duration_since(last.at).as_secs_f64().max(1e-3);
        let mbps = |bytes: u64, before: u64| (bytes - before) as f64 * 8.0 / secs / 1e6;
        let drops = now.drops - last.drops;
        tracing::info!(
            exit_sessions = EXIT_SESSIONS.get(),
            relay_sessions = RELAY_SESSIONS.get(),
            pool_leased = sessions.as_ref().map(|s| s.usage().0),
            exit_up_mbps = format_args!("{:.2}", mbps(now.exit_up, last.exit_up)),
            exit_down_mbps = format_args!("{:.2}", mbps(now.exit_down, last.exit_down)),
            relay_up_mbps = format_args!("{:.2}", mbps(now.relay_up, last.relay_up)),
            relay_down_mbps = format_args!("{:.2}", mbps(now.relay_down, last.relay_down)),
            drops,
            "stats"
        );
        last = now;
    }
}

struct Snapshot {
    at: Instant,
    exit_up: u64,
    exit_down: u64,
    relay_up: u64,
    relay_down: u64,
    drops: u64,
}

impl Snapshot {
    fn take() -> Self {
        Self {
            at: Instant::now(),
            exit_up: EXIT_UP.bytes(),
            exit_down: EXIT_DOWN.bytes(),
            relay_up: RELAY_UP.bytes(),
            relay_down: RELAY_DOWN.bytes(),
            drops: OVERSIZED_DROPS.get()
                + DROP_FILTERED.get()
                + DROP_NO_SESSION.get()
                + DROP_NOT_IPV4.get()
                + TUN_WRITE_ERRORS.get(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn renders_every_family_once() {
        let text = render::<()>(None);
        for name in [
            "magictunnel_exit_packets_total",
            "magictunnel_relay_bytes_total",
            "magictunnel_sessions",
            "magictunnel_dropped_packets_total",
        ] {
            assert_eq!(
                text.matches(&format!("# TYPE {name} ")).count(),
                1,
                "{name}"
            );
        }
        assert!(!text.contains("magictunnel_pool_leased"));
    }
}
