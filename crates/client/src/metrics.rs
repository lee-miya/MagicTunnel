//! Process-wide counters of the client, rendered for `GET /metrics` and the periodic stats log.

use std::sync::Mutex;
use std::time::{Duration, Instant};

use magictunnel_common::metrics::{Counter, Exposition, Gauge, Traffic};
use magictunnel_transport::quinn::Connection;
use magictunnel_transport::{FRAG_NEEDED_SENT, OVERSIZED_DROPS};

/// Up is TUN to tunnel, down is tunnel to TUN.
pub static UP: Traffic = Traffic::new();
pub static DOWN: Traffic = Traffic::new();
pub static DROP_NOT_IPV4: Counter = Counter::new();
pub static TUN_WRITE_ERRORS: Counter = Counter::new();
pub static RECONNECTS: Counter = Counter::new();
pub static CONNECTED: Gauge = Gauge::new();
/// The live connection to the first hop, for its QUIC path statistics.
pub static CURRENT: Mutex<Option<Connection>> = Mutex::new(None);

pub fn set_current(conn: Option<Connection>) {
    CONNECTED.set(i64::from(conn.is_some()));
    *CURRENT.lock().expect("metrics lock poisoned") = conn;
}

fn current() -> Option<Connection> {
    CURRENT.lock().expect("metrics lock poisoned").clone()
}

pub fn render() -> String {
    let mut out = Exposition::default();
    out.traffic("magictunnel_client", "Tunnelled", &UP, &DOWN);
    out.family(
        "magictunnel_dropped_packets_total",
        "counter",
        "Packets dropped by reason",
        &[
            ("reason=\"too_large\"", OVERSIZED_DROPS.get()),
            ("reason=\"not_ipv4\"", DROP_NOT_IPV4.get()),
            ("reason=\"tun_write\"", TUN_WRITE_ERRORS.get()),
        ],
    );
    out.counter(
        "magictunnel_icmp_frag_needed_sent_total",
        "ICMP fragmentation-needed errors returned to local senders",
        FRAG_NEEDED_SENT.get(),
    );
    out.counter(
        "magictunnel_reconnects_total",
        "Tunnels re-established after a failure",
        RECONNECTS.get(),
    );
    out.gauge(
        "magictunnel_connected",
        "1 while the tunnel is up",
        CONNECTED.get(),
    );
    if let Some(conn) = current() {
        let path = conn.stats().path;
        out.gauge(
            "magictunnel_quic_rtt_seconds",
            "Smoothed RTT to the first hop",
            path.rtt.as_secs_f64(),
        );
        out.gauge(
            "magictunnel_quic_cwnd_bytes",
            "Congestion window towards the first hop",
            path.cwnd,
        );
        out.gauge(
            "magictunnel_quic_mtu_bytes",
            "Current UDP payload size towards the first hop",
            path.current_mtu,
        );
        out.gauge(
            "magictunnel_quic_sent_packets",
            "QUIC packets sent on the current connection",
            path.sent_packets,
        );
        out.gauge(
            "magictunnel_quic_lost_packets",
            "QUIC packets lost on the current connection",
            path.lost_packets,
        );
        out.gauge(
            "magictunnel_quic_congestion_events",
            "Congestion events on the current connection",
            path.congestion_events,
        );
    }
    out.finish()
}

/// Logs a traffic summary every `interval` until cancelled.
pub async fn log_periodically(interval: Duration) {
    let mut last = (Instant::now(), UP.bytes(), DOWN.bytes());
    let mut ticker = tokio::time::interval_at(tokio::time::Instant::now() + interval, interval);
    loop {
        ticker.tick().await;
        let now = (Instant::now(), UP.bytes(), DOWN.bytes());
        let secs = now.0.duration_since(last.0).as_secs_f64().max(1e-3);
        let mbps = |now: u64, before: u64| (now - before) as f64 * 8.0 / secs / 1e6;
        let path = current().map(|c| c.stats().path);
        tracing::info!(
            connected = CONNECTED.get() == 1,
            up_mbps = format_args!("{:.2}", mbps(now.1, last.1)),
            down_mbps = format_args!("{:.2}", mbps(now.2, last.2)),
            rtt_ms = path.map(|p| p.rtt.as_millis() as u64),
            lost_packets = path.map(|p| p.lost_packets),
            reconnects = RECONNECTS.get(),
            "stats"
        );
        last = now;
    }
}
