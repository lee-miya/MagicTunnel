//! Process-wide counters and a minimal Prometheus text endpoint (`GET /metrics`).
//!
//! Counters are plain relaxed atomics, cheap enough to bump per packet. Binaries keep them in
//! `static`s and render them on demand; nothing here allocates on the data path.

use std::fmt::{Display, Write as _};
use std::io;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicI64, AtomicU64, Ordering::Relaxed};
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

#[derive(Debug, Default)]
pub struct Counter(AtomicU64);

impl Counter {
    pub const fn new() -> Self {
        Self(AtomicU64::new(0))
    }

    pub fn inc(&self) {
        self.add(1);
    }

    pub fn add(&self, n: u64) {
        self.0.fetch_add(n, Relaxed);
    }

    pub fn get(&self) -> u64 {
        self.0.load(Relaxed)
    }
}

#[derive(Debug, Default)]
pub struct Gauge(AtomicI64);

impl Gauge {
    pub const fn new() -> Self {
        Self(AtomicI64::new(0))
    }

    pub fn inc(&self) {
        self.0.fetch_add(1, Relaxed);
    }

    pub fn dec(&self) {
        self.0.fetch_sub(1, Relaxed);
    }

    pub fn set(&self, v: i64) {
        self.0.store(v, Relaxed);
    }

    pub fn get(&self) -> i64 {
        self.0.load(Relaxed)
    }
}

/// Packets and bytes in one direction. A per-session meter can roll up into a process-wide
/// one, so each packet is recorded once and shows up in both.
#[derive(Debug, Default)]
pub struct Traffic {
    packets: Counter,
    bytes: Counter,
    parent: Option<&'static Traffic>,
}

impl Traffic {
    pub const fn new() -> Self {
        Self {
            packets: Counter::new(),
            bytes: Counter::new(),
            parent: None,
        }
    }

    pub const fn child_of(parent: &'static Traffic) -> Self {
        Self {
            packets: Counter::new(),
            bytes: Counter::new(),
            parent: Some(parent),
        }
    }

    pub fn record(&self, bytes: usize) {
        self.packets.inc();
        self.bytes.add(bytes as u64);
        if let Some(parent) = self.parent {
            parent.record(bytes);
        }
    }

    pub fn packets(&self) -> u64 {
        self.packets.get()
    }

    pub fn bytes(&self) -> u64 {
        self.bytes.get()
    }
}

/// Builds a Prometheus text-format (0.0.4) document.
#[derive(Debug, Default)]
pub struct Exposition(String);

impl Exposition {
    pub fn counter(&mut self, name: &str, help: &str, value: u64) {
        self.family(name, "counter", help, &[("", value)]);
    }

    pub fn gauge(&mut self, name: &str, help: &str, value: impl Display) {
        self.family(name, "gauge", help, &[("", value)]);
    }

    /// One metric with a sample per label set; labels are pre-formatted, e.g. `dir="up"`.
    pub fn family<V: Display>(
        &mut self,
        name: &str,
        kind: &str,
        help: &str,
        samples: &[(&str, V)],
    ) {
        let out = &mut self.0;
        let _ = writeln!(out, "# HELP {name} {help}");
        let _ = writeln!(out, "# TYPE {name} {kind}");
        for (labels, value) in samples {
            if labels.is_empty() {
                let _ = writeln!(out, "{name} {value}");
            } else {
                let _ = writeln!(out, "{name}{{{labels}}} {value}");
            }
        }
    }

    /// Both directions of a [`Traffic`] pair as `<prefix>_packets_total` and
    /// `<prefix>_bytes_total`, labelled `dir="up"` / `dir="down"`.
    pub fn traffic(&mut self, prefix: &str, what: &str, up: &Traffic, down: &Traffic) {
        self.family(
            &format!("{prefix}_packets_total"),
            "counter",
            &format!("{what} packets; up is towards the exit"),
            &[
                ("dir=\"up\"", up.packets()),
                ("dir=\"down\"", down.packets()),
            ],
        );
        self.family(
            &format!("{prefix}_bytes_total"),
            "counter",
            &format!("{what} bytes (IP packet sizes); up is towards the exit"),
            &[("dir=\"up\"", up.bytes()), ("dir=\"down\"", down.bytes())],
        );
    }

    pub fn finish(self) -> String {
        self.0
    }
}

const REQUEST_TIMEOUT: Duration = Duration::from_secs(5);
const MAX_REQUEST: usize = 8 * 1024;
const ACCEPT_BACKOFF: Duration = Duration::from_millis(100);

/// A bound metrics listener; binding up front makes a taken port a startup error.
pub struct MetricsServer {
    listener: TcpListener,
}

impl MetricsServer {
    pub async fn bind(addr: SocketAddr) -> io::Result<Self> {
        Ok(Self {
            listener: TcpListener::bind(addr).await?,
        })
    }

    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        self.listener.local_addr()
    }

    /// Answers `GET /metrics` with `render()` forever.
    pub async fn run<F>(self, render: F)
    where
        F: Fn() -> String + Clone + Send + 'static,
    {
        loop {
            let stream = match self.listener.accept().await {
                Ok((stream, _)) => stream,
                // Errors here concern one connection or a momentary lack of file descriptors.
                Err(e) => {
                    tracing::debug!("metrics accept failed: {e}");
                    tokio::time::sleep(ACCEPT_BACKOFF).await;
                    continue;
                }
            };
            let render = render.clone();
            tokio::spawn(async move {
                if let Err(e) = tokio::time::timeout(REQUEST_TIMEOUT, respond(stream, render)).await
                {
                    tracing::debug!("metrics request timed out: {e}");
                }
            });
        }
    }
}

async fn respond(mut stream: TcpStream, render: impl Fn() -> String) {
    let mut request = Vec::with_capacity(1024);
    let mut buf = [0u8; 1024];
    while !request.windows(4).any(|w| w == b"\r\n\r\n") {
        match stream.read(&mut buf).await {
            Ok(0) | Err(_) => return,
            Ok(n) => request.extend_from_slice(&buf[..n]),
        }
        if request.len() > MAX_REQUEST {
            return;
        }
    }
    let (status, content_type, body) = match request_target(&request) {
        Some("/metrics") => ("200 OK", "text/plain; version=0.0.4", render()),
        _ => ("404 Not Found", "text/plain", "not found\n".to_owned()),
    };
    let head = format!(
        "HTTP/1.1 {status}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\n\
         Connection: close\r\n\r\n",
        body.len()
    );
    let _ = stream.write_all(head.as_bytes()).await;
    let _ = stream.write_all(body.as_bytes()).await;
    let _ = stream.shutdown().await;
}

/// Path of a `GET` request, without the query string.
fn request_target(request: &[u8]) -> Option<&str> {
    let line = request.split(|&b| b == b'\r').next()?;
    let line = std::str::from_utf8(line).ok()?;
    let mut parts = line.split(' ');
    if parts.next()? != "GET" {
        return None;
    }
    parts.next()?.split('?').next()
}

#[cfg(test)]
mod tests {
    use super::*;

    static TOTAL: Traffic = Traffic::new();

    #[test]
    fn traffic_rolls_up() {
        let session = Traffic::child_of(&TOTAL);
        session.record(100);
        session.record(50);
        assert_eq!((session.packets(), session.bytes()), (2, 150));
        assert_eq!((TOTAL.packets(), TOTAL.bytes()), (2, 150));
    }

    #[test]
    fn renders_text_format() {
        let mut out = Exposition::default();
        out.counter("mt_x_total", "X.", 3);
        out.family(
            "mt_drop_total",
            "counter",
            "Drops.",
            &[("reason=\"a\"", 1), ("reason=\"b\"", 2)],
        );
        out.gauge("mt_rtt_seconds", "RTT.", 0.25);
        assert_eq!(
            out.finish(),
            "# HELP mt_x_total X.\n# TYPE mt_x_total counter\nmt_x_total 3\n\
             # HELP mt_drop_total Drops.\n# TYPE mt_drop_total counter\n\
             mt_drop_total{reason=\"a\"} 1\nmt_drop_total{reason=\"b\"} 2\n\
             # HELP mt_rtt_seconds RTT.\n# TYPE mt_rtt_seconds gauge\nmt_rtt_seconds 0.25\n"
        );
    }

    #[test]
    fn parses_request_target() {
        assert_eq!(
            request_target(b"GET /metrics HTTP/1.1\r\n\r\n"),
            Some("/metrics")
        );
        assert_eq!(
            request_target(b"GET /metrics?x=1 HTTP/1.1\r\n\r\n"),
            Some("/metrics")
        );
        assert_eq!(request_target(b"POST /metrics HTTP/1.1\r\n\r\n"), None);
        assert_eq!(request_target(b"\xff\r\n\r\n"), None);
    }

    #[tokio::test]
    async fn serves_metrics_over_http() {
        let server = MetricsServer::bind("127.0.0.1:0".parse().unwrap())
            .await
            .unwrap();
        let addr = server.local_addr().unwrap();
        tokio::spawn(server.run(|| "mt_up 1\n".to_owned()));

        let get = |path: &'static str| async move {
            let mut s = TcpStream::connect(addr).await.unwrap();
            s.write_all(format!("GET {path} HTTP/1.1\r\nHost: x\r\n\r\n").as_bytes())
                .await
                .unwrap();
            let mut resp = String::new();
            s.read_to_string(&mut resp).await.unwrap();
            resp
        };
        let ok = get("/metrics").await;
        assert!(ok.starts_with("HTTP/1.1 200 OK\r\n"), "{ok}");
        assert!(ok.ends_with("\r\n\r\nmt_up 1\n"), "{ok}");
        assert!(get("/").await.starts_with("HTTP/1.1 404"));
    }
}
