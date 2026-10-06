//! Per-link heartbeat. QUIC's idle timeout only notices a link that has gone silent. When the
//! dialer's packets stop reaching the peer while the peer's still arrive, the peer's
//! retransmissions keep the dialer's idle timer fresh, and the link looks alive for about
//! twice the timeout. So the side that dialed a link pings it, the other side answers, and the
//! dialer gives the link up once [`timeout`] passes without an answer.
//!
//! Heartbeats are one-byte datagrams, which no IP packet (20 bytes at least) is mistaken for.
//! They queue with the IP packets: quinn only fills the room datagrams leave with stream
//! frames, so on a saturated link anything sent on the control stream would starve. One
//! dropped from a full queue is covered by sending several per timeout.

use std::sync::atomic::{AtomicU64, Ordering::Relaxed};
use std::time::Duration;

use bytes::Bytes;
use magictunnel_common::config::QuicConfig;
use quinn::Connection;
use tokio::time::Instant;

use crate::datagram::send_packet;
use crate::{Error, Result};

const PING: u8 = 0x01;
const PONG: u8 = 0x02;
const PINGS_PER_TIMEOUT: u32 = 6;
const MIN_INTERVAL: Duration = Duration::from_secs(1);

/// How long a link may go without answering heartbeats: the configured idle timeout, so a
/// link that only works one way is given up as soon as a silent one would be.
pub fn timeout(quic: &QuicConfig) -> Duration {
    Duration::from_secs(quic.idle_timeout_secs)
}

fn kind(packet: &[u8]) -> Option<u8> {
    match packet {
        [b @ (PING | PONG)] => Some(*b),
        _ => None,
    }
}

/// Whether `packet` is a heartbeat rather than an IP packet.
pub fn is_heartbeat(packet: &[u8]) -> bool {
    kind(packet).is_some()
}

/// For the accepting side of a link: answers `packet` if it is a ping. Returns whether it was
/// a heartbeat, which is consumed here and not to be passed on.
pub fn answer(conn: &Connection, packet: &[u8]) -> bool {
    match kind(packet) {
        Some(PING) => {
            let _ = send_packet(conn, Bytes::from_static(&[PONG]));
            true
        }
        Some(_) => true,
        None => false,
    }
}

/// The dialing side's view of whether its peer still answers.
#[derive(Debug)]
pub struct Liveness {
    started: Instant,
    /// Milliseconds after `started` at which the last pong arrived.
    last_pong: AtomicU64,
}

impl Default for Liveness {
    fn default() -> Self {
        Self {
            started: Instant::now(),
            last_pong: AtomicU64::new(0),
        }
    }
}

impl Liveness {
    /// For the dialing side of a link: records `packet` if it is a pong. Returns whether it was
    /// a heartbeat, which is consumed here and not to be passed on.
    pub fn observe(&self, packet: &[u8]) -> bool {
        match kind(packet) {
            Some(PONG) => {
                let ms = self.started.elapsed().as_millis();
                self.last_pong
                    .fetch_max(u64::try_from(ms).unwrap_or(u64::MAX), Relaxed);
                true
            }
            Some(_) => true,
            None => false,
        }
    }

    fn last_pong(&self) -> Instant {
        self.started + Duration::from_millis(self.last_pong.load(Relaxed))
    }

    /// Pings `conn` until `timeout` passes without a pong (counting from when this was
    /// created), then returns [`Error::Unresponsive`]; or returns the error that ended the
    /// connection first. Pongs must be fed to [`Liveness::observe`] by the receive loop.
    pub async fn watch(&self, conn: &Connection, timeout: Duration) -> Error {
        let interval = (timeout / PINGS_PER_TIMEOUT).max(MIN_INTERVAL);
        let mut next_ping = Instant::now();
        loop {
            let deadline = self.last_pong() + timeout;
            let now = Instant::now();
            if now >= deadline {
                return Error::Unresponsive(timeout);
            }
            if now >= next_ping {
                if let Err(e) = ping(conn) {
                    return e;
                }
                next_ping = now + interval;
            }
            tokio::time::sleep_until(next_ping.min(deadline)).await;
        }
    }
}

/// Sends one ping; [`Liveness::watch`] does so periodically.
pub fn ping(conn: &Connection) -> Result<()> {
    send_packet(conn, Bytes::from_static(&[PING])).map(drop)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tells_heartbeats_from_ip_packets() {
        assert!(is_heartbeat(&[PING]));
        assert!(is_heartbeat(&[PONG]));
        for other in [&[][..], &[0x00], &[0x45], &[PING, PING], &[0x45; 20]] {
            assert!(!is_heartbeat(other), "{other:?}");
        }
    }

    #[tokio::test]
    async fn only_pongs_move_the_deadline() {
        let live = Liveness::default();
        let at_start = live.last_pong();
        tokio::time::sleep(Duration::from_millis(20)).await;
        assert!(!live.observe(&[0x45; 20]));
        assert!(live.observe(&[PING]), "a stray ping is consumed too");
        assert_eq!(live.last_pong(), at_start);
        assert!(live.observe(&[PONG]));
        assert!(live.last_pong() >= at_start + Duration::from_millis(20));
    }
}
