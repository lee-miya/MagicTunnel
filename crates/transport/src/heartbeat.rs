//! Per-link heartbeat. QUIC's idle timeout only fires at an end that hears nothing, and
//! silently. When one end's packets stop reaching the other while the other's still arrive,
//! the deaf end gives up without a word, and the end that still hears retransmissions only
//! notices once they stop, after about twice the timeout. So each end of a link watches what
//! it receives itself and, once [`timeout`] passes without a single packet from the peer,
//! closes the link explicitly: the close travels the direction that still works, so the other
//! end learns at once.
//!
//! Liveness is judged by arrivals of any kind rather than by answers to pings: a full datagram
//! queue drops its oldest entries, which an answer queued behind a flood would be, while a
//! link that is carrying a flood is plainly alive. Both ends ping, so an idle link still
//! carries something both ways. Pings are one-byte datagrams, which no IP packet (20 bytes at
//! least) is mistaken for; the receiver drops them.

use std::time::Duration;

use bytes::Bytes;
use magictunnel_common::config::QuicConfig;
use quinn::{Connection, VarInt};
use tokio::time::{Instant, MissedTickBehavior};

use crate::datagram::send_packet;
use crate::{Error, Result};

const PING: u8 = 0x01;
/// What the peer reads as the close reason when it is the one that went quiet.
pub const SILENT_PEER: &[u8] = b"heard nothing from you";
/// Checks of the receive counter per timeout. A link is given up at most two ticks late,
/// which [`quic_idle_timeout`] leaves room for.
const TICKS_PER_TIMEOUT: u32 = 12;
const TICKS_PER_PING: u32 = 2;

/// How long a link may go without a packet from the peer: the configured idle timeout.
pub fn timeout(quic: &QuicConfig) -> Duration {
    Duration::from_secs(quic.idle_timeout_secs)
}

/// QUIC's own idle timeout: past [`timeout`], so the watch closes a silent link explicitly
/// before QUIC drops it without telling the peer. Still in force before the watch starts.
pub fn quic_idle_timeout(quic: &QuicConfig) -> Duration {
    let timeout = timeout(quic);
    timeout + tick(timeout) * 3
}

fn tick(timeout: Duration) -> Duration {
    (timeout / TICKS_PER_TIMEOUT).max(Duration::from_millis(1))
}

/// Whether `packet` is a heartbeat rather than an IP packet; receivers drop these.
pub fn is_heartbeat(packet: &[u8]) -> bool {
    packet == [PING]
}

/// Sends one ping; [`watch`] does so periodically.
pub fn ping(conn: &Connection) -> Result<()> {
    send_packet(conn, Bytes::from_static(&[PING])).map(drop)
}

/// For either end of a link: pings `conn` every `timeout / 6` until `timeout` passes without
/// any packet arriving from the peer, then closes the connection with [`SILENT_PEER`] and
/// returns [`Error::Unresponsive`]; or returns the error that ended the connection first.
pub async fn watch(conn: &Connection, timeout: Duration) -> Error {
    let mut ticks = tokio::time::interval(tick(timeout));
    ticks.set_missed_tick_behavior(MissedTickBehavior::Delay);
    let mut received = conn.stats().udp_rx.datagrams;
    let mut heard = Instant::now();
    let mut n: u32 = 0;
    loop {
        ticks.tick().await;
        let now = Instant::now();
        let count = conn.stats().udp_rx.datagrams;
        if count != received {
            received = count;
            heard = now;
        } else if now - heard >= timeout {
            conn.close(VarInt::from_u32(0), SILENT_PEER);
            return Error::Unresponsive(timeout);
        }
        if n.is_multiple_of(TICKS_PER_PING)
            && let Err(e) = ping(conn)
        {
            return e;
        }
        n = n.wrapping_add(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tells_heartbeats_from_ip_packets() {
        assert!(is_heartbeat(&[PING]));
        for other in [
            &[][..],
            &[0x00],
            &[0x02],
            &[0x45],
            &[PING, PING],
            &[0x45; 20],
        ] {
            assert!(!is_heartbeat(other), "{other:?}");
        }
    }

    #[test]
    fn quic_gives_up_only_after_the_watch() {
        let quic = QuicConfig {
            idle_timeout_secs: 4,
            ..QuicConfig::default()
        };
        let watch_at_the_latest = timeout(&quic) + tick(timeout(&quic)) * 2;
        assert!(quic_idle_timeout(&quic) > watch_at_the_latest);
    }
}
