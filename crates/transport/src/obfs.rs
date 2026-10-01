//! UDP-level XOR obfuscation, applied below QUIC so that no QUIC header byte reaches the wire
//! in the clear. This hides protocol fingerprints from DPI; it is not encryption — QUIC/TLS
//! provides confidentiality and integrity.
//!
//! Wire format of every UDP datagram (each GSO/GRO segment individually):
//!
//! ```text
//! nonce: [u8; NONCE_LEN] (random) || payload XOR keystream(key, nonce)
//! ```
//!
//! The per-datagram random nonce selects where in a key-derived table the keystream starts, so
//! fixed QUIC header fields do not map to fixed wire bytes.

use std::cell::{Cell, RefCell};
use std::fmt;
use std::hash::{BuildHasher, RandomState};
use std::io::{self, IoSliceMut};
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll, ready};

use quinn::udp::{RecvMeta, Transmit};
use quinn::{AsyncUdpSocket, UdpPoller};

use crate::{Error, Result};

/// Bytes prepended to every UDP datagram.
pub const NONCE_LEN: usize = 4;

const OFFSETS: usize = 1 << 16;
/// Upper bound on a single UDP payload (IPv6 jumbograms aside).
const MAX_DATAGRAM: usize = 1 << 16;
const TABLE_LEN: usize = OFFSETS + MAX_DATAGRAM;

/// Keystream table derived from the shared `obfs.xor_key`.
pub struct XorKey {
    table: Box<[u8]>,
}

impl XorKey {
    pub fn new(key: &[u8]) -> Result<Self> {
        if key.is_empty() {
            return Err(Error::EmptyXorKey);
        }
        let mut state = fnv1a(key);
        let mut table = vec![0u8; TABLE_LEN].into_boxed_slice();
        for chunk in table.chunks_mut(8) {
            let word = splitmix64(&mut state).to_le_bytes();
            chunk.copy_from_slice(&word[..chunk.len()]);
        }
        for (byte, k) in table.iter_mut().zip(key.iter().cycle()) {
            *byte ^= k;
        }
        Ok(Self { table })
    }

    fn apply(&self, nonce: [u8; NONCE_LEN], data: &mut [u8]) {
        debug_assert!(data.len() <= MAX_DATAGRAM);
        let n = u32::from_le_bytes(nonce);
        let offset = ((n ^ (n >> 16)) as usize) & (OFFSETS - 1);
        for (byte, k) in data.iter_mut().zip(&self.table[offset..]) {
            *byte ^= k;
        }
    }

    /// Obfuscates `contents`, laid out as datagrams of `segment` bytes (the last may be
    /// shorter), into `out`. Each output datagram is `segment + NONCE_LEN` bytes.
    fn encode(
        &self,
        contents: &[u8],
        segment: usize,
        out: &mut Vec<u8>,
        mut nonce: impl FnMut() -> [u8; NONCE_LEN],
    ) {
        out.clear();
        out.reserve(contents.len() + NONCE_LEN * contents.len().div_ceil(segment));
        for datagram in contents.chunks(segment) {
            let nonce = nonce();
            out.extend_from_slice(&nonce);
            let start = out.len();
            out.extend_from_slice(datagram);
            self.apply(nonce, &mut out[start..]);
        }
    }

    /// De-obfuscates `buf[..len]`, holding datagrams at `stride` boundaries, in place and
    /// compacts the payloads to the front. Returns the new `(len, stride)`. Datagrams too short
    /// to carry a nonce are dropped.
    fn decode_in_place(&self, buf: &mut [u8], len: usize, stride: usize) -> (usize, usize) {
        if stride <= NONCE_LEN {
            // Leave `stride` non-zero: quinn splits the buffer by it.
            return (0, stride.max(1));
        }
        let mut read = 0;
        let mut write = 0;
        while read < len {
            let end = (read + stride).min(len);
            if end - read <= NONCE_LEN {
                break;
            }
            let nonce: [u8; NONCE_LEN] = buf[read..read + NONCE_LEN].try_into().unwrap();
            let payload_len = end - read - NONCE_LEN;
            buf.copy_within(read + NONCE_LEN..end, write);
            self.apply(nonce, &mut buf[write..write + payload_len]);
            write += payload_len;
            read = end;
        }
        (write, stride - NONCE_LEN)
    }
}

impl fmt::Debug for XorKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("XorKey").finish_non_exhaustive()
    }
}

/// [`AsyncUdpSocket`] that XOR-obfuscates everything the wrapped socket sends and receives.
///
/// Wraps quinn's own runtime socket so GSO/GRO and ECN keep working; segment boundaries are
/// preserved by obfuscating each segment separately.
#[derive(Debug)]
pub struct XorSocket {
    inner: Arc<dyn AsyncUdpSocket>,
    key: Arc<XorKey>,
}

impl XorSocket {
    pub fn new(inner: Arc<dyn AsyncUdpSocket>, key: Arc<XorKey>) -> Self {
        Self { inner, key }
    }
}

thread_local! {
    static SEND_BUF: RefCell<Vec<u8>> = const { RefCell::new(Vec::new()) };
    static NONCE_RNG: Cell<u64> = Cell::new(RandomState::new().hash_one(0u8) | 1);
}

fn random_nonce() -> [u8; NONCE_LEN] {
    NONCE_RNG.with(|state| {
        // xorshift64*: cheap and unpredictable enough for a nonce that only needs to vary.
        let mut x = state.get();
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        state.set(x);
        ((x.wrapping_mul(0x2545_f491_4f6c_dd1d) >> 32) as u32).to_le_bytes()
    })
}

impl AsyncUdpSocket for XorSocket {
    fn create_io_poller(self: Arc<Self>) -> Pin<Box<dyn UdpPoller>> {
        self.inner.clone().create_io_poller()
    }

    fn try_send(&self, transmit: &Transmit) -> io::Result<()> {
        let segment = transmit
            .segment_size
            .unwrap_or(transmit.contents.len())
            .max(1);
        SEND_BUF.with_borrow_mut(|buf| {
            self.key
                .encode(transmit.contents, segment, buf, random_nonce);
            self.inner.try_send(&Transmit {
                destination: transmit.destination,
                ecn: transmit.ecn,
                contents: buf,
                segment_size: transmit.segment_size.map(|s| s + NONCE_LEN),
                src_ip: transmit.src_ip,
            })
        })
    }

    fn poll_recv(
        &self,
        cx: &mut Context,
        bufs: &mut [IoSliceMut<'_>],
        meta: &mut [RecvMeta],
    ) -> Poll<io::Result<usize>> {
        let count = ready!(self.inner.poll_recv(cx, bufs, meta))?;
        for (buf, meta) in bufs.iter_mut().zip(meta.iter_mut()).take(count) {
            (meta.len, meta.stride) = self.key.decode_in_place(buf, meta.len, meta.stride);
        }
        Poll::Ready(Ok(count))
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        self.inner.local_addr()
    }

    fn max_transmit_segments(&self) -> usize {
        self.inner.max_transmit_segments()
    }

    fn max_receive_segments(&self) -> usize {
        self.inner.max_receive_segments()
    }

    fn may_fragment(&self) -> bool {
        self.inner.may_fragment()
    }
}

fn fnv1a(data: &[u8]) -> u64 {
    data.iter().fold(0xcbf2_9ce4_8422_2325, |hash, &b| {
        (hash ^ u64::from(b)).wrapping_mul(0x0000_0100_0000_01b3)
    })
}

fn splitmix64(state: &mut u64) -> u64 {
    *state = state.wrapping_add(0x9e37_79b9_7f4a_7c15);
    let mut z = *state;
    z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
    z ^ (z >> 31)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key() -> XorKey {
        XorKey::new(b"test-key").unwrap()
    }

    fn counter_nonces() -> impl FnMut() -> [u8; NONCE_LEN] {
        let mut n = 0u32;
        move || {
            n = n.wrapping_add(0x0101_0101);
            n.to_le_bytes()
        }
    }

    #[test]
    fn rejects_empty_key() {
        assert!(matches!(XorKey::new(b""), Err(Error::EmptyXorKey)));
    }

    #[test]
    fn single_datagram_round_trip() {
        let key = key();
        let plain: Vec<u8> = (0..1200).map(|i| i as u8).collect();
        let mut wire = Vec::new();
        key.encode(&plain, plain.len(), &mut wire, counter_nonces());
        assert_eq!(wire.len(), plain.len() + NONCE_LEN);
        assert_ne!(&wire[NONCE_LEN..], &plain[..]);

        let len = wire.len();
        let (len, _) = key.decode_in_place(&mut wire, len, len);
        assert_eq!(&wire[..len], &plain[..]);
    }

    #[test]
    fn segmented_round_trip_with_short_tail() {
        let key = key();
        let segment = 100;
        let plain: Vec<u8> = (0..350).map(|i| (i * 7) as u8).collect();
        let mut wire = Vec::new();
        key.encode(&plain, segment, &mut wire, counter_nonces());
        assert_eq!(wire.len(), plain.len() + 4 * NONCE_LEN);

        let wire_len = wire.len();
        let (len, stride) = key.decode_in_place(&mut wire, wire_len, segment + NONCE_LEN);
        assert_eq!(stride, segment);
        assert_eq!(&wire[..len], &plain[..]);
    }

    #[test]
    fn nonce_varies_the_keystream() {
        let key = key();
        let plain = [0x40u8; 32];
        let mut a = Vec::new();
        let mut b = Vec::new();
        key.encode(&plain, plain.len(), &mut a, || [1, 0, 0, 0]);
        key.encode(&plain, plain.len(), &mut b, || [2, 0, 0, 0]);
        assert_ne!(a[NONCE_LEN..], b[NONCE_LEN..]);
    }

    #[test]
    fn different_keys_differ() {
        let plain = [0u8; 64];
        let mut a = Vec::new();
        let mut b = Vec::new();
        key().encode(&plain, plain.len(), &mut a, || [9; NONCE_LEN]);
        XorKey::new(b"test-kez")
            .unwrap()
            .encode(&plain, plain.len(), &mut b, || [9; NONCE_LEN]);
        assert_ne!(a, b);
    }

    #[test]
    fn drops_datagrams_without_payload() {
        let key = key();
        let mut buf = [0u8; 16];
        assert_eq!(key.decode_in_place(&mut buf, 3, 3), (0, 3));
        assert_eq!(key.decode_in_place(&mut buf, 4, 4), (0, 4));

        // A short trailing GRO segment that only holds part of a nonce is discarded.
        let mut wire = Vec::new();
        key.encode(&[1, 2, 3, 4, 5, 6], 6, &mut wire, counter_nonces());
        wire.extend_from_slice(&[0xaa, 0xbb]);
        let wire_len = wire.len();
        let (len, stride) = key.decode_in_place(&mut wire, wire_len, 6 + NONCE_LEN);
        assert_eq!((len, stride), (6, 6));
        assert_eq!(&wire[..len], &[1, 2, 3, 4, 5, 6]);
    }

    #[test]
    fn max_size_datagram_is_fully_covered() {
        let key = key();
        let plain = vec![0u8; MAX_DATAGRAM];
        let mut wire = Vec::new();
        key.encode(&plain, plain.len(), &mut wire, || [0xff; NONCE_LEN]);
        let wire_len = wire.len();
        let (len, _) = key.decode_in_place(&mut wire, wire_len, wire_len);
        assert_eq!(&wire[..len], &plain[..]);
    }
}
