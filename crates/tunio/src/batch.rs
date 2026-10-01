//! Batched TUN I/O. With Linux offload (`IFF_VNET_HDR`), the kernel hands over TCP/UDP
//! super-packets of up to 64 KB, which [`TunReader`] splits into MTU-sized packets (one
//! datagram each), and [`TunWriter`] coalesces consecutive segments of a flow back into
//! super-packets (GRO) before writing them. Either way a bulk transfer crosses the kernel's
//! TUN and IP stack once per super-packet instead of once per packet. Without offload, and on
//! other platforms, both move one packet per syscall.

use std::io;
use std::sync::Arc;

use bytes::{Bytes, BytesMut};
use tun_rs::AsyncDevice;
#[cfg(target_os = "linux")]
use tun_rs::{GROTable, IDEAL_BATCH_SIZE, VIRTIO_NET_HDR_LEN};

/// Most packets moved per batch.
#[cfg(target_os = "linux")]
pub const BATCH: usize = IDEAL_BATCH_SIZE;
#[cfg(not(target_os = "linux"))]
pub const BATCH: usize = 128;

/// Largest IP packet, and so the most a single read can return without offload.
const MAX_PACKET: usize = u16::MAX as usize;
/// Writer buffers that grew past this while coalescing are released after the write, so an
/// idle session does not keep a batch of 64 KB buffers.
#[cfg(target_os = "linux")]
const KEEP_BUFFER: usize = 4 * 1024;
const ARENA_CHUNK: usize = 256 * 1024;

/// Copies packets into large shared chunks, so turning a TUN packet into an owned datagram
/// does not cost an allocation per packet.
#[derive(Debug, Default)]
pub struct Arena(BytesMut);

impl Arena {
    pub fn copy(&mut self, packet: &[u8]) -> Bytes {
        if self.0.capacity() < packet.len() {
            self.0.reserve(ARENA_CHUNK.max(packet.len()));
        }
        self.0.extend_from_slice(packet);
        self.0.split().freeze()
    }
}

/// Whether the device really runs with offload: it was requested and the kernel accepted it.
pub fn offload_enabled(dev: &AsyncDevice) -> bool {
    #[cfg(target_os = "linux")]
    return dev.tcp_gso();
    #[cfg(not(target_os = "linux"))]
    {
        let _ = dev;
        false
    }
}

pub struct TunReader {
    dev: Arc<AsyncDevice>,
    /// One raw read: the virtio-net header plus a super-packet. Empty without offload.
    #[cfg(target_os = "linux")]
    raw: Vec<u8>,
    bufs: Vec<Vec<u8>>,
    sizes: Vec<usize>,
}

impl TunReader {
    /// `max_mtu` is the largest MTU the device will have; segments are at most that big.
    pub fn new(dev: Arc<AsyncDevice>, max_mtu: u16) -> Self {
        #[cfg(target_os = "linux")]
        if offload_enabled(&dev) {
            return Self {
                dev,
                raw: vec![0; VIRTIO_NET_HDR_LEN + MAX_PACKET],
                bufs: vec![vec![0; usize::from(max_mtu)]; BATCH],
                sizes: vec![0; BATCH],
            };
        }
        let _ = max_mtu;
        Self {
            dev,
            #[cfg(target_os = "linux")]
            raw: Vec::new(),
            bufs: vec![vec![0; MAX_PACKET]],
            sizes: vec![0],
        }
    }

    /// Waits for the next read: one packet or, with offload, the segments of one
    /// super-packet. A super-packet that cannot be split is dropped; only errors of the
    /// device itself are returned.
    pub async fn recv(&mut self) -> io::Result<impl Iterator<Item = &[u8]>> {
        loop {
            match self.read().await {
                Ok(n) => {
                    let packets = self.bufs[..n].iter().zip(&self.sizes);
                    return Ok(packets.map(|(buf, &len)| &buf[..len]));
                }
                // tun-rs reports malformed offload metadata without an OS error code.
                Err(e) if e.raw_os_error().is_none() => {
                    tracing::debug!(error = %e, "dropping TUN read that could not be split");
                }
                Err(e) => return Err(e),
            }
        }
    }

    async fn read(&mut self) -> io::Result<usize> {
        #[cfg(target_os = "linux")]
        if !self.raw.is_empty() {
            return self
                .dev
                .recv_multiple(&mut self.raw, &mut self.bufs, &mut self.sizes, 0)
                .await;
        }
        self.sizes[0] = self.dev.recv(&mut self.bufs[0]).await?;
        Ok(1)
    }
}

pub struct TunWriter {
    dev: Arc<AsyncDevice>,
    #[cfg(target_os = "linux")]
    offload: Option<Gro>,
}

#[cfg(target_os = "linux")]
struct Gro {
    table: GROTable,
    /// Each packet behind `VIRTIO_NET_HDR_LEN` bytes of headroom for its header.
    bufs: Vec<BytesMut>,
}

impl TunWriter {
    pub fn new(dev: Arc<AsyncDevice>) -> Self {
        Self {
            #[cfg(target_os = "linux")]
            offload: offload_enabled(&dev).then(|| Gro {
                table: GROTable::default(),
                bufs: Vec::new(),
            }),
            dev,
        }
    }

    /// Writes `packets` (at most [`BATCH`]), coalescing them first with offload. Packets the
    /// kernel rejects are dropped and reported as the last error; the rest are still written.
    /// Empty packets are skipped.
    pub async fn send(&mut self, packets: &[Bytes]) -> io::Result<()> {
        #[cfg(target_os = "linux")]
        if let Some(gro) = &mut self.offload {
            return gro.send(&self.dev, packets).await;
        }
        let mut result = Ok(());
        for packet in packets.iter().filter(|p| !p.is_empty()) {
            if let Err(e) = self.dev.send(packet).await {
                result = Err(e);
            }
        }
        result
    }
}

#[cfg(target_os = "linux")]
impl Gro {
    async fn send(&mut self, dev: &AsyncDevice, packets: &[Bytes]) -> io::Result<()> {
        let mut n = 0;
        for packet in packets.iter().filter(|p| !p.is_empty()) {
            if n == self.bufs.len() {
                self.bufs.push(BytesMut::with_capacity(KEEP_BUFFER));
            }
            let buf = &mut self.bufs[n];
            buf.clear();
            buf.resize(VIRTIO_NET_HDR_LEN, 0);
            buf.extend_from_slice(packet);
            n += 1;
        }
        if n == 0 {
            return Ok(());
        }
        let result = dev
            .send_multiple(&mut self.table, &mut self.bufs[..n], VIRTIO_NET_HDR_LEN)
            .await
            .map(drop);
        for buf in &mut self.bufs[..n] {
            if buf.capacity() > KEEP_BUFFER {
                *buf = BytesMut::with_capacity(KEEP_BUFFER);
            }
        }
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn arena_copies_share_chunks() {
        let mut arena = Arena::default();
        let a = arena.copy(&[1; 1200]);
        let b = arena.copy(&[2; 1200]);
        assert_eq!((&a[..], &b[..]), (&[1; 1200][..], &[2; 1200][..]));
        assert_eq!(a.as_ptr().wrapping_add(1200), b.as_ptr());
        let big = arena.copy(&vec![3; ARENA_CHUNK + 1]);
        assert_eq!(big.len(), ARENA_CHUNK + 1);
    }
}
