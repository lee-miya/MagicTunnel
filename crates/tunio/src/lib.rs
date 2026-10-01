//! TUN side of the magicTunnel data plane: batched reads and writes; with Linux offload, one
//! syscall moves a whole TSO/GRO super-packet.

mod batch;

pub use batch::{Arena, BATCH, TunReader, TunWriter, offload_enabled};
