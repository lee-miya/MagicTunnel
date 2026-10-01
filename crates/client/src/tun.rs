//! Client TUN device: `/dev/net/tun` on Linux, utun on macOS, Wintun on Windows.

use std::net::Ipv4Addr;
use std::sync::Arc;

use anyhow::{Context, bail};
use tun_rs::{AsyncDevice, DeviceBuilder};

/// Every IPv4 host must accept datagrams of this size (RFC 791).
const MIN_MTU: u16 = 576;

#[cfg(target_os = "linux")]
const PRIVILEGE_HINT: &str = "needs root or CAP_NET_ADMIN";
#[cfg(target_os = "macos")]
const PRIVILEGE_HINT: &str = "needs root";
#[cfg(windows)]
const PRIVILEGE_HINT: &str =
    "needs Administrator and wintun.dll (https://www.wintun.net) next to mt-client.exe";

/// The TUN device plus what the OS actually assigned to it.
pub struct Tun {
    pub dev: Arc<AsyncDevice>,
    /// May differ from the configured name on macOS, where the kernel picks the utun unit.
    pub name: String,
    pub index: u32,
}

impl Tun {
    /// IPv4 MTU only on Windows, matching [`create`].
    pub fn set_mtu(&self, mtu: u16) -> anyhow::Result<()> {
        self.dev.set_mtu(mtu).context("changing TUN MTU")
    }

    /// Moves the device to a new address. The new one is added before the old one goes, so
    /// the device never has no address: Linux would drop the routes through it.
    pub fn readdress(&self, old: Ipv4Addr, new: Ipv4Addr, prefix_len: u8) -> anyhow::Result<()> {
        self.dev
            .add_address_v4(new, prefix_len)
            .with_context(|| format!("adding {new}/{prefix_len} to {}", self.name))?;
        self.dev
            .remove_address(old.into())
            .with_context(|| format!("removing {old} from {}", self.name))
    }
}

/// Largest TUN MTU whose packets fit the whole path: the configured value, the exit's limit,
/// and what one QUIC datagram on the first hop can carry right after the handshake.
pub fn clamp_mtu(configured: u16, exit_mtu: u16, max_datagram: usize) -> anyhow::Result<u16> {
    let datagram = u16::try_from(max_datagram).unwrap_or(u16::MAX);
    let mtu = configured.min(exit_mtu).min(datagram);
    if mtu < MIN_MTU {
        bail!(
            "usable MTU {mtu} is below {MIN_MTU} \
             (tun.mtu {configured}, exit {exit_mtu}, first-hop datagram {max_datagram})"
        );
    }
    Ok(mtu)
}

pub fn create(
    name: &str,
    addr: Ipv4Addr,
    prefix_len: u8,
    mtu: u16,
    offload: bool,
) -> anyhow::Result<Tun> {
    let builder = DeviceBuilder::new().ipv4(addr, prefix_len, None);
    #[cfg(target_os = "linux")]
    let builder = builder.offload(offload);
    #[cfg(not(target_os = "linux"))]
    let _ = offload;

    #[cfg(target_os = "macos")]
    let builder = match utun_name(name)? {
        Some(name) => builder.name(name),
        None => builder,
    };
    #[cfg(not(target_os = "macos"))]
    let builder = builder.name(name);

    // Windows rejects IPv6 MTUs below 1280, which `mtu()` would also set.
    #[cfg(windows)]
    let builder = builder.mtu_v4(mtu).with(|b| {
        b.description("magicTunnel");
        if let Some(dll) = bundled_wintun() {
            b.wintun_file(dll);
        }
    });
    #[cfg(not(windows))]
    let builder = builder.mtu(mtu);

    let dev = builder
        .build_async()
        .with_context(|| format!("creating TUN device {name} ({PRIVILEGE_HINT})"))?;
    let name = dev.name().context("reading TUN device name")?;
    let index = dev.if_index().context("reading TUN interface index")?;
    Ok(Tun {
        dev: Arc::new(dev),
        name,
        index,
    })
}

/// Maps `tun.name` to the utun unit to request: `utun` lets the kernel choose.
#[cfg(any(target_os = "macos", test))]
fn utun_name(name: &str) -> anyhow::Result<Option<&str>> {
    match name.strip_prefix("utun") {
        Some("") => Ok(None),
        Some(unit) if unit.bytes().all(|b| b.is_ascii_digit()) && unit.len() <= 6 => Ok(Some(name)),
        _ => bail!("on macOS tun.name must be \"utun\" or \"utunN\", got {name:?}"),
    }
}

/// Prefers the `wintun.dll` shipped next to the executable over the DLL search path.
#[cfg(windows)]
fn bundled_wintun() -> Option<String> {
    let dll = std::env::current_exe().ok()?.with_file_name("wintun.dll");
    dll.is_file().then(|| dll.to_string_lossy().into_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn clamps_to_the_smallest_limit() {
        assert_eq!(clamp_mtu(1200, 1400, 1250).unwrap(), 1200);
        assert_eq!(clamp_mtu(1400, 1300, 1350).unwrap(), 1300);
        assert_eq!(clamp_mtu(1400, 1400, 1240).unwrap(), 1240);
        assert_eq!(clamp_mtu(1200, 1200, 1 << 20).unwrap(), 1200);
    }

    #[test]
    fn rejects_unusably_small_mtu() {
        assert!(clamp_mtu(1200, 500, 1250).is_err());
        assert!(clamp_mtu(1200, 1200, 100).is_err());
    }

    #[test]
    fn maps_utun_names() {
        assert_eq!(utun_name("utun").unwrap(), None);
        assert_eq!(utun_name("utun7").unwrap(), Some("utun7"));
        assert!(utun_name("mt0").is_err());
        assert!(utun_name("utunx").is_err());
        assert!(utun_name("utun-1").is_err());
    }
}
