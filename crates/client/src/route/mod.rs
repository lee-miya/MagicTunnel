//! Route takeover: all IPv4 traffic goes through the TUN, except traffic to the first hop,
//! which keeps its original path so the tunnel does not route into itself.
//!
//! The default route is never touched: the TUN gets `0.0.0.0/1` and `128.0.0.0/1`, which win
//! by being more specific and vanish with the device even if the process is killed. Only the
//! first-hop bypass route can outlive a crash; every backend removes such leftovers on the
//! next start.

// The ledger and the macOS backend are portable, so their tests run on every platform.
#[cfg(any(target_os = "macos", windows, test))]
#[cfg_attr(target_os = "linux", allow(dead_code))]
mod ledger;
#[cfg(target_os = "linux")]
mod linux;
#[cfg(any(target_os = "macos", test))]
#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
mod macos;
#[cfg(windows)]
mod windows;

#[cfg(target_os = "linux")]
use linux as sys;
#[cfg(target_os = "macos")]
use macos as sys;
#[cfg(windows)]
use windows as sys;

#[cfg(not(any(target_os = "linux", target_os = "macos", windows)))]
compile_error!("mt-client supports Linux, macOS and Windows");

use std::net::{IpAddr, Ipv4Addr, SocketAddr};

use crate::tun::Tun;

const DEFAULT_HALVES: [(Ipv4Addr, u8); 2] = [
    (Ipv4Addr::new(0, 0, 0, 0), 1),
    (Ipv4Addr::new(128, 0, 0, 0), 1),
];

/// Installed routes; dropping it removes them.
pub struct RouteGuard {
    _routes: sys::Routes,
}

impl RouteGuard {
    /// Must be called after the first-hop connection is up and the TUN exists.
    pub fn install(tun: &Tun, first_hop: SocketAddr) -> anyhow::Result<Self> {
        // Removes leftovers of an earlier run; whatever is added below is undone when this
        // value drops, including on the error paths.
        let mut routes = sys::Routes::new(tun)?;
        match first_hop.ip() {
            IpAddr::V4(hop) => routes.add_bypass(hop)?,
            // Only IPv4 is captured, so IPv6 traffic to the hop already bypasses the TUN.
            IpAddr::V6(_) => {}
        }
        for (net, prefix_len) in DEFAULT_HALVES {
            routes.add_via_tun(net, prefix_len)?;
        }
        tracing::info!(tun = %tun.name, "default IPv4 traffic now routed through the tunnel");
        Ok(Self { _routes: routes })
    }
}
