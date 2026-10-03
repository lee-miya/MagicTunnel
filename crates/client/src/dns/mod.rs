//! DNS takeover (`[dns] servers`): while the tunnel is up the system resolves through the
//! configured servers, and the route takeover carries those queries through the tunnel. The
//! previous settings come back on exit. Whatever could outlive a crash is recorded in a
//! [`Ledger`](crate::ledger::Ledger) and undone at the next start.

#[cfg(target_os = "linux")]
mod linux;
// The macOS backend is portable, so its tests run on every platform.
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

use std::net::Ipv4Addr;

use anyhow::Context;

use crate::tun::Tun;

/// Applied DNS settings; dropping it restores the previous ones.
pub struct DnsGuard {
    _dns: sys::Dns,
}

impl DnsGuard {
    /// Must be called once the routes send traffic to `servers` through the TUN. Returns
    /// `None` when `servers` is empty, after undoing what a crashed earlier run left behind.
    pub fn install(tun: &Tun, servers: &[Ipv4Addr]) -> anyhow::Result<Option<Self>> {
        sys::restore_stale();
        if servers.is_empty() {
            return Ok(None);
        }
        let dns = sys::Dns::apply(tun, servers).context("taking over system DNS")?;
        Ok(Some(Self { _dns: dns }))
    }
}
