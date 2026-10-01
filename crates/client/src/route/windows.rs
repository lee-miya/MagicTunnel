//! Windows backend, using the IP Helper API. Routes go to the active store only, so none
//! survive a reboot; routes on the Wintun adapter vanish with it, and the first-hop bypass is
//! kept in the [`Ledger`] so a crashed run's leftover is deleted at the next start.

use std::net::Ipv4Addr;
use std::{io, ptr};

use anyhow::{Context, bail};
use serde::{Deserialize, Serialize};
use windows_sys::Win32::Foundation::{ERROR_NOT_FOUND, ERROR_OBJECT_ALREADY_EXISTS, NO_ERROR};
use windows_sys::Win32::NetworkManagement::IpHelper::{
    CreateIpForwardEntry2, DeleteIpForwardEntry2, GetBestRoute2, InitializeIpForwardEntry,
    MIB_IPFORWARD_ROW2,
};
use windows_sys::Win32::Networking::WinSock::{
    AF_INET, MIB_IPPROTO_NETMGMT, NlroManual, SOCKADDR_INET,
};

use super::ledger::Ledger;
use crate::tun::Tun;

pub struct Routes {
    tun: String,
    tun_index: u32,
    via_tun: Vec<Route>,
    bypass: Option<Route>,
    ledger: Ledger,
}

/// What identifies a route to `DeleteIpForwardEntry2`.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
struct Route {
    dst: Ipv4Addr,
    prefix_len: u8,
    /// Unspecified for on-link routes.
    next_hop: Ipv4Addr,
    if_index: u32,
}

impl Route {
    fn row(&self) -> MIB_IPFORWARD_ROW2 {
        let mut row = MIB_IPFORWARD_ROW2::default();
        unsafe { InitializeIpForwardEntry(&mut row) };
        row.InterfaceIndex = self.if_index;
        row.DestinationPrefix.Prefix = sockaddr(self.dst);
        row.DestinationPrefix.PrefixLength = self.prefix_len;
        // InitializeIpForwardEntry sets an invalid SitePrefixLength (255).
        row.SitePrefixLength = 0;
        row.NextHop = sockaddr(self.next_hop);
        row.Metric = 0;
        row.Protocol = MIB_IPPROTO_NETMGMT;
        row.Origin = NlroManual;
        row
    }

    fn create(&self) -> io::Result<()> {
        win(unsafe { CreateIpForwardEntry2(&self.row()) })
    }

    /// Succeeds if the route is already gone.
    fn delete(&self) -> io::Result<()> {
        match win(unsafe { DeleteIpForwardEntry2(&self.row()) }) {
            Err(e) if is(&e, ERROR_NOT_FOUND) => Ok(()),
            r => r,
        }
    }
}

impl Routes {
    pub fn new(tun: &Tun) -> anyhow::Result<Self> {
        let ledger = Ledger::system();
        if let Some(stale) = ledger.take::<Route>() {
            match stale.delete() {
                Ok(()) => {
                    tracing::info!(dst = %stale.dst, "removed bypass route left by an earlier run")
                }
                Err(e) => tracing::warn!(
                    dst = %stale.dst,
                    "failed to remove bypass route left by an earlier run: {e}"
                ),
            }
        }
        Ok(Self {
            tun: tun.name.clone(),
            tun_index: tun.index,
            via_tun: Vec::new(),
            bypass: None,
            ledger,
        })
    }

    pub fn add_bypass(&mut self, hop: Ipv4Addr) -> anyhow::Result<()> {
        let (best, source) =
            best_route(hop).with_context(|| format!("looking up the route to {hop}"))?;
        if best.Loopback || source == Some(hop) {
            tracing::debug!(%hop, "first hop is local, no bypass route needed");
            return Ok(());
        }
        if best.InterfaceIndex == self.tun_index {
            bail!(
                "first hop {hop} is itself routed through {}; check the tunnel address pool",
                self.tun
            );
        }

        let route = Route {
            dst: hop,
            prefix_len: 32,
            next_hop: ipv4(&best.NextHop).unwrap_or(Ipv4Addr::UNSPECIFIED),
            if_index: best.InterfaceIndex,
        };
        match route.create() {
            Ok(()) => {
                tracing::info!(
                    %hop,
                    via = %route.next_hop,
                    if_index = route.if_index,
                    "first-hop bypass route added"
                );
                if let Err(e) = self.ledger.record(&route) {
                    tracing::warn!(
                        path = %self.ledger.path().display(),
                        "cannot record the bypass route, it would survive a crash: {e}"
                    );
                }
                self.bypass = Some(route);
                Ok(())
            }
            // A host route to the hop that someone else configured already does the job.
            Err(e) if is(&e, ERROR_OBJECT_ALREADY_EXISTS) => {
                tracing::info!(%hop, "keeping existing host route to the first hop");
                Ok(())
            }
            Err(e) => Err(e).with_context(|| format!("adding bypass route to {hop}")),
        }
    }

    pub fn add_via_tun(&mut self, net: Ipv4Addr, prefix_len: u8) -> anyhow::Result<()> {
        let route = Route {
            dst: net,
            prefix_len,
            next_hop: Ipv4Addr::UNSPECIFIED,
            if_index: self.tun_index,
        };
        route
            .create()
            .with_context(|| format!("routing {net}/{prefix_len} through {}", self.tun))?;
        self.via_tun.push(route);
        Ok(())
    }
}

impl Drop for Routes {
    fn drop(&mut self) {
        // These also disappear with the adapter; deleting them first just avoids a window
        // where traffic is routed to a device that is going away.
        for route in self.via_tun.drain(..) {
            if let Err(e) = route.delete() {
                tracing::debug!(dst = %route.dst, "removing tunnel route: {e}");
            }
        }
        if let Some(bypass) = self.bypass.take() {
            if let Err(e) = bypass.delete() {
                // The record stays, so the next start retries.
                tracing::warn!(
                    "failed to remove bypass route, run `route delete {}`: {e}",
                    bypass.dst
                );
                return;
            }
            self.ledger.clear();
        }
        tracing::info!("tunnel routes removed");
    }
}

/// The route the system would use for `dst` right now, and the source address it would pick.
fn best_route(dst: Ipv4Addr) -> io::Result<(MIB_IPFORWARD_ROW2, Option<Ipv4Addr>)> {
    let dst = sockaddr(dst);
    let mut best = MIB_IPFORWARD_ROW2::default();
    let mut source = SOCKADDR_INET::default();
    win(unsafe { GetBestRoute2(ptr::null(), 0, ptr::null(), &dst, 0, &mut best, &mut source) })?;
    Ok((best, ipv4(&source)))
}

fn sockaddr(addr: Ipv4Addr) -> SOCKADDR_INET {
    let mut sa = SOCKADDR_INET::default();
    sa.Ipv4.sin_family = AF_INET;
    sa.Ipv4.sin_addr.S_un.S_addr = u32::from_ne_bytes(addr.octets());
    sa
}

fn ipv4(sa: &SOCKADDR_INET) -> Option<Ipv4Addr> {
    // SAFETY: every variant starts with the address family, which selects the valid one.
    unsafe {
        (sa.si_family == AF_INET)
            .then(|| Ipv4Addr::from(sa.Ipv4.sin_addr.S_un.S_addr.to_ne_bytes()))
    }
}

fn win(code: u32) -> io::Result<()> {
    if code == NO_ERROR {
        Ok(())
    } else {
        Err(io::Error::from_raw_os_error(code as i32))
    }
}

fn is(e: &io::Error, code: u32) -> bool {
    e.raw_os_error() == Some(code as i32)
}
