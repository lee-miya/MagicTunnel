//! Windows backend. The servers go on the Wintun adapter with `netsh` (addressed by interface
//! index), and the adapter's interface metric drops to 0 so the DNS client asks it before any
//! other adapter. Both settings belong to the adapter and vanish with it, so there is nothing
//! to restore.

use std::io;
use std::net::Ipv4Addr;
use std::process::Command;

use anyhow::{Context, bail};
use windows_sys::Win32::Foundation::NO_ERROR;
use windows_sys::Win32::NetworkManagement::IpHelper::{
    GetIpInterfaceEntry, InitializeIpInterfaceEntry, MIB_IPINTERFACE_ROW, SetIpInterfaceEntry,
};
use windows_sys::Win32::Networking::WinSock::AF_INET;

use crate::tun::Tun;

pub struct Dns;

pub fn restore_stale() {}

impl Dns {
    pub fn apply(tun: &Tun, servers: &[Ipv4Addr]) -> anyhow::Result<Self> {
        let name = format!("name={}", tun.index);
        for (i, server) in servers.iter().enumerate() {
            let address = format!("address={server}");
            if i == 0 {
                netsh(&[
                    "interface",
                    "ipv4",
                    "set",
                    "dnsservers",
                    &name,
                    "source=static",
                    &address,
                    "register=none",
                    "validate=no",
                ])?;
            } else {
                let index = format!("index={}", i + 1);
                netsh(&[
                    "interface",
                    "ipv4",
                    "add",
                    "dnsservers",
                    &name,
                    &address,
                    &index,
                    "validate=no",
                ])?;
            }
        }
        prefer_interface(tun.index).context("lowering the TUN's interface metric")?;
        if let Err(e) = Command::new("ipconfig").arg("/flushdns").output() {
            tracing::debug!("running ipconfig /flushdns: {e}");
        }
        tracing::info!(tun = %tun.name, ?servers, "DNS servers set on the TUN");
        Ok(Self)
    }
}

/// Interface metric 0, which also puts the adapter first in the DNS client's order.
fn prefer_interface(index: u32) -> io::Result<()> {
    let mut row = MIB_IPINTERFACE_ROW::default();
    unsafe { InitializeIpInterfaceEntry(&mut row) };
    row.Family = AF_INET;
    row.InterfaceIndex = index;
    win(unsafe { GetIpInterfaceEntry(&mut row) })?;
    row.UseAutomaticMetric = false;
    row.Metric = 0;
    // SetIpInterfaceEntry rejects IPv4 rows that carry a site prefix length.
    row.SitePrefixLength = 0;
    win(unsafe { SetIpInterfaceEntry(&mut row) })
}

fn netsh(args: &[&str]) -> anyhow::Result<()> {
    tracing::debug!(?args, "netsh");
    let output = Command::new("netsh")
        .args(args)
        .output()
        .context("failed to run `netsh`")?;
    if output.status.success() {
        return Ok(());
    }
    // netsh reports errors on stdout.
    let stdout = String::from_utf8_lossy(&output.stdout);
    bail!("`netsh {}` failed: {}", args.join(" "), stdout.trim())
}

fn win(code: u32) -> io::Result<()> {
    if code == NO_ERROR {
        Ok(())
    } else {
        Err(io::Error::from_raw_os_error(code as i32))
    }
}
