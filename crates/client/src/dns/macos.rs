//! macOS backend, driving `networksetup`: every network service gets the tunnel's servers, so
//! whichever one is primary resolves through them. These settings survive reboots, so each
//! service's previous servers are kept in a persistent [`Ledger`] until they are restored.

use std::net::{IpAddr, Ipv4Addr};
use std::process::Command;

use anyhow::{Context, bail};
use serde::{Deserialize, Serialize};

use crate::ledger::Ledger;
use crate::tun::Tun;

const LEDGER: &str = "client-dns.json";

pub struct Dns {
    saved: Vec<Saved>,
    ledger: Ledger,
}

#[derive(Debug, PartialEq, Serialize, Deserialize)]
struct Saved {
    service: String,
    /// Empty when the service uses the servers DHCP hands out.
    servers: Vec<String>,
}

/// Restores the services a crashed run left pointing at its servers.
pub fn restore_stale() {
    let ledger = Ledger::persistent(LEDGER);
    let Some(saved) = ledger.take::<Vec<Saved>>() else {
        return;
    };
    match restore(&saved) {
        Ok(()) => tracing::info!("restored DNS settings left by an earlier run"),
        Err(e) => {
            tracing::warn!("failed to restore DNS settings left by an earlier run: {e:#}");
            if let Err(e) = ledger.record(&saved) {
                tracing::warn!(path = %ledger.path().display(), "cannot keep the DNS record: {e}");
            }
        }
    }
}

impl Dns {
    pub fn apply(_tun: &Tun, servers: &[Ipv4Addr]) -> anyhow::Result<Self> {
        let services = parse_services(&networksetup(&["-listallnetworkservices"])?);
        if services.is_empty() {
            bail!("`networksetup -listallnetworkservices` lists no network service");
        }
        let saved = services
            .into_iter()
            .map(|service| {
                let servers = parse_servers(&networksetup(&["-getdnsservers", &service])?);
                Ok(Saved { service, servers })
            })
            .collect::<anyhow::Result<Vec<_>>>()?;
        let ledger = Ledger::persistent(LEDGER);
        ledger
            .record(&saved)
            .with_context(|| format!("saving DNS settings to {}", ledger.path().display()))?;

        // From here on, dropping it puts back whatever was changed.
        let dns = Self { saved, ledger };
        let servers: Vec<String> = servers.iter().map(ToString::to_string).collect();
        for saved in &dns.saved {
            set_servers(&saved.service, &servers)?;
        }
        flush_cache();
        tracing::info!(
            ?servers,
            services = dns.saved.len(),
            "DNS servers set on every network service"
        );
        Ok(dns)
    }
}

impl Drop for Dns {
    fn drop(&mut self) {
        match restore(&self.saved) {
            Ok(()) => {
                self.ledger.clear();
                flush_cache();
                tracing::info!("DNS settings restored");
            }
            // The record stays, so the next start retries.
            Err(e) => tracing::warn!("failed to restore DNS settings: {e:#}"),
        }
    }
}

/// Restores every service, reporting the last failure.
fn restore(saved: &[Saved]) -> anyhow::Result<()> {
    let mut result = Ok(());
    for saved in saved {
        if let Err(e) = set_servers(&saved.service, &saved.servers) {
            result = Err(e);
        }
    }
    result
}

fn set_servers(service: &str, servers: &[String]) -> anyhow::Result<()> {
    let mut args = vec!["-setdnsservers", service];
    if servers.is_empty() {
        args.push("Empty");
    } else {
        args.extend(servers.iter().map(String::as_str));
    }
    networksetup(&args).map(drop)
}

/// Lists the services, disabled ones (marked with `*`) included.
fn parse_services(text: &str) -> Vec<String> {
    text.lines()
        .filter(|line| !line.is_empty() && !line.starts_with("An asterisk"))
        .map(|line| line.strip_prefix('*').unwrap_or(line).to_owned())
        .collect()
}

/// Anything but a list of addresses means none are set, as in
/// "There aren't any DNS Servers set on Wi-Fi.".
fn parse_servers(text: &str) -> Vec<String> {
    text.lines()
        .map(str::trim)
        .filter(|line| line.parse::<IpAddr>().is_ok())
        .map(str::to_owned)
        .collect()
}

fn flush_cache() {
    for (cmd, args) in [
        ("dscacheutil", &["-flushcache"][..]),
        ("killall", &["-HUP", "mDNSResponder"]),
    ] {
        if let Err(e) = Command::new(cmd).args(args).output() {
            tracing::debug!("running {cmd}: {e}");
        }
    }
}

fn networksetup(args: &[&str]) -> anyhow::Result<String> {
    tracing::debug!(?args, "networksetup");
    let output = Command::new("networksetup")
        .args(args)
        .output()
        .context("failed to run `networksetup`")?;
    let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
    // Some failures are only reported on stdout, with exit status 0.
    if output.status.success() && !stdout.contains("** Error") {
        return Ok(stdout);
    }
    let stderr = String::from_utf8_lossy(&output.stderr);
    let message = if stderr.trim().is_empty() {
        stdout.trim()
    } else {
        stderr.trim()
    };
    bail!("`networksetup {}` failed: {message}", args.join(" "))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_services() {
        let text = "An asterisk (*) denotes that a network service is disabled.\n\
                    USB 10/100/1000 LAN\nWi-Fi\n*Thunderbolt Bridge\n";
        assert_eq!(
            parse_services(text),
            ["USB 10/100/1000 LAN", "Wi-Fi", "Thunderbolt Bridge"]
        );
    }

    #[test]
    fn parses_dns_servers() {
        assert_eq!(
            parse_servers("192.168.1.1\nfd00::1\n"),
            ["192.168.1.1", "fd00::1"]
        );
        assert!(parse_servers("There aren't any DNS Servers set on Wi-Fi.\n").is_empty());
    }

    #[test]
    fn record_round_trips() {
        let saved = vec![
            Saved {
                service: "Wi-Fi".into(),
                servers: vec![],
            },
            Saved {
                service: "USB LAN".into(),
                servers: vec!["192.168.1.1".into()],
            },
        ];
        let json = serde_json::to_string(&saved).unwrap();
        assert_eq!(serde_json::from_str::<Vec<Saved>>(&json).unwrap(), saved);
    }
}
