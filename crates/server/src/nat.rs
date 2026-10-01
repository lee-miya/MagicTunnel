//! Exit NAT: IPv4 forwarding plus iptables rules that masquerade tunnel traffic leaving the
//! host and let it through a restrictive `FORWARD` policy (e.g. Docker's).
//!
//! Every rule carries a `magictunnel:<tun>` comment. Installing first deletes identical rules
//! left behind by a run that did not exit cleanly, so rules never pile up.

use std::process::Command;

use anyhow::{Context, bail};
use ipnet::Ipv4Net;

const IP_FORWARD: &str = "/proc/sys/net/ipv4/ip_forward";

#[derive(Debug)]
struct Rule {
    table: &'static str,
    chain: &'static str,
    spec: Vec<String>,
}

impl Rule {
    fn new(table: &'static str, chain: &'static str, comment: &str, spec: &[&str]) -> Self {
        let mut spec: Vec<String> = spec.iter().map(|s| s.to_string()).collect();
        spec.extend(["-m", "comment", "--comment", comment].map(String::from));
        Self { table, chain, spec }
    }

    fn insert(&self) -> anyhow::Result<()> {
        iptables(self.table, "-I", self.chain, &self.spec)?;
        Ok(())
    }

    fn exists(&self) -> anyhow::Result<bool> {
        match iptables(self.table, "-C", self.chain, &self.spec)? {
            Status::Ok => Ok(true),
            Status::Absent => Ok(false),
        }
    }

    fn remove_all(&self) -> anyhow::Result<()> {
        while self.exists()? {
            iptables(self.table, "-D", self.chain, &self.spec)?;
        }
        Ok(())
    }
}

/// Installed NAT state; dropping it removes the rules and restores `ip_forward`.
#[derive(Debug)]
pub struct NatGuard {
    rules: Vec<Rule>,
    restore_ip_forward: bool,
}

impl NatGuard {
    /// Must be called after the TUN `tun` carrying `pool` exists.
    pub fn install(tun: &str, pool: Ipv4Net) -> anyhow::Result<Self> {
        if !cfg!(target_os = "linux") {
            bail!("exit NAT is only implemented on Linux");
        }
        let mut guard = Self {
            rules: Vec::new(),
            restore_ip_forward: false,
        };
        guard.restore_ip_forward = enable_ip_forward()?;

        for rule in rules(tun, pool) {
            rule.remove_all()
                .context("removing stale magicTunnel iptables rules")?;
            rule.insert()
                .with_context(|| format!("adding iptables rule {} {:?}", rule.chain, rule.spec))?;
            guard.rules.push(rule);
        }
        tracing::info!(tun, %pool, "NAT enabled: tunnel traffic is masqueraded on egress");
        Ok(guard)
    }
}

impl Drop for NatGuard {
    fn drop(&mut self) {
        for rule in self.rules.iter().rev() {
            if let Err(e) = rule.remove_all() {
                tracing::warn!(
                    "failed to remove iptables rule -t {} {} {:?}: {e:#}",
                    rule.table,
                    rule.chain,
                    rule.spec
                );
            }
        }
        if self.restore_ip_forward
            && let Err(e) = std::fs::write(IP_FORWARD, "0")
        {
            tracing::warn!("failed to restore net.ipv4.ip_forward=0: {e}");
        }
        tracing::info!("NAT rules removed");
    }
}

fn rules(tun: &str, pool: Ipv4Net) -> Vec<Rule> {
    let comment = format!("magictunnel:{tun}");
    let pool = pool.trunc().to_string();
    vec![
        Rule::new(
            "nat",
            "POSTROUTING",
            &comment,
            &["-s", &pool, "!", "-o", tun, "-j", "MASQUERADE"],
        ),
        // Clients may reach the world, but not each other through the exit.
        Rule::new(
            "filter",
            "FORWARD",
            &comment,
            &["-i", tun, "!", "-o", tun, "-j", "ACCEPT"],
        ),
        Rule::new(
            "filter",
            "FORWARD",
            &comment,
            &[
                "-o",
                tun,
                "-m",
                "conntrack",
                "--ctstate",
                "RELATED,ESTABLISHED",
                "-j",
                "ACCEPT",
            ],
        ),
    ]
}

/// Turns on IPv4 forwarding; returns whether it was off before.
fn enable_ip_forward() -> anyhow::Result<bool> {
    let current =
        std::fs::read_to_string(IP_FORWARD).with_context(|| format!("reading {IP_FORWARD}"))?;
    if current.trim() == "1" {
        return Ok(false);
    }
    std::fs::write(IP_FORWARD, "1").context("enabling net.ipv4.ip_forward")?;
    tracing::info!("enabled net.ipv4.ip_forward");
    Ok(true)
}

enum Status {
    Ok,
    Absent,
}

fn iptables(table: &str, action: &str, chain: &str, spec: &[String]) -> anyhow::Result<Status> {
    let mut cmd = Command::new("iptables");
    cmd.args(["-w", "-t", table, action, chain]).args(spec);
    tracing::debug!(?cmd, "iptables");
    let output = cmd
        .output()
        .context("failed to run `iptables` (is it installed and on PATH?)")?;
    match output.status.code() {
        Some(0) => Ok(Status::Ok),
        Some(1) if action == "-C" => Ok(Status::Absent),
        _ => bail!(
            "`iptables -t {table} {action} {chain} {}` failed: {}",
            spec.join(" "),
            String::from_utf8_lossy(&output.stderr).trim()
        ),
    }
}
