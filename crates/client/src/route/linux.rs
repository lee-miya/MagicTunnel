//! Linux backend, driving iproute2's `ip`. Every route added here carries [`RT_PROTO`], so
//! cleanup removes exactly our routes, including ones left behind by a previous run that did
//! not exit cleanly.

use std::net::Ipv4Addr;
use std::process::Command;

use anyhow::{Context, bail};
use serde::Deserialize;

use crate::tun::Tun;

/// Routing protocol id tagging our routes; unassigned in iproute2's `rt_protos`.
const RT_PROTO: &str = "233";

#[derive(Debug)]
pub struct Routes {
    tun: String,
}

impl Routes {
    pub fn new(tun: &Tun) -> anyhow::Result<Self> {
        flush().context("removing stale magicTunnel routes")?;
        Ok(Self {
            tun: tun.name.clone(),
        })
    }

    pub fn add_bypass(&mut self, hop: Ipv4Addr) -> anyhow::Result<()> {
        let current = route_get(hop).with_context(|| format!("looking up the route to {hop}"))?;
        if current.kind.as_deref() == Some("local") {
            tracing::debug!(%hop, "first hop is local, no bypass route needed");
            return Ok(());
        }
        if current.dev == self.tun {
            bail!(
                "first hop {hop} is itself routed through {}; check the tunnel address pool",
                self.tun
            );
        }

        let dst = format!("{hop}/32");
        let gateway = current.gateway.map(|g| g.to_string());
        let mut args = vec![dst.as_str()];
        if let Some(gateway) = &gateway {
            args.extend(["via", gateway]);
        }
        args.extend(["dev", &current.dev]);
        match ip_route("add", &args) {
            Ok(()) => {
                tracing::info!(%hop, via = ?current.gateway, dev = %current.dev, "first-hop bypass route added");
                Ok(())
            }
            // A host route to the hop that someone else configured already does the job.
            Err(IpError::Exists) => {
                tracing::info!(%hop, "keeping existing host route to the first hop");
                Ok(())
            }
            Err(e) => Err(e).with_context(|| format!("adding bypass route to {hop}")),
        }
    }

    pub fn add_via_tun(&mut self, net: Ipv4Addr, prefix_len: u8) -> anyhow::Result<()> {
        let dst = format!("{net}/{prefix_len}");
        ip_route("add", &[&dst, "dev", &self.tun])
            .with_context(|| format!("routing {dst} through {}", self.tun))
    }
}

impl Drop for Routes {
    fn drop(&mut self) {
        match flush() {
            Ok(()) => tracing::info!("tunnel routes removed"),
            Err(e) => tracing::warn!(
                "failed to remove tunnel routes, run `ip -4 route flush proto {RT_PROTO}`: {e:#}"
            ),
        }
    }
}

/// One entry of `ip -j route get` output.
#[derive(Debug, Deserialize)]
struct RouteGet {
    /// Absent for ordinary unicast routes.
    #[serde(rename = "type")]
    kind: Option<String>,
    gateway: Option<Ipv4Addr>,
    dev: String,
}

fn route_get(dst: Ipv4Addr) -> anyhow::Result<RouteGet> {
    let output = run_ip(&["-j", "-4", "route", "get", &dst.to_string()])?;
    parse_route_get(&output)
}

fn parse_route_get(json: &str) -> anyhow::Result<RouteGet> {
    let routes: Vec<RouteGet> =
        serde_json::from_str(json).context("unexpected `ip -j route get` output")?;
    routes
        .into_iter()
        .next()
        .context("`ip route get` returned no route")
}

fn flush() -> anyhow::Result<()> {
    run_ip(&["-4", "route", "flush", "proto", RT_PROTO])?;
    Ok(())
}

fn ip_route(action: &str, spec: &[&str]) -> Result<(), IpError> {
    let mut args = vec!["-4", "route", action];
    args.extend_from_slice(spec);
    args.extend(["proto", RT_PROTO]);
    run_ip(&args).map(drop)
}

#[derive(Debug, thiserror::Error)]
enum IpError {
    #[error("route already exists")]
    Exists,
    #[error("failed to run `ip` (is iproute2 installed?)")]
    Spawn(#[from] std::io::Error),
    #[error("`ip {args}` failed: {stderr}")]
    Failed { args: String, stderr: String },
}

fn run_ip(args: &[&str]) -> Result<String, IpError> {
    tracing::debug!(?args, "ip");
    let output = Command::new("ip").args(args).output()?;
    if output.status.success() {
        return Ok(String::from_utf8_lossy(&output.stdout).into_owned());
    }
    let stderr = String::from_utf8_lossy(&output.stderr).trim().to_owned();
    if stderr.contains("File exists") {
        return Err(IpError::Exists);
    }
    Err(IpError::Failed {
        args: args.join(" "),
        stderr,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_gateway_route() {
        let route = parse_route_get(
            r#"[{"dst":"203.0.113.7","gateway":"192.168.1.1","dev":"eth0",
                 "prefsrc":"192.168.1.20","flags":[],"uid":0,"cache":[]}]"#,
        )
        .unwrap();
        assert_eq!(route.kind, None);
        assert_eq!(route.gateway, Some(Ipv4Addr::new(192, 168, 1, 1)));
        assert_eq!(route.dev, "eth0");
    }

    #[test]
    fn parses_on_link_and_local_routes() {
        let on_link = parse_route_get(
            r#"[{"dst":"192.168.1.9","dev":"eth0","prefsrc":"192.168.1.20","flags":[],"uid":0,"cache":[]}]"#,
        )
        .unwrap();
        assert_eq!(on_link.gateway, None);

        let local = parse_route_get(
            r#"[{"type":"local","dst":"127.0.0.1","dev":"lo","prefsrc":"127.0.0.1","flags":[],"uid":0,"cache":["local"]}]"#,
        )
        .unwrap();
        assert_eq!(local.kind.as_deref(), Some("local"));
    }

    #[test]
    fn rejects_empty_output() {
        assert!(parse_route_get("[]").is_err());
    }
}
