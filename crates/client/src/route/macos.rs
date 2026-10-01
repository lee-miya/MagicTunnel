//! macOS backend, driving the BSD `route` command. Routes through the utun vanish with the
//! device; the first-hop bypass is kept in the [`Ledger`] so a crashed run's leftover is
//! deleted at the next start.

use std::net::Ipv4Addr;
use std::process::Command;

use anyhow::{Context, bail};
use serde::{Deserialize, Serialize};

use super::ledger::Ledger;
use crate::tun::Tun;

pub struct Routes {
    tun: String,
    via_tun: Vec<String>,
    bypass: Option<Bypass>,
    ledger: Ledger,
}

#[derive(Debug, PartialEq, Serialize, Deserialize)]
struct Bypass {
    dst: Ipv4Addr,
    via: Via,
}

#[derive(Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum Via {
    Gateway(Ipv4Addr),
    /// On-link destination.
    Interface(String),
}

impl Bypass {
    fn args(&self) -> Vec<String> {
        let mut args = vec!["-host".to_owned(), self.dst.to_string()];
        match &self.via {
            Via::Gateway(gateway) => args.push(gateway.to_string()),
            Via::Interface(iface) => args.extend(["-interface".to_owned(), iface.clone()]),
        }
        args
    }
}

impl Routes {
    pub fn new(tun: &Tun) -> anyhow::Result<Self> {
        let ledger = Ledger::system();
        if let Some(stale) = ledger.take::<Bypass>() {
            match route("delete", &stale.args()) {
                Ok(_) => {
                    tracing::info!(dst = %stale.dst, "removed bypass route left by an earlier run")
                }
                Err(RouteError::Missing) => {}
                Err(e) => tracing::warn!(
                    dst = %stale.dst,
                    "failed to remove bypass route left by an earlier run: {e}"
                ),
            }
        }
        Ok(Self {
            tun: tun.name.clone(),
            via_tun: Vec::new(),
            bypass: None,
            ledger,
        })
    }

    pub fn add_bypass(&mut self, hop: Ipv4Addr) -> anyhow::Result<()> {
        let current = route_get(hop).with_context(|| format!("looking up the route to {hop}"))?;
        if current.is_local() {
            tracing::debug!(%hop, "first hop is local, no bypass route needed");
            return Ok(());
        }
        if current.interface == self.tun {
            bail!(
                "first hop {hop} is itself routed through {}; check the tunnel address pool",
                self.tun
            );
        }

        let via = match current.gateway {
            Some(gateway) => Via::Gateway(gateway),
            None => Via::Interface(current.interface.clone()),
        };
        let bypass = Bypass { dst: hop, via };
        // Talking to the hop has usually cloned a host route already. Clones are dynamic and
        // can expire, which would send hop traffic into the tunnel, so it becomes static.
        if current.is_clone()
            && let Err(e) = route("delete", &["-host".to_owned(), hop.to_string()])
        {
            tracing::debug!(%hop, "removing cloned host route: {e}");
        }
        match route("add", &bypass.args()) {
            Ok(_) => {
                tracing::info!(%hop, via = ?bypass.via, "first-hop bypass route added");
                if let Err(e) = self.ledger.record(&bypass) {
                    tracing::warn!(
                        path = %self.ledger.path().display(),
                        "cannot record the bypass route, it would survive a crash: {e}"
                    );
                }
                self.bypass = Some(bypass);
                Ok(())
            }
            // A host route to the hop that someone else configured already does the job.
            Err(RouteError::Exists) => {
                tracing::info!(%hop, "keeping existing host route to the first hop");
                Ok(())
            }
            Err(e) => Err(e).with_context(|| format!("adding bypass route to {hop}")),
        }
    }

    pub fn add_via_tun(&mut self, net: Ipv4Addr, prefix_len: u8) -> anyhow::Result<()> {
        let dst = format!("{net}/{prefix_len}");
        route("add", &self.via_tun_args(&dst))
            .with_context(|| format!("routing {dst} through {}", self.tun))?;
        self.via_tun.push(dst);
        Ok(())
    }

    fn via_tun_args(&self, dst: &str) -> Vec<String> {
        ["-net", dst, "-interface", &self.tun]
            .map(str::to_owned)
            .to_vec()
    }
}

impl Drop for Routes {
    fn drop(&mut self) {
        // These also disappear with the utun; deleting them first just avoids a window where
        // traffic is routed to a device that is going away.
        for dst in std::mem::take(&mut self.via_tun) {
            if let Err(e) = route("delete", &self.via_tun_args(&dst)) {
                tracing::debug!(%dst, "removing tunnel route: {e}");
            }
        }
        if let Some(bypass) = self.bypass.take() {
            match route("delete", &bypass.args()) {
                Ok(_) | Err(RouteError::Missing) => self.ledger.clear(),
                // The record stays, so the next start retries.
                Err(e) => {
                    tracing::warn!(
                        "failed to remove bypass route, run `sudo route -n delete -host {}`: {e}",
                        bypass.dst
                    );
                    return;
                }
            }
        }
        tracing::info!("tunnel routes removed");
    }
}

/// The relevant fields of `route -n get` output.
#[derive(Debug)]
struct RouteGet {
    /// Only set for routes through a gateway; on-link routes may show a link-layer address.
    gateway: Option<Ipv4Addr>,
    interface: String,
    flags: Vec<String>,
}

impl RouteGet {
    fn is_local(&self) -> bool {
        self.has_flag("LOCAL") || self.interface.starts_with("lo")
    }

    fn is_clone(&self) -> bool {
        self.has_flag("WASCLONED")
    }

    fn has_flag(&self, flag: &str) -> bool {
        self.flags.iter().any(|f| f == flag)
    }
}

fn route_get(dst: Ipv4Addr) -> anyhow::Result<RouteGet> {
    let output = route("get", &[dst.to_string()])?;
    parse_route_get(&output)
}

fn parse_route_get(text: &str) -> anyhow::Result<RouteGet> {
    let (mut gateway, mut interface, mut flags) = (None, None, Vec::new());
    for line in text.lines() {
        let Some((key, value)) = line.split_once(':') else {
            continue;
        };
        let value = value.trim();
        match key.trim() {
            "gateway" => gateway = Some(value),
            "interface" => interface = Some(value.to_owned()),
            "flags" => {
                flags = value
                    .trim_start_matches('<')
                    .trim_end_matches('>')
                    .split(',')
                    .map(str::to_owned)
                    .collect();
            }
            _ => {}
        }
    }
    let interface = interface.context("unexpected `route get` output: no interface")?;
    let gateway = match gateway {
        Some(gateway) if flags.iter().any(|f| f == "GATEWAY") => Some(
            gateway
                .parse()
                .with_context(|| format!("unexpected `route get` gateway {gateway:?}"))?,
        ),
        _ => None,
    };
    Ok(RouteGet {
        gateway,
        interface,
        flags,
    })
}

#[derive(Debug, thiserror::Error)]
enum RouteError {
    #[error("route already exists")]
    Exists,
    #[error("route not in table")]
    Missing,
    #[error("failed to run `route`")]
    Spawn(#[from] std::io::Error),
    #[error("`route {args}` failed: {output}")]
    Failed { args: String, output: String },
}

fn route(action: &str, args: &[String]) -> Result<String, RouteError> {
    tracing::debug!(action, ?args, "route");
    let output = Command::new("route")
        .args(["-n", action, "-inet"])
        .args(args)
        .output()?;
    let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
    let stderr = String::from_utf8_lossy(&output.stderr).trim().to_owned();
    // `route` reports some failures with exit status 0, so stderr counts as failure too.
    if output.status.success() && stderr.is_empty() {
        return Ok(stdout);
    }
    let message = if stderr.is_empty() {
        stdout.trim().to_owned()
    } else {
        stderr
    };
    if message.contains("File exists") {
        return Err(RouteError::Exists);
    }
    if message.contains("not in table") {
        return Err(RouteError::Missing);
    }
    Err(RouteError::Failed {
        args: format!("-n {action} -inet {}", args.join(" ")),
        output: message,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_gateway_route() {
        let route = parse_route_get(
            "   route to: 203.0.113.7
destination: default
       mask: default
    gateway: 192.168.1.1
  interface: en0
      flags: <UP,GATEWAY,DONE,STATIC,PRCLONING,GLOBAL>
 recvpipe  sendpipe  ssthresh  rtt,msec    rttvar  hopcount      mtu     expire
       0         0         0         0         0         0      1500         0
",
        )
        .unwrap();
        assert_eq!(route.gateway, Some(Ipv4Addr::new(192, 168, 1, 1)));
        assert_eq!(route.interface, "en0");
        assert!(!route.is_local());
        assert!(!route.is_clone());
    }

    #[test]
    fn detects_cloned_host_route() {
        let route = parse_route_get(
            "   route to: 203.0.113.7
destination: 203.0.113.7
    gateway: 192.168.1.1
  interface: en0
      flags: <UP,GATEWAY,HOST,DONE,WASCLONED,IFSCOPE,IFREF,GLOBAL>
",
        )
        .unwrap();
        assert_eq!(route.gateway, Some(Ipv4Addr::new(192, 168, 1, 1)));
        assert!(route.is_clone());
    }

    #[test]
    fn parses_on_link_and_local_routes() {
        let on_link = parse_route_get(
            "   route to: 192.168.1.9
destination: 192.168.1.9
    gateway: a4:83:e7:1:2:3
  interface: en0
      flags: <UP,HOST,DONE,LLINFO,WASCLONED,IFSCOPE,IFREF>
",
        )
        .unwrap();
        assert_eq!(on_link.gateway, None);
        assert!(!on_link.is_local());

        let local = parse_route_get(
            "   route to: 192.168.1.20
destination: 192.168.1.20
  interface: lo0
      flags: <UP,HOST,DONE,LOCAL>
",
        )
        .unwrap();
        assert!(local.is_local());
    }

    #[test]
    fn rejects_output_without_interface() {
        assert!(parse_route_get("route: writing to routing socket: not in table").is_err());
    }

    #[test]
    fn builds_bypass_arguments() {
        let hop = Ipv4Addr::new(203, 0, 113, 7);
        let via_gateway = Bypass {
            dst: hop,
            via: Via::Gateway(Ipv4Addr::new(192, 168, 1, 1)),
        };
        assert_eq!(via_gateway.args(), ["-host", "203.0.113.7", "192.168.1.1"]);
        let on_link = Bypass {
            dst: hop,
            via: Via::Interface("en0".into()),
        };
        assert_eq!(
            on_link.args(),
            ["-host", "203.0.113.7", "-interface", "en0"]
        );
    }

    #[test]
    fn bypass_record_round_trips() {
        let bypass = Bypass {
            dst: Ipv4Addr::new(203, 0, 113, 7),
            via: Via::Interface("en0".into()),
        };
        let json = serde_json::to_string(&bypass).unwrap();
        assert_eq!(serde_json::from_str::<Bypass>(&json).unwrap(), bypass);
    }
}
