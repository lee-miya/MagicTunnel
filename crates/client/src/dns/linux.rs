//! Linux backend. When systemd-resolved owns `/etc/resolv.conf` (it names the 127.0.0.53
//! stub), the servers go on the TUN link together with the catch-all routing domain `~.`, so
//! resolved sends every query there; that configuration goes away with the link.
//!
//! Otherwise `/etc/resolv.conf` itself is rewritten and the original kept in a [`Ledger`]
//! until it is put back. A network manager may rewrite the file while the tunnel is up, so a
//! watcher re-applies the tunnel's version, adopting the newcomer as the original to restore.

use std::fmt::Write as _;
use std::net::Ipv4Addr;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;
use std::{fs, io};

use anyhow::{Context, bail};
use serde::{Deserialize, Serialize};
use tokio::task::JoinHandle;

use crate::ledger::Ledger;
use crate::tun::Tun;

const RESOLV_CONF: &str = "/etc/resolv.conf";
const LEDGER: &str = "resolv-conf.json";
/// systemd-resolved's stub listeners.
const STUB_RESOLVERS: [&str; 2] = ["127.0.0.53", "127.0.0.54"];
const WATCH_INTERVAL: Duration = Duration::from_secs(2);
const HEADER: &str = "# Written by mt-client (magicTunnel) while the tunnel is up; \
                      the original returns when it stops.\n";

pub enum Dns {
    Resolved {
        link: String,
    },
    File {
        state: Arc<Mutex<FileState>>,
        watcher: JoinHandle<()>,
    },
}

/// Puts back a resolv.conf that a crashed run left rewritten.
pub fn restore_stale() {
    let ledger = Ledger::persistent(LEDGER);
    let Some(backup) = ledger.take::<Backup>() else {
        return;
    };
    match backup.restore(Path::new(RESOLV_CONF)) {
        Ok(true) => tracing::info!("restored {RESOLV_CONF} left rewritten by an earlier run"),
        Ok(false) => {}
        Err(e) => {
            tracing::warn!("failed to restore {RESOLV_CONF} after an earlier run: {e}");
            if let Err(e) = ledger.record(&backup) {
                tracing::warn!(path = %ledger.path().display(), "cannot keep the DNS record: {e}");
            }
        }
    }
}

impl Dns {
    pub fn apply(tun: &Tun, servers: &[Ipv4Addr]) -> anyhow::Result<Self> {
        let current = match fs::read_to_string(RESOLV_CONF) {
            Ok(text) => text,
            Err(e) if e.kind() == io::ErrorKind::NotFound => String::new(),
            Err(e) => return Err(e).with_context(|| format!("reading {RESOLV_CONF}")),
        };
        if uses_resolved_stub(&current) {
            apply_resolved(&tun.name, servers)?;
            tracing::info!(link = %tun.name, ?servers, "DNS servers set on the TUN in systemd-resolved");
            return Ok(Self::Resolved {
                link: tun.name.clone(),
            });
        }

        let state = FileState::apply(RESOLV_CONF.into(), Ledger::persistent(LEDGER), servers)?;
        tracing::info!(?servers, "DNS servers written to {RESOLV_CONF}");
        let state = Arc::new(Mutex::new(state));
        let watcher = tokio::spawn(watch(state.clone()));
        Ok(Self::File { state, watcher })
    }
}

impl Drop for Dns {
    fn drop(&mut self) {
        match self {
            Self::Resolved { link } => match resolvectl(&["revert", link]) {
                Ok(()) => tracing::info!("DNS settings of the TUN reverted"),
                // The settings go away with the link anyway.
                Err(e) => tracing::debug!("{e:#}"),
            },
            Self::File { state, watcher } => {
                watcher.abort();
                state
                    .lock()
                    .unwrap_or_else(PoisonError::into_inner)
                    .restore();
            }
        }
    }
}

/// `/etc/resolv.conf` while the tunnel's version is in place. Shared with the watcher; the
/// lock keeps it from re-applying after the restore.
pub struct FileState {
    path: PathBuf,
    ledger: Ledger,
    servers: Vec<Ipv4Addr>,
    backup: Backup,
    active: bool,
}

impl FileState {
    fn apply(path: PathBuf, ledger: Ledger, servers: &[Ipv4Addr]) -> anyhow::Result<Self> {
        let backup =
            Backup::take(&path, servers).with_context(|| format!("reading {}", path.display()))?;
        // Recorded first, so a crash right after the write below still gets undone.
        ledger
            .record(&backup)
            .with_context(|| format!("saving the original to {}", ledger.path().display()))?;
        if let Err(e) = backup.write_ours(&path) {
            ledger.clear();
            return Err(e).with_context(|| format!("writing {}", path.display()));
        }
        Ok(Self {
            path,
            ledger,
            servers: servers.to_vec(),
            backup,
            active: true,
        })
    }

    /// Puts the tunnel's version back if something replaced it; returns whether it did.
    fn reassert(&mut self) -> anyhow::Result<bool> {
        if !self.active || self.backup.is_current(&self.path) {
            return Ok(false);
        }
        let backup = Backup::take(&self.path, &self.servers)?;
        self.ledger.record(&backup)?;
        backup.write_ours(&self.path)?;
        self.backup = backup;
        Ok(true)
    }

    fn restore(&mut self) {
        if !std::mem::replace(&mut self.active, false) {
            return;
        }
        let path = self.path.display();
        match self.backup.restore(&self.path) {
            Ok(true) => tracing::info!("original {path} restored"),
            Ok(false) => tracing::warn!("{path} was replaced by another program, leaving it"),
            // The record stays, so the next start retries.
            Err(e) => {
                tracing::warn!(
                    "failed to restore {path}: {e}; the original is saved in {}",
                    self.ledger.path().display()
                );
                return;
            }
        }
        self.ledger.clear();
    }
}

async fn watch(state: Arc<Mutex<FileState>>) {
    let mut tick = tokio::time::interval(WATCH_INTERVAL);
    tick.tick().await;
    loop {
        tick.tick().await;
        let mut state = state.lock().unwrap_or_else(PoisonError::into_inner);
        match state.reassert() {
            Ok(true) => tracing::warn!(
                "{} was overwritten by another program; tunnel DNS re-applied",
                state.path.display()
            ),
            Ok(false) => {}
            Err(e) => tracing::warn!(
                "cannot re-apply tunnel DNS to {}: {e:#}",
                state.path.display()
            ),
        }
    }
}

/// What resolv.conf was before, and what the tunnel replaced it with.
#[derive(Debug, PartialEq, Serialize, Deserialize)]
struct Backup {
    original: Original,
    ours: String,
}

#[derive(Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum Original {
    File(String),
    /// Typically into a network manager's runtime directory.
    Symlink(PathBuf),
    Missing,
}

impl Backup {
    fn take(path: &Path, servers: &[Ipv4Addr]) -> io::Result<Self> {
        let original = match fs::symlink_metadata(path) {
            Ok(meta) if meta.file_type().is_symlink() => Original::Symlink(fs::read_link(path)?),
            Ok(_) => Original::File(fs::read_to_string(path)?),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Original::Missing,
            Err(e) => return Err(e),
        };
        let text = match &original {
            Original::File(text) => text.clone(),
            Original::Symlink(_) => fs::read_to_string(path).unwrap_or_default(),
            Original::Missing => String::new(),
        };
        Ok(Self {
            ours: render(servers, &text),
            original,
        })
    }

    fn is_current(&self, path: &Path) -> bool {
        fs::symlink_metadata(path).is_ok_and(|meta| meta.is_file())
            && fs::read_to_string(path).is_ok_and(|text| text == self.ours)
    }

    fn write_ours(&self, path: &Path) -> io::Result<()> {
        match self.original {
            // In place: keeps owner and mode, and works where the file is a bind mount, as in
            // containers.
            Original::File(_) => fs::write(path, &self.ours),
            // Replacing the link leaves its target, which belongs to someone else, untouched.
            Original::Symlink(_) | Original::Missing => replace(path, |tmp| {
                fs::write(tmp, &self.ours)?;
                fs::set_permissions(tmp, fs::Permissions::from_mode(0o644))
            }),
        }
    }

    /// Puts the original back, unless the file no longer holds the tunnel's version; returns
    /// whether it did.
    fn restore(&self, path: &Path) -> io::Result<bool> {
        if !self.is_current(path) {
            return Ok(false);
        }
        match &self.original {
            Original::File(text) => fs::write(path, text)?,
            Original::Symlink(target) => {
                replace(path, |tmp| std::os::unix::fs::symlink(target, tmp))?
            }
            Original::Missing => fs::remove_file(path)?,
        }
        Ok(true)
    }
}

/// Atomically replaces `path` with what `create` makes at a temporary path next to it.
fn replace(path: &Path, create: impl FnOnce(&Path) -> io::Result<()>) -> io::Result<()> {
    let tmp = path.with_file_name(".resolv.conf.mt-client");
    let _ = fs::remove_file(&tmp);
    create(&tmp)
        .and_then(|()| fs::rename(&tmp, path))
        .inspect_err(|_| {
            let _ = fs::remove_file(&tmp);
        })
}

/// The tunnel's resolv.conf: its servers, plus the original's search domains and options.
fn render(servers: &[Ipv4Addr], original: &str) -> String {
    let mut out = HEADER.to_owned();
    for server in servers {
        let _ = writeln!(out, "nameserver {server}");
    }
    for line in original.lines() {
        if matches!(
            line.split_whitespace().next(),
            Some("search" | "domain" | "options")
        ) {
            out.push_str(line);
            out.push('\n');
        }
    }
    out
}

fn uses_resolved_stub(resolv_conf: &str) -> bool {
    resolv_conf.lines().any(|line| {
        let mut words = line.split_whitespace();
        words.next() == Some("nameserver")
            && words
                .next()
                .is_some_and(|addr| STUB_RESOLVERS.contains(&addr))
    })
}

fn apply_resolved(link: &str, servers: &[Ipv4Addr]) -> anyhow::Result<()> {
    let servers: Vec<String> = servers.iter().map(ToString::to_string).collect();
    let mut args = vec!["dns", link];
    args.extend(servers.iter().map(String::as_str));
    resolvectl(&args)?;
    // Matches every name, so other links only keep queries for their own (longer) domains.
    if let Err(e) = resolvectl(&["domain", link, "~."]) {
        let _ = resolvectl(&["revert", link]);
        return Err(e);
    }
    if let Err(e) = resolvectl(&["flush-caches"]) {
        tracing::debug!("{e:#}");
    }
    Ok(())
}

fn resolvectl(args: &[&str]) -> anyhow::Result<()> {
    tracing::debug!(?args, "resolvectl");
    let output = Command::new("resolvectl")
        .args(args)
        .output()
        .context("failed to run `resolvectl` (systemd-resolved manages /etc/resolv.conf)")?;
    if output.status.success() {
        return Ok(());
    }
    bail!(
        "`resolvectl {}` failed: {}",
        args.join(" "),
        String::from_utf8_lossy(&output.stderr).trim()
    )
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::MetadataExt;

    use super::*;

    const SERVERS: [Ipv4Addr; 2] = [Ipv4Addr::new(1, 1, 1, 1), Ipv4Addr::new(8, 8, 8, 8)];
    const ORIGINAL: &str = "# Generated by NetworkManager\nsearch lan\n\
                            nameserver 192.168.1.1\nnameserver fd00::1\noptions edns0\n";

    struct Dir(PathBuf);

    impl Dir {
        fn new(name: &str) -> Self {
            let dir = std::env::temp_dir().join(format!("mt-dns-{name}-{}", std::process::id()));
            let _ = fs::remove_dir_all(&dir);
            fs::create_dir_all(&dir).unwrap();
            Self(dir)
        }

        fn state(&self, resolv: &Path) -> anyhow::Result<FileState> {
            FileState::apply(
                resolv.to_owned(),
                Ledger::at(self.0.join("state").join(LEDGER)),
                &SERVERS,
            )
        }
    }

    impl Drop for Dir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn renders_servers_and_keeps_search_and_options() {
        assert_eq!(
            render(&SERVERS, ORIGINAL),
            format!("{HEADER}nameserver 1.1.1.1\nnameserver 8.8.8.8\nsearch lan\noptions edns0\n")
        );
        assert_eq!(
            render(&SERVERS[..1], ""),
            format!("{HEADER}nameserver 1.1.1.1\n")
        );
    }

    #[test]
    fn detects_the_resolved_stub() {
        assert!(uses_resolved_stub(
            "# This is /run/systemd/resolve/stub-resolv.conf\nnameserver 127.0.0.53\noptions edns0 trust-ad\n"
        ));
        assert!(uses_resolved_stub("nameserver\t127.0.0.54\n"));
        assert!(!uses_resolved_stub(ORIGINAL));
        assert!(!uses_resolved_stub("# nameserver 127.0.0.53\n"));
    }

    #[test]
    fn rewrites_a_file_in_place_and_restores_it() {
        let dir = Dir::new("file");
        let resolv = dir.0.join("resolv.conf");
        fs::write(&resolv, ORIGINAL).unwrap();
        fs::set_permissions(&resolv, fs::Permissions::from_mode(0o640)).unwrap();
        let inode = fs::metadata(&resolv).unwrap().ino();

        let mut state = dir.state(&resolv).unwrap();
        let ours = fs::read_to_string(&resolv).unwrap();
        assert!(ours.contains("nameserver 1.1.1.1\n") && !ours.contains("192.168.1.1"));
        let meta = fs::metadata(&resolv).unwrap();
        assert_eq!((meta.ino(), meta.mode() & 0o777), (inode, 0o640));
        assert!(state.ledger.path().exists());
        assert!(!state.reassert().unwrap());

        state.restore();
        assert_eq!(fs::read_to_string(&resolv).unwrap(), ORIGINAL);
        assert!(!state.ledger.path().exists());
        state.restore();
        assert_eq!(fs::read_to_string(&resolv).unwrap(), ORIGINAL);
    }

    #[test]
    fn replaces_a_symlink_and_puts_it_back() {
        let dir = Dir::new("symlink");
        let target = dir.0.join("nm-resolv.conf");
        let resolv = dir.0.join("resolv.conf");
        fs::write(&target, ORIGINAL).unwrap();
        std::os::unix::fs::symlink(&target, &resolv).unwrap();

        let mut state = dir.state(&resolv).unwrap();
        assert!(fs::symlink_metadata(&resolv).unwrap().is_file());
        assert!(
            fs::read_to_string(&resolv)
                .unwrap()
                .contains("search lan\n")
        );
        assert_eq!(fs::read_to_string(&target).unwrap(), ORIGINAL);

        state.restore();
        assert_eq!(fs::read_link(&resolv).unwrap(), target);
        assert!(!dir.0.join(".resolv.conf.mt-client").exists());
    }

    #[test]
    fn creates_a_missing_file_and_removes_it() {
        let dir = Dir::new("missing");
        let resolv = dir.0.join("resolv.conf");
        let mut state = dir.state(&resolv).unwrap();
        assert_eq!(
            fs::read_to_string(&resolv).unwrap(),
            format!("{HEADER}nameserver 1.1.1.1\nnameserver 8.8.8.8\n")
        );
        state.restore();
        assert!(!resolv.exists());
    }

    #[test]
    fn reasserts_over_a_rewrite_and_restores_the_newcomer() {
        let dir = Dir::new("rewrite");
        let resolv = dir.0.join("resolv.conf");
        fs::write(&resolv, ORIGINAL).unwrap();
        let mut state = dir.state(&resolv).unwrap();

        let renewed = "search home.arpa\nnameserver 192.168.1.254\n";
        fs::write(&resolv, renewed).unwrap();
        assert!(state.reassert().unwrap());
        let ours = fs::read_to_string(&resolv).unwrap();
        assert!(ours.contains("nameserver 1.1.1.1\n") && ours.contains("search home.arpa\n"));
        assert!(!ours.contains("192.168.1.254"));

        state.restore();
        assert_eq!(fs::read_to_string(&resolv).unwrap(), renewed);
    }

    #[test]
    fn restore_leaves_a_foreign_file_alone() {
        let dir = Dir::new("foreign");
        let resolv = dir.0.join("resolv.conf");
        fs::write(&resolv, ORIGINAL).unwrap();
        let mut state = dir.state(&resolv).unwrap();
        fs::write(&resolv, "nameserver 10.0.0.1\n").unwrap();
        state.restore();
        assert_eq!(
            fs::read_to_string(&resolv).unwrap(),
            "nameserver 10.0.0.1\n"
        );
        assert!(!state.ledger.path().exists());
    }

    #[test]
    fn restores_from_the_record_of_a_crashed_run() {
        let dir = Dir::new("crash");
        let resolv = dir.0.join("resolv.conf");
        fs::write(&resolv, ORIGINAL).unwrap();
        let state = dir.state(&resolv).unwrap();
        let ledger = Ledger::at(state.ledger.path().to_owned());
        std::mem::forget(state);

        let backup = ledger.take::<Backup>().unwrap();
        assert!(backup.restore(&resolv).unwrap());
        assert_eq!(fs::read_to_string(&resolv).unwrap(), ORIGINAL);
        assert!(!backup.restore(&resolv).unwrap());
    }
}
