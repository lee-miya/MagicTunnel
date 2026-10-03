//! On-disk record of a system change that would outlive a crash. It is written once the
//! change is made and removed once it is undone, so a run that dies in between leaves a
//! record the next start uses to undo it.

use std::path::{Path, PathBuf};
use std::{fs, io};

use serde::Serialize;
use serde::de::DeserializeOwned;

pub struct Ledger {
    path: PathBuf,
}

impl Ledger {
    /// For changes that do not survive a reboot either; on macOS the record goes with them.
    #[cfg_attr(target_os = "linux", allow(dead_code))]
    pub fn runtime(name: &str) -> Self {
        Self::at(runtime_dir().join(name))
    }

    /// For changes that persist across reboots.
    #[cfg_attr(windows, allow(dead_code))]
    pub fn persistent(name: &str) -> Self {
        Self::at(persistent_dir().join(name))
    }

    pub fn at(path: PathBuf) -> Self {
        Self { path }
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Returns the recorded change, if any, and forgets it.
    pub fn take<T: DeserializeOwned>(&self) -> Option<T> {
        let text = match fs::read_to_string(&self.path) {
            Ok(text) => text,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return None,
            Err(e) => {
                tracing::warn!(path = %self.path.display(), "cannot read record: {e}");
                return None;
            }
        };
        self.clear();
        serde_json::from_str(&text)
            .inspect_err(
                |e| tracing::warn!(path = %self.path.display(), "ignoring corrupt record: {e}"),
            )
            .ok()
    }

    pub fn record<T: Serialize>(&self, change: &T) -> io::Result<()> {
        if let Some(dir) = self.path.parent() {
            fs::create_dir_all(dir)?;
        }
        fs::write(&self.path, serde_json::to_vec(change)?)
    }

    pub fn clear(&self) {
        match fs::remove_file(&self.path) {
            Ok(()) => {}
            Err(e) if e.kind() == io::ErrorKind::NotFound => {}
            Err(e) => tracing::warn!(path = %self.path.display(), "cannot remove record: {e}"),
        }
    }
}

/// Cleared at boot on macOS.
#[cfg(target_os = "macos")]
fn runtime_dir() -> PathBuf {
    PathBuf::from("/var/run")
}

#[cfg(target_os = "macos")]
fn persistent_dir() -> PathBuf {
    PathBuf::from("/Library/Application Support/magicTunnel")
}

#[cfg(windows)]
fn runtime_dir() -> PathBuf {
    persistent_dir()
}

#[cfg(windows)]
fn persistent_dir() -> PathBuf {
    std::env::var_os("ProgramData")
        .map(PathBuf::from)
        .unwrap_or_else(std::env::temp_dir)
        .join("magicTunnel")
}

#[cfg(not(any(target_os = "macos", windows)))]
fn runtime_dir() -> PathBuf {
    std::env::temp_dir()
}

/// The systemd unit's `StateDirectory`.
#[cfg(not(any(target_os = "macos", windows)))]
fn persistent_dir() -> PathBuf {
    PathBuf::from("/var/lib/magictunnel")
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use super::*;

    #[test]
    fn records_and_takes_once() {
        let dir = std::env::temp_dir().join(format!("mt-ledger-test-{}", std::process::id()));
        let ledger = Ledger::at(dir.join("nested").join("record.json"));
        assert_eq!(ledger.take::<Ipv4Addr>(), None);

        let hop = Ipv4Addr::new(203, 0, 113, 7);
        ledger.record(&hop).unwrap();
        assert_eq!(ledger.take::<Ipv4Addr>(), Some(hop));
        assert_eq!(ledger.take::<Ipv4Addr>(), None);

        ledger.record(&hop).unwrap();
        ledger.clear();
        assert!(!ledger.path().exists());

        fs::write(ledger.path(), "not json").unwrap();
        assert_eq!(ledger.take::<Ipv4Addr>(), None);
        assert!(!ledger.path().exists());
        fs::remove_dir_all(&dir).unwrap();
    }
}
