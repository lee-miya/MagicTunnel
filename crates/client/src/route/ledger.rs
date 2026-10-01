//! On-disk record of the first-hop bypass route, for platforms that cannot tag routes the way
//! Linux does with `proto`. It is written once the route is added and removed once it is
//! deleted, so a run that dies in between leaves a record the next start uses to delete it.

use std::path::{Path, PathBuf};
use std::{fs, io};

use serde::Serialize;
use serde::de::DeserializeOwned;

const FILE_NAME: &str = "magictunnel-client-route.json";

pub struct Ledger {
    path: PathBuf,
}

impl Ledger {
    pub fn system() -> Self {
        Self::at(system_dir().join(FILE_NAME))
    }

    pub fn at(path: PathBuf) -> Self {
        Self { path }
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Returns the recorded route, if any, and forgets it.
    pub fn take<T: DeserializeOwned>(&self) -> Option<T> {
        let text = match fs::read_to_string(&self.path) {
            Ok(text) => text,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return None,
            Err(e) => {
                tracing::warn!(path = %self.path.display(), "cannot read route record: {e}");
                return None;
            }
        };
        self.clear();
        serde_json::from_str(&text)
            .inspect_err(|e| {
                tracing::warn!(path = %self.path.display(), "ignoring corrupt route record: {e}")
            })
            .ok()
    }

    pub fn record<T: Serialize>(&self, route: &T) -> io::Result<()> {
        if let Some(dir) = self.path.parent() {
            fs::create_dir_all(dir)?;
        }
        fs::write(&self.path, serde_json::to_vec(route)?)
    }

    pub fn clear(&self) {
        match fs::remove_file(&self.path) {
            Ok(()) => {}
            Err(e) if e.kind() == io::ErrorKind::NotFound => {}
            Err(e) => {
                tracing::warn!(path = %self.path.display(), "cannot remove route record: {e}")
            }
        }
    }
}

/// Cleared at boot on macOS, matching the lifetime of the routes it describes.
#[cfg(target_os = "macos")]
fn system_dir() -> PathBuf {
    PathBuf::from("/var/run")
}

#[cfg(windows)]
fn system_dir() -> PathBuf {
    std::env::var_os("ProgramData")
        .map(PathBuf::from)
        .unwrap_or_else(std::env::temp_dir)
        .join("magicTunnel")
}

#[cfg(not(any(target_os = "macos", windows)))]
fn system_dir() -> PathBuf {
    std::env::temp_dir()
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use super::*;

    #[test]
    fn records_and_takes_once() {
        let dir = std::env::temp_dir().join(format!("mt-ledger-test-{}", std::process::id()));
        let ledger = Ledger::at(dir.join("nested").join(FILE_NAME));
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
