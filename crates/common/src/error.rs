use std::path::PathBuf;

pub type Result<T, E = Error> = std::result::Result<T, E>;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("failed to read {path}")]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    #[error("failed to parse config {path}")]
    ConfigParse {
        path: PathBuf,
        #[source]
        source: toml::de::Error,
    },

    #[error("invalid config: {0}")]
    InvalidConfig(String),

    #[error("failed to load PEM from {path}")]
    Pem {
        path: PathBuf,
        #[source]
        source: rustls_pki_types::pem::Error,
    },

    #[error("no certificates found in {0}")]
    NoCertificates(PathBuf),
}
