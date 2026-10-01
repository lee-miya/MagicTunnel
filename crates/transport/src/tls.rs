//! mTLS: every node presents a certificate signed by the shared CA and verifies its peer's.

use std::sync::Arc;

use magictunnel_common::config::TlsConfig;
use magictunnel_common::proto::ALPN;
use quinn::crypto::rustls::{QuicClientConfig, QuicServerConfig};
use rustls::RootCertStore;
use rustls::crypto::CryptoProvider;
use rustls::server::WebPkiClientVerifier;
use rustls_pki_types::{CertificateDer, PrivateKeyDer};

use crate::Result;
use crate::endpoint::transport_config;

/// A node's trust anchors plus its own certificate chain and key.
#[derive(Debug)]
pub struct TlsMaterial {
    roots: Arc<RootCertStore>,
    certs: Vec<CertificateDer<'static>>,
    key: PrivateKeyDer<'static>,
}

impl TlsMaterial {
    pub fn load(cfg: &TlsConfig) -> Result<Self> {
        use magictunnel_common::tls::{load_certs, load_key};
        Self::new(
            load_certs(&cfg.ca)?,
            load_certs(&cfg.cert)?,
            load_key(&cfg.key)?,
        )
    }

    pub fn new(
        ca: Vec<CertificateDer<'static>>,
        certs: Vec<CertificateDer<'static>>,
        key: PrivateKeyDer<'static>,
    ) -> Result<Self> {
        let mut roots = RootCertStore::empty();
        for cert in ca {
            roots.add(cert)?;
        }
        Ok(Self {
            roots: Arc::new(roots),
            certs,
            key,
        })
    }

    /// Config for dialing a hop: verifies the hop's certificate and name, presents ours.
    pub fn client_config(&self) -> Result<quinn::ClientConfig> {
        let mut crypto = rustls::ClientConfig::builder_with_provider(provider())
            .with_protocol_versions(&[&rustls::version::TLS13])?
            .with_root_certificates(self.roots.clone())
            .with_client_auth_cert(self.certs.clone(), self.key.clone_key())?;
        crypto.alpn_protocols = vec![ALPN.to_vec()];

        let mut config = quinn::ClientConfig::new(Arc::new(QuicClientConfig::try_from(crypto)?));
        config.transport_config(Arc::new(transport_config()));
        Ok(config)
    }

    /// Config for accepting peers: requires a client certificate signed by our CA.
    pub fn server_config(&self) -> Result<quinn::ServerConfig> {
        let verifier =
            WebPkiClientVerifier::builder_with_provider(self.roots.clone(), provider()).build()?;
        let mut crypto = rustls::ServerConfig::builder_with_provider(provider())
            .with_protocol_versions(&[&rustls::version::TLS13])?
            .with_client_cert_verifier(verifier)
            .with_single_cert(self.certs.clone(), self.key.clone_key())?;
        crypto.alpn_protocols = vec![ALPN.to_vec()];

        let mut config =
            quinn::ServerConfig::with_crypto(Arc::new(QuicServerConfig::try_from(crypto)?));
        config.transport_config(Arc::new(transport_config()));
        Ok(config)
    }
}

/// Pinned explicitly so behavior doesn't depend on which rustls backends get compiled in.
fn provider() -> Arc<CryptoProvider> {
    Arc::new(rustls::crypto::ring::default_provider())
}
