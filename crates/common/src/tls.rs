use std::path::Path;

use rustls_pki_types::pem::PemObject;
use rustls_pki_types::{CertificateDer, PrivateKeyDer};

use crate::{Error, Result};

pub fn load_certs(path: impl AsRef<Path>) -> Result<Vec<CertificateDer<'static>>> {
    let path = path.as_ref();
    let pem_err = |source| Error::Pem {
        path: path.to_owned(),
        source,
    };
    let certs = CertificateDer::pem_file_iter(path)
        .map_err(pem_err)?
        .collect::<std::result::Result<Vec<_>, _>>()
        .map_err(pem_err)?;
    if certs.is_empty() {
        return Err(Error::NoCertificates(path.to_owned()));
    }
    Ok(certs)
}

pub fn load_key(path: impl AsRef<Path>) -> Result<PrivateKeyDer<'static>> {
    let path = path.as_ref();
    PrivateKeyDer::from_pem_file(path).map_err(|source| Error::Pem {
        path: path.to_owned(),
        source,
    })
}
