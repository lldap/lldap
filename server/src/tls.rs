use anyhow::{Context, Result, anyhow};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, pem::PemObject};

pub fn load_certificates(filename: &str) -> Result<Vec<CertificateDer<'static>>> {
    let certs = CertificateDer::pem_file_iter(filename)
        .with_context(|| format!("Unable to open or read certificate file: {}", filename))?
        .collect::<Result<Vec<_>, _>>()
        .with_context(|| format!("Error parsing certificates in {}", filename))?;

    if certs.is_empty() {
        return Err(anyhow!("No certificates found in {}", filename));
    }

    Ok(certs)
}

pub fn load_private_key(filename: &str) -> Result<PrivateKeyDer<'static>> {
    PrivateKeyDer::from_pem_file(filename)
        .with_context(|| format!("Unable to load private key from {}", filename))
}
