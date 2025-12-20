use anyhow::{Context, Result, anyhow};
use rustls::{Certificate, PrivateKey};
use std::fs::File;
use std::io::{BufReader, Cursor, Read};

pub fn load_certificates(filename: &str) -> Result<Vec<Certificate>> {
    let cert_file = File::open(filename)
        .with_context(|| format!("Unable to open certificate file: {}", filename))?;
    let mut reader = BufReader::new(cert_file);

    let certs = rustls_pemfile::certs(&mut reader)
        .context("Error parsing certificates")?
        .into_iter()
        .map(Certificate)
        .collect();

    Ok(certs)
}

pub fn load_private_key(filename: &str) -> Result<PrivateKey> {
    let mut file =
        File::open(filename).with_context(|| format!("Unable to open key file: {}", filename))?;
    let mut content = Vec::new();
    file.read_to_end(&mut content)
        .with_context(|| format!("Unable to read key file: {}", filename))?;

    let get_reader = || BufReader::new(Cursor::new(&content));

    if let Ok(keys) = rustls_pemfile::pkcs8_private_keys(&mut get_reader()) {
        if let Some(key) = keys.into_iter().next() {
            return Ok(PrivateKey(key));
        }
    }

    if let Ok(keys) = rustls_pemfile::rsa_private_keys(&mut get_reader()) {
        if let Some(key) = keys.into_iter().next() {
            return Ok(PrivateKey(key));
        }
    }

    if let Ok(keys) = rustls_pemfile::ec_private_keys(&mut get_reader()) {
        if let Some(key) = keys.into_iter().next() {
            return Ok(PrivateKey(key));
        }
    }

    Err(anyhow!(
        "No supported private key found in {}. \
        Expected formats: PKCS8, RSA (PKCS1) or EC (SEC1). \
        Note: Encrypted keys (with passwords) are not supported.",
        filename
    ))
}
