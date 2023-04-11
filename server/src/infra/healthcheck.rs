use crate::infra::{configuration::LdapsOptions, ldap_server::read_certificates};
use anyhow::{anyhow, bail, ensure, Context, Result};
use futures_util::SinkExt;
use ldap3_proto::{
    proto::{
        LdapDerefAliases, LdapFilter, LdapMsg, LdapOp, LdapSearchRequest, LdapSearchResultEntry,
        LdapSearchScope,
    },
    LdapCodec,
};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector as RustlsTlsConnector;
use tokio_util::codec::{FramedRead, FramedWrite};
use tracing::{debug, info, instrument};

async fn check_ldap_endpoint<Stream>(stream: Stream) -> Result<()>
where
    Stream: tokio::io::AsyncRead + tokio::io::AsyncWrite,
{
    use tokio_stream::StreamExt;
    let (r, w) = tokio::io::split(stream);
    let mut requests = FramedRead::new(r, LdapCodec);
    let mut resp = FramedWrite::new(w, LdapCodec);

    resp.send(LdapMsg {
        msgid: 0,
        op: LdapOp::SearchRequest(LdapSearchRequest {
            base: "".to_string(),
            scope: LdapSearchScope::Base,
            aliases: LdapDerefAliases::Never,
            sizelimit: 0,
            timelimit: 0,
            typesonly: false,
            filter: LdapFilter::Present("objectClass".to_string()),
            attrs: vec!["supportedExtension".to_string()],
        }),
        ctrl: vec![],
    })
    .await?;
    resp.flush().await?;

    let no_answer = || anyhow!("No answer from LDAP server");
    let invalid_answer = "Invalid answer from LDAP server";

    let msg = requests
        .next()
        .await
        .ok_or_else(no_answer)?
        .context(invalid_answer)?;
    debug!("Received message: {:?}", &msg);
    match msg.op {
        LdapOp::SearchResultEntry(LdapSearchResultEntry { dn, attributes }) => ensure!(
            dn.is_empty()
                && attributes
                    .into_iter()
                    .any(|a| a.atype == "objectClass" && a.vals == vec![b"top".to_vec()]),
            invalid_answer
        ),
        _ => bail!(invalid_answer),
    }
    let msg = requests.next().await.ok_or_else(no_answer)??;
    debug!("Received message: {:?}", &msg);
    ensure!(
        matches!(msg.op, LdapOp::SearchResultDone(_)),
        invalid_answer
    );
    info!("Success");
    resp.close().await?;
    Ok(())
}

#[instrument(skip_all, level = "info", err)]
pub async fn check_ldap(port: u16) -> Result<()> {
    check_ldap_endpoint(TcpStream::connect(format!("localhost:{}", port)).await?).await
}

fn get_root_certificates() -> rustls::RootCertStore {
    let mut root_store = rustls::RootCertStore::empty();
    root_store.add_server_trust_anchors(webpki_roots::TLS_SERVER_ROOTS.0.iter().map(|ta| {
        rustls::OwnedTrustAnchor::from_subject_spki_name_constraints(
            ta.subject,
            ta.spki,
            ta.name_constraints,
        )
    }));
    root_store
}

fn get_tls_connector(ldaps_options: &LdapsOptions) -> Result<RustlsTlsConnector> {
    let mut client_config = rustls::ClientConfig::builder()
        .with_safe_defaults()
        .with_root_certificates(get_root_certificates())
        .with_no_client_auth();
    let (certs, _private_key) = read_certificates(ldaps_options)?;
    // Check that the server cert is the one in the config file.
    struct CertificateVerifier {
        certificate: rustls::Certificate,
        certificate_path: String,
    }
    impl rustls::client::ServerCertVerifier for CertificateVerifier {
        fn verify_server_cert(
            &self,
            end_entity: &rustls::Certificate,
            _intermediates: &[rustls::Certificate],
            _server_name: &rustls::ServerName,
            _scts: &mut dyn Iterator<Item = &[u8]>,
            _ocsp_response: &[u8],
            _now: std::time::SystemTime,
        ) -> std::result::Result<rustls::client::ServerCertVerified, rustls::Error> {
            if end_entity != &self.certificate {
                return Err(rustls::Error::InvalidCertificateData(format!(
                    "Server certificate doesn't match the one in the config file {}",
                    &self.certificate_path
                )));
            }
            Ok(rustls::client::ServerCertVerified::assertion())
        }
    }
    let mut dangerous_config = rustls::client::DangerousClientConfig {
        cfg: &mut client_config,
    };
    dangerous_config.set_certificate_verifier(std::sync::Arc::new(CertificateVerifier {
        certificate: certs.first().expect("empty certificate chain").clone(),
        certificate_path: ldaps_options.cert_file.clone(),
    }));
    Ok(std::sync::Arc::new(client_config).into())
}

#[instrument(skip_all, level = "info", err)]
pub async fn check_ldaps(ldaps_options: &LdapsOptions) -> Result<()> {
    if !ldaps_options.enabled {
        info!("LDAPS not enabled");
        return Ok(());
    };
    let tls_connector =
        get_tls_connector(ldaps_options).context("while preparing the tls connection")?;
    let url = format!("localhost:{}", ldaps_options.port);
    check_ldap_endpoint(
        tls_connector
            .connect(
                rustls::ServerName::try_from("localhost")
                    .context("while parsing the server name")?,
                TcpStream::connect(&url)
                    .await
                    .context("while connecting TCP")?,
            )
            .await
            .context("while connecting TLS")?,
    )
    .await
}

#[instrument(skip_all, level = "info", err)]
pub async fn check_api(port: u16) -> Result<()> {
    reqwest::get(format!("http://localhost:{}/health", port))
        .await?
        .error_for_status()?;
    info!("Success");
    Ok(())
}
