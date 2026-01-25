use crate::{
    configuration::{LdapsOptions},
    tls,
};
use anyhow::{Context, Result, anyhow, bail, ensure};
use futures_util::SinkExt;
use ldap3_proto::{
    LdapCodec,
    proto::{
        LdapDerefAliases, LdapFilter, LdapMsg, LdapOp, LdapSearchRequest, LdapSearchResultEntry,
        LdapSearchScope,
    },
};
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::{verify_tls12_signature, verify_tls13_signature};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{DigitallySignedStruct, SignatureScheme};
use std::sync::Arc;
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
    let mut requests = FramedRead::new(r, LdapCodec::default());
    let mut resp = FramedWrite::new(w, LdapCodec::default());

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

#[instrument(level = "info", err)]
pub async fn check_ldap(host: &str, port: u16) -> Result<()> {
    check_ldap_endpoint(TcpStream::connect((host, port)).await?).await
}

fn get_tls_connector(ldaps_options: &LdapsOptions) -> Result<RustlsTlsConnector> {
    let certs = tls::load_certificates(&ldaps_options.cert_file)?;
    let target_cert = certs.first().expect("empty certificate chain").clone();

    #[derive(Debug)]
    struct CertificateVerifier {
        certificate: CertificateDer<'static>,
    }

    impl ServerCertVerifier for CertificateVerifier {
        fn verify_server_cert(
            &self,
            end_entity: &CertificateDer<'_>,
            _intermediates: &[CertificateDer<'_>],
            _server_name: &ServerName<'_>,
            _ocsp_response: &[u8],
            _now: UnixTime,
        ) -> Result<ServerCertVerified, rustls::Error> {
            if end_entity != &self.certificate {
                return Err(rustls::Error::InvalidCertificate(
                    rustls::CertificateError::NotValidForName,
                ));
            }
            Ok(ServerCertVerified::assertion())
        }

        fn verify_tls12_signature(
            &self,
            message: &[u8],
            cert: &CertificateDer<'_>,
            dss: &DigitallySignedStruct,
        ) -> Result<HandshakeSignatureValid, rustls::Error> {
            verify_tls12_signature(
                message,
                cert,
                dss,
                &rustls::crypto::ring::default_provider().signature_verification_algorithms,
            )
        }

        fn verify_tls13_signature(
            &self,
            message: &[u8],
            cert: &CertificateDer<'_>,
            dss: &DigitallySignedStruct,
        ) -> Result<HandshakeSignatureValid, rustls::Error> {
            verify_tls13_signature(
                message,
                cert,
                dss,
                &rustls::crypto::ring::default_provider().signature_verification_algorithms,
            )
        }

        fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
            rustls::crypto::ring::default_provider()
                .signature_verification_algorithms
                .supported_schemes()
        }
    }

    let verifier = Arc::new(CertificateVerifier {
        certificate: target_cert,
    });

    let client_config = rustls::ClientConfig::builder_with_provider(
        rustls::crypto::ring::default_provider().into(),
    )
    .with_safe_default_protocol_versions()
    .context("Failed to set default protocol versions")?
    .dangerous()
    .with_custom_certificate_verifier(verifier)
    .with_no_client_auth();

    Ok(Arc::new(client_config).into())
}

#[instrument(skip_all, level = "info", err, fields(host = %host, port = %ldaps_options.port))]
pub async fn check_ldaps(host: &str, ldaps_options: &LdapsOptions) -> Result<()> {
    if !ldaps_options.enabled {
        info!("LDAPS not enabled");
        return Ok(());
    };
    let tls_connector =
        get_tls_connector(ldaps_options).context("while preparing the tls connection")?;

    let domain = ServerName::try_from(host.to_string())
        .map_err(|_| anyhow!("Invalid DNS name: {}", host))?;

    check_ldap_endpoint(
        tls_connector
            .connect(
                domain,
                TcpStream::connect((host, ldaps_options.port))
                    .await
                    .context("while connecting TCP")?,
            )
            .await
            .context("while connecting TLS")?,
    )
    .await
}

#[instrument(level = "info", err)]
pub async fn check_api(host: &str, port: u16) -> Result<()> {
    reqwest::get(format!("http://{host}:{port}/health"))
        .await?
        .error_for_status()?;
    info!("Success");
    Ok(())
}
