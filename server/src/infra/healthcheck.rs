use crate::infra::configuration::LdapsOptions;
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

fn get_tls_connector() -> Result<RustlsTlsConnector> {
    use rustls::ClientConfig;
    let client_config = std::sync::Arc::new(
        ClientConfig::builder()
            .with_safe_defaults()
            .with_root_certificates(get_root_certificates())
            .with_no_client_auth(),
    );
    Ok(client_config.into())
}

#[instrument(skip_all, level = "info", err)]
pub async fn check_ldaps(ldaps_options: &LdapsOptions) -> Result<()> {
    if !ldaps_options.enabled {
        return Ok(());
    };
    let tls_connector = get_tls_connector()?;
    let url = format!("localhost:{}", ldaps_options.port);
    check_ldap_endpoint(
        tls_connector
            .connect(
                rustls::ServerName::try_from(url.as_str())?,
                TcpStream::connect(&url).await?,
            )
            .await?,
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
