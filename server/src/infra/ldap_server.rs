use crate::{
    domain::{
        handler::{BackendHandler, LoginHandler},
        opaque_handler::OpaqueHandler,
        types::AttributeName,
    },
    infra::{
        access_control::AccessControlledBackendHandler,
        configuration::{Configuration, LdapsOptions},
        ldap_handler::LdapHandler,
    },
};
use actix_rt::net::TcpStream;
use actix_server::ServerBuilder;
use actix_service::{fn_service, ServiceFactoryExt};
use anyhow::{anyhow, Context, Result};
use ldap3_proto::{control::LdapControl, proto::LdapMsg, proto::LdapOp, LdapCodec};
use rustls::PrivateKey;
use tokio_rustls::TlsAcceptor as RustlsTlsAcceptor;
use tokio_util::codec::{FramedRead, FramedWrite};
use tracing::{debug, error, info, instrument};

#[instrument(skip_all, level = "info", name = "LDAP request")]
async fn handle_ldap_message<Backend, Writer>(
    msg: Result<LdapMsg, std::io::Error>,
    resp: &mut Writer,
    session: &mut LdapHandler<Backend>,
) -> Result<bool>
where
    Backend: BackendHandler + LoginHandler + OpaqueHandler,
    Writer: futures_util::Sink<LdapMsg> + Unpin,
    <Writer as futures_util::Sink<LdapMsg>>::Error: std::error::Error + Send + Sync + 'static,
{
    use futures_util::SinkExt;
    let msg = msg.context("while receiving LDAP op")?;
    debug!(?msg);
    match session.handle_ldap_message(msg.op).await {
        None => return Ok(false),
        Some(result) => {
            if result.is_empty() {
                debug!("No response");
            }
            let results: i64 = result.len().try_into().unwrap();
            for response in result.into_iter() {
                debug!(?response);
                let controls = if matches!(response, LdapOp::SearchResultDone(_)) {
                    vec![LdapControl::SimplePagedResults {
                        size: results - 1, // Avoid counting SearchResultDone as a result
                        cookie: vec![],
                    }]
                } else {
                    vec![]
                };
                resp.send(LdapMsg {
                    msgid: msg.msgid,
                    op: response,
                    ctrl: controls,
                })
                .await
                .context("while sending a response: {:#}")?
            }

            resp.flush()
                .await
                .context("while flushing responses: {:#}")?
        }
    }
    Ok(true)
}

#[instrument(skip_all, level = "info", name = "LDAP session")]
async fn handle_ldap_stream<Stream, Backend>(
    stream: Stream,
    backend_handler: Backend,
    ldap_base_dn: String,
    ignored_user_attributes: Vec<AttributeName>,
    ignored_group_attributes: Vec<AttributeName>,
) -> Result<Stream>
where
    Backend: BackendHandler + LoginHandler + OpaqueHandler + 'static,
    Stream: tokio::io::AsyncRead + tokio::io::AsyncWrite + std::marker::Unpin,
{
    use tokio_stream::StreamExt;
    let (r, w) = tokio::io::split(stream);
    // Configure the codec etc.
    let mut requests = FramedRead::new(r, LdapCodec::default());
    let mut resp = FramedWrite::new(w, LdapCodec::default());

    let mut session = LdapHandler::new(
        AccessControlledBackendHandler::new(backend_handler),
        ldap_base_dn,
        ignored_user_attributes,
        ignored_group_attributes,
    );

    while let Some(msg) = requests.next().await {
        if !handle_ldap_message(msg, &mut resp, &mut session)
            .await
            .context("while handling incoming messages")?
        {
            break;
        }
    }
    Ok(requests.into_inner().unsplit(resp.into_inner()))
}

fn read_private_key(key_file: &str) -> Result<PrivateKey> {
    use rustls_pemfile::{ec_private_keys, pkcs8_private_keys, rsa_private_keys};
    use std::{fs::File, io::BufReader};
    pkcs8_private_keys(&mut BufReader::new(File::open(key_file)?))
        .map_err(anyhow::Error::from)
        .and_then(|keys| {
            keys.into_iter()
                .next()
                .ok_or_else(|| anyhow!("No PKCS8 key"))
        })
        .or_else(|_| {
            rsa_private_keys(&mut BufReader::new(File::open(key_file)?))
                .map_err(anyhow::Error::from)
                .and_then(|keys| {
                    keys.into_iter()
                        .next()
                        .ok_or_else(|| anyhow!("No PKCS1 key"))
                })
        })
        .or_else(|_| {
            ec_private_keys(&mut BufReader::new(File::open(key_file)?))
                .map_err(anyhow::Error::from)
                .and_then(|keys| keys.into_iter().next().ok_or_else(|| anyhow!("No EC key")))
        })
        .with_context(|| {
            format!(
                "Cannot read either PKCS1, PKCS8 or EC private key from {}",
                key_file
            )
        })
        .map(rustls::PrivateKey)
}

pub fn read_certificates(
    ldaps_options: &LdapsOptions,
) -> Result<(Vec<rustls::Certificate>, rustls::PrivateKey)> {
    use std::{fs::File, io::BufReader};
    let certs = rustls_pemfile::certs(&mut BufReader::new(File::open(&ldaps_options.cert_file)?))?
        .into_iter()
        .map(rustls::Certificate)
        .collect::<Vec<_>>();
    let private_key = read_private_key(&ldaps_options.key_file)?;
    Ok((certs, private_key))
}

fn get_tls_acceptor(ldaps_options: &LdapsOptions) -> Result<RustlsTlsAcceptor> {
    let (certs, private_key) = read_certificates(ldaps_options)?;
    let server_config = std::sync::Arc::new(
        rustls::ServerConfig::builder()
            .with_safe_defaults()
            .with_no_client_auth()
            .with_single_cert(certs, private_key)?,
    );
    Ok(server_config.into())
}

pub fn build_ldap_server<Backend>(
    config: &Configuration,
    backend_handler: Backend,
    server_builder: ServerBuilder,
) -> Result<ServerBuilder>
where
    Backend: BackendHandler + LoginHandler + OpaqueHandler + Clone + 'static,
{
    let context = (
        backend_handler,
        config.ldap_base_dn.clone(),
        config.ignored_user_attributes.clone(),
        config.ignored_group_attributes.clone(),
    );

    let context_for_tls = context.clone();

    let binder = move || {
        let context = context.clone();
        fn_service(move |stream: TcpStream| {
            let context = context.clone();
            async move {
                let (handler, base_dn, ignored_user_attributes, ignored_group_attributes) = context;
                handle_ldap_stream(
                    stream,
                    handler,
                    base_dn,
                    ignored_user_attributes,
                    ignored_group_attributes,
                )
                .await
            }
        })
        .map_err(|err: anyhow::Error| error!("[LDAP] Service Error: {:#}", err))
    };

    info!("Starting the LDAP server on port {}", config.ldap_port);
    let server_builder = server_builder
        .bind("ldap", (config.ldap_host.clone(), config.ldap_port), binder)
        .with_context(|| format!("while binding to the port {}", config.ldap_port));
    if config.ldaps_options.enabled {
        let tls_context = (
            context_for_tls,
            get_tls_acceptor(&config.ldaps_options)
                .context("while setting up the SSL certificate")?,
        );
        let tls_binder = move || {
            let tls_context = tls_context.clone();
            fn_service(move |stream: TcpStream| {
                let tls_context = tls_context.clone();
                async move {
                    let (
                        (handler, base_dn, ignored_user_attributes, ignored_group_attributes),
                        tls_acceptor,
                    ) = tls_context;
                    let tls_stream = tls_acceptor.accept(stream).await?;
                    handle_ldap_stream(
                        tls_stream,
                        handler,
                        base_dn,
                        ignored_user_attributes,
                        ignored_group_attributes,
                    )
                    .await
                }
            })
            .map_err(|err: anyhow::Error| error!("[LDAPS] Service Error: {:#}", err))
        };

        info!(
            "Starting the LDAPS server on port {}",
            config.ldaps_options.port
        );
        server_builder.and_then(|s| {
            s.bind(
                "ldaps",
                (config.ldap_host.clone(), config.ldaps_options.port),
                tls_binder,
            )
            .with_context(|| format!("while binding to the port {}", config.ldaps_options.port))
        })
    } else {
        server_builder
    }
}
