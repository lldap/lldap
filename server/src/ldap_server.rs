use crate::configuration::{Configuration, LdapsOptions};
use crate::tls;
use actix_rt::net::TcpStream;
use actix_server::ServerBuilder;
use actix_service::{ServiceFactoryExt, fn_service};
use anyhow::{Context, Result};
use ldap3_proto::{LdapCodec, control::LdapControl, proto::LdapMsg, proto::LdapOp};
use lldap_access_control::AccessControlledBackendHandler;
use lldap_domain_handlers::handler::{BackendHandler, LoginHandler};
use lldap_ldap::{LdapHandler, LdapInfo};
use lldap_opaque_handler::OpaqueHandler;
use tokio_rustls::TlsAcceptor as RustlsTlsAcceptor;
use tokio_util::codec::{FramedRead, FramedWrite};
use tracing::{debug, error, info, instrument};
use uuid::Uuid;

#[instrument(skip_all, level = "info", name = "LDAP request", fields(session_id = %session.session_uuid()))]
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
    for control in msg.ctrl.iter() {
        if let LdapControl::Unknown { oid, .. } = control {
            info!("Received unknown control: {}, ignoring", oid);
        }
    }
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

async fn handle_ldap_stream<Stream, Backend>(
    stream: Stream,
    backend_handler: Backend,
    ldap_info: &'static LdapInfo,
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

    let session_uuid = Uuid::new_v4();
    let mut session = LdapHandler::new(
        AccessControlledBackendHandler::new(backend_handler),
        ldap_info,
        session_uuid,
    );

    info!("LDAP session start: {}", session_uuid);
    while let Some(msg) = requests.next().await {
        if !handle_ldap_message(msg, &mut resp, &mut session)
            .await
            .context("while handling incoming messages")?
        {
            break;
        }
    }
    info!("LDAP session end: {}", session_uuid);
    Ok(requests.into_inner().unsplit(resp.into_inner()))
}

fn get_tls_acceptor(ldaps_options: &LdapsOptions) -> Result<RustlsTlsAcceptor> {
    let certs = tls::load_certificates(&ldaps_options.cert_file)?;
    let private_key = tls::load_private_key(&ldaps_options.key_file)?;

    let server_config = std::sync::Arc::new(
        rustls::ServerConfig::builder_with_provider(
            rustls::crypto::ring::default_provider().into(),
        )
        .with_safe_default_protocol_versions()
        .expect("Failed to set default protocol versions")
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
        Box::leak(Box::new(
            LdapInfo::new(
                &config.ldap_base_dn,
                config.ignored_user_attributes.clone(),
                config.ignored_group_attributes.clone(),
            )
            .with_context(|| {
                format!(
                    "Invalid value for ldap_base_dn in configuration: {}",
                    &config.ldap_base_dn
                )
            })?,
        )) as &'static LdapInfo,
    );

    let context_for_tls = context.clone();

    let binder = move || {
        let context = context.clone();
        fn_service(move |stream: TcpStream| {
            let context = context.clone();
            async move {
                let (handler, ldap_info) = context;
                handle_ldap_stream(stream, handler, ldap_info).await
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
                    let ((handler, ldap_info), tls_acceptor) = tls_context;
                    let tls_stream = tls_acceptor.accept(stream).await?;
                    handle_ldap_stream(tls_stream, handler, ldap_info).await
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
