use crate::{
    domain::{
        error::DomainError,
        handler::{BackendHandler, LoginHandler},
        opaque_handler::OpaqueHandler,
    },
    infra::{
        access_control::{AccessControlledBackendHandler, ReadonlyBackendHandler},
        auth_service,
        configuration::{Configuration, MailOptions},
        logging::CustomRootSpanBuilder,
        tcp_backend_handler::*,
    },
};
use actix_files::{Files, NamedFile};
use actix_http::{header, HttpServiceBuilder};
use actix_server::ServerBuilder;
use actix_service::map_config;
use actix_web::{dev::AppConfig, guard, web, App, HttpResponse, Responder};
use anyhow::{Context, Result};
use hmac::Hmac;
use sha2::Sha512;
use std::collections::HashSet;
use std::path::PathBuf;
use std::sync::RwLock;
use tracing::info;

async fn index() -> actix_web::Result<NamedFile> {
    let path = PathBuf::from(r"app/index.html");
    Ok(NamedFile::open(path)?)
}

#[derive(thiserror::Error, Debug)]
pub enum TcpError {
    #[error("`{0}`")]
    DomainError(#[from] DomainError),
    #[error("Bad request: `{0}`")]
    BadRequest(String),
    #[error("Internal server error: `{0}`")]
    InternalServerError(String),
    #[error("Not found: `{0}`")]
    NotFoundError(String),
    #[error("Unauthorized: `{0}`")]
    UnauthorizedError(String),
}

pub type TcpResult<T> = std::result::Result<T, TcpError>;

pub(crate) fn error_to_http_response(error: TcpError) -> HttpResponse {
    match error {
        TcpError::DomainError(ref de) => match de {
            DomainError::AuthenticationError(_) | DomainError::AuthenticationProtocolError(_) => {
                HttpResponse::Unauthorized()
            }
            DomainError::DatabaseError(_)
            | DomainError::InternalError(_)
            | DomainError::UnknownCryptoError(_) => HttpResponse::InternalServerError(),
            DomainError::Base64DecodeError(_)
            | DomainError::BinarySerializationError(_)
            | DomainError::EntityNotFound(_) => HttpResponse::BadRequest(),
        },
        TcpError::BadRequest(_) => HttpResponse::BadRequest(),
        TcpError::NotFoundError(_) => HttpResponse::NotFound(),
        TcpError::InternalServerError(_) => HttpResponse::InternalServerError(),
        TcpError::UnauthorizedError(_) => HttpResponse::Unauthorized(),
    }
    .body(error.to_string())
}

async fn wasm_handler() -> actix_web::Result<impl Responder> {
    Ok(actix_files::NamedFile::open_async("./app/pkg/lldap_app_bg.wasm").await?)
}

async fn wasm_handler_compressed() -> actix_web::Result<impl Responder> {
    Ok(
        actix_files::NamedFile::open_async("./app/pkg/lldap_app_bg.wasm.gz")
            .await?
            .customize()
            .insert_header(header::ContentEncoding::Gzip)
            .insert_header((header::CONTENT_TYPE, "application/wasm")),
    )
}

fn http_config<Backend>(
    cfg: &mut web::ServiceConfig,
    backend_handler: Backend,
    jwt_secret: secstr::SecUtf8,
    jwt_blacklist: HashSet<u64>,
    server_url: String,
    mail_options: MailOptions,
) where
    Backend: TcpBackendHandler + BackendHandler + LoginHandler + OpaqueHandler + Clone + 'static,
{
    let enable_password_reset = mail_options.enable_password_reset;
    cfg.app_data(web::Data::new(AppState::<Backend> {
        backend_handler: AccessControlledBackendHandler::new(backend_handler),
        jwt_key: hmac::Mac::new_from_slice(jwt_secret.unsecure().as_bytes()).unwrap(),
        jwt_blacklist: RwLock::new(jwt_blacklist),
        server_url,
        mail_options,
    }))
    .route(
        "/health",
        web::get().to(|| async { HttpResponse::Ok().finish() }),
    )
    .service(
        web::scope("/auth")
            .configure(|cfg| auth_service::configure_server::<Backend>(cfg, enable_password_reset)),
    )
    // API endpoint.
    .service(
        web::scope("/api")
            .wrap(auth_service::CookieToHeaderTranslatorFactory)
            .configure(super::graphql::api::configure_endpoint::<Backend>),
    )
    .service(
        web::resource("/pkg/lldap_app_bg.wasm.gz").route(web::route().to(wasm_handler_compressed)),
    )
    .service(web::resource("/pkg/lldap_app_bg.wasm").route(web::route().to(wasm_handler)))
    // Serve the /pkg path with the compiled WASM app.
    .service(Files::new("/pkg", "./app/pkg"))
    // Serve static files
    .service(Files::new("/static", "./app/static"))
    // Serve static fonts
    .service(Files::new("/static/fonts", "./app/static/fonts"))
    // Default to serve index.html for unknown routes, to support routing.
    .default_service(web::route().guard(guard::Get()).to(index));
}

pub(crate) struct AppState<Backend> {
    pub backend_handler: AccessControlledBackendHandler<Backend>,
    pub jwt_key: Hmac<Sha512>,
    pub jwt_blacklist: RwLock<HashSet<u64>>,
    pub server_url: String,
    pub mail_options: MailOptions,
}

impl<Backend: BackendHandler> AppState<Backend> {
    pub fn get_readonly_handler(&self) -> &impl ReadonlyBackendHandler {
        self.backend_handler.unsafe_get_handler()
    }
}
impl<Backend: TcpBackendHandler> AppState<Backend> {
    pub fn get_tcp_handler(&self) -> &impl TcpBackendHandler {
        self.backend_handler.unsafe_get_handler()
    }
}
impl<Backend: OpaqueHandler> AppState<Backend> {
    pub fn get_opaque_handler(&self) -> &impl OpaqueHandler {
        self.backend_handler.unsafe_get_handler()
    }
}
impl<Backend: LoginHandler> AppState<Backend> {
    pub fn get_login_handler(&self) -> &impl LoginHandler {
        self.backend_handler.unsafe_get_handler()
    }
}

pub async fn build_tcp_server<Backend>(
    config: &Configuration,
    backend_handler: Backend,
    server_builder: ServerBuilder,
) -> Result<ServerBuilder>
where
    Backend: TcpBackendHandler + BackendHandler + LoginHandler + OpaqueHandler + Clone + 'static,
{
    let jwt_secret = config.jwt_secret.clone();
    let jwt_blacklist = backend_handler
        .get_jwt_blacklist()
        .await
        .context("while getting the jwt blacklist")?;
    let server_url = config.http_url.clone();
    let mail_options = config.smtp_options.clone();
    let verbose = config.verbose;
    info!("Starting the API/web server on port {}", config.http_port);
    server_builder
        .bind(
            "http",
            (config.http_host.clone(), config.http_port),
            move || {
                let backend_handler = backend_handler.clone();
                let jwt_secret = jwt_secret.clone();
                let jwt_blacklist = jwt_blacklist.clone();
                let server_url = server_url.clone();
                let mail_options = mail_options.clone();
                HttpServiceBuilder::default()
                    .finish(map_config(
                        App::new()
                            .wrap(actix_web::middleware::Condition::new(
                                verbose,
                                tracing_actix_web::TracingLogger::<CustomRootSpanBuilder>::new(),
                            ))
                            .configure(move |cfg| {
                                http_config(
                                    cfg,
                                    backend_handler,
                                    jwt_secret,
                                    jwt_blacklist,
                                    server_url,
                                    mail_options,
                                )
                            }),
                        |_| AppConfig::default(),
                    ))
                    .tcp()
            },
        )
        .with_context(|| {
            format!(
                "While bringing up the TCP server with port {}",
                config.http_port
            )
        })
}
