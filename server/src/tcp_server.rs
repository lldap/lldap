use crate::{
    auth_service,
    configuration::{Configuration, MailOptions},
    logging::CustomRootSpanBuilder,
    tcp_backend_handler::*,
};
use actix_files::Files;
use actix_http::{HttpServiceBuilder, header};
use actix_multipart::Multipart;
use actix_server::ServerBuilder;
use actix_service::map_config;
use actix_web::FromRequest;
use actix_web::{App, HttpResponse, Responder, dev::AppConfig, guard, web};
use actix_web_httpauth::extractors::bearer::BearerAuth;
use anyhow::{Context, Result};
use futures_util::StreamExt;
use hmac::Hmac;
use lldap_access_control::{AccessControlledBackendHandler, ReadonlyBackendHandler};
use lldap_domain_handlers::handler::{BackendHandler, LoginHandler};
use lldap_domain_model::error::DomainError;
use lldap_frontend_options::BrandingOptions;
use lldap_opaque_handler::OpaqueHandler;
use sha2::Sha512;
use std::collections::HashSet;
use std::path::PathBuf;
use std::sync::RwLock;
use tracing::{info, warn};

async fn index<Backend>(data: web::Data<AppState<Backend>>) -> actix_web::Result<impl Responder> {
    let mut file = std::fs::read_to_string(data.assets_path.join("index.html"))?;

    if data.server_url.path() != "/" {
        file = file.replace(
            "<base href=\"/\">",
            format!("<base href=\"{}/\">", data.server_url.path()).as_str(),
        );
    }

    Ok(file
        .customize()
        .insert_header((header::CONTENT_TYPE, "text/html; charset=utf-8")))
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
            | DomainError::DatabaseTransactionError(_)
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

async fn main_js_handler<Backend>(
    data: web::Data<AppState<Backend>>,
) -> actix_web::Result<impl Responder> {
    let mut file = std::fs::read_to_string(data.assets_path.join("static/main.js"))?;

    if data.server_url.path() != "/" {
        file = file.replace("/pkg/", format!("{}/pkg/", data.server_url.path()).as_str());
    }

    Ok(file
        .customize()
        .insert_header((header::CONTENT_TYPE, "text/javascript")))
}

async fn wasm_handler<Backend>(
    data: web::Data<AppState<Backend>>,
) -> actix_web::Result<impl Responder> {
    Ok(actix_files::NamedFile::open_async(data.assets_path.join("pkg/lldap_app_bg.wasm")).await?)
}

async fn wasm_handler_compressed<Backend>(
    data: web::Data<AppState<Backend>>,
) -> actix_web::Result<impl Responder> {
    Ok(
        actix_files::NamedFile::open_async(data.assets_path.join("pkg/lldap_app_bg.wasm.gz"))
            .await?
            .customize()
            .insert_header(header::ContentEncoding::Gzip)
            .insert_header((header::CONTENT_TYPE, "application/wasm")),
    )
}

async fn get_settings<Backend>(data: web::Data<AppState<Backend>>) -> HttpResponse {
    let branding_guard = data
        .branding
        .read()
        .expect("The branding RwLock should never be poisoned");
    HttpResponse::Ok().json(lldap_frontend_options::Options {
        password_reset_enabled: data.mail_options.enable_password_reset,
        branding: branding_guard.clone(),
    })
}

/// The maximum file size for an uploaded logo, in bytes (1 MB).
/// Kept small because the logo is served inline on every page.
const MAXIMUM_LOGO_FILE_SIZE_IN_BYTES: usize = 1_048_576;

/// Allowed MIME types for logo uploads.
const PERMITTED_LOGO_CONTENT_TYPES: &[&str] =
    &["image/png", "image/jpeg", "image/webp", "image/svg+xml"];

/// Checks admin group membership from a validated JWT token.
async fn verify_admin_access<Backend>(
    data: &web::Data<AppState<Backend>>,
    token: &str,
) -> Result<(), HttpResponse>
where
    Backend: BackendHandler + 'static,
{
    let validation_result = auth_service::check_if_token_is_valid(data, token)
        .map_err(|_| HttpResponse::Unauthorized().body("Invalid or expired JWT"))?;
    if !validation_result.is_admin() {
        return Err(HttpResponse::Forbidden()
            .body("Only members of the lldap_admin group can change branding settings"));
    }
    Ok(())
}

async fn put_settings<Backend>(
    request: actix_web::HttpRequest,
    payload: actix_web::web::Payload,
    data: web::Data<AppState<Backend>>,
) -> HttpResponse
where
    Backend: TcpBackendHandler + BackendHandler + 'static,
{
    let mut inner_payload = payload.into_inner();
    // Extract and validate the Bearer token.
    let bearer = match BearerAuth::from_request(&request, &mut inner_payload).await {
        Ok(bearer) => bearer,
        Err(_) => {
            return HttpResponse::Unauthorized().body("Missing or invalid Authorization header");
        }
    };
    if let Err(response) = verify_admin_access::<Backend>(&data, bearer.token()).await {
        return response;
    }

    let branding_update =
        match web::Json::<BrandingOptions>::from_request(&request, &mut inner_payload).await {
            Ok(json) => json.into_inner(),
            Err(error) => {
                return HttpResponse::BadRequest().body(format!("Invalid JSON body: {error:#?}"));
            }
        };

    let tcp_handler = data.get_tcp_handler();
    if let Err(error) = tcp_handler.set_branding_settings(&branding_update).await {
        return HttpResponse::InternalServerError().body(format!("Database error: {error:#?}"));
    }

    let mut branding_guard = data
        .branding
        .write()
        .expect("The branding RwLock should never be poisoned");
    *branding_guard = branding_update.clone();

    HttpResponse::Ok().json(lldap_frontend_options::Options {
        password_reset_enabled: data.mail_options.enable_password_reset,
        branding: branding_update,
    })
}

async fn put_settings_logo<Backend>(
    request: actix_web::HttpRequest,
    payload: actix_web::web::Payload,
    data: web::Data<AppState<Backend>>,
) -> HttpResponse
where
    Backend: TcpBackendHandler + BackendHandler + 'static,
{
    let mut inner_payload = payload.into_inner();
    // Extract and validate the Bearer token.
    let bearer = match BearerAuth::from_request(&request, &mut inner_payload).await {
        Ok(bearer) => bearer,
        Err(_) => {
            return HttpResponse::Unauthorized().body("Missing or invalid Authorization header");
        }
    };
    if let Err(response) = verify_admin_access::<Backend>(&data, bearer.token()).await {
        return response;
    }

    let mut multipart_stream = Multipart::new(&request.headers(), inner_payload);
    let mut field = match multipart_stream.next().await {
        Some(Ok(field)) => field,
        Some(Err(error)) => {
            return HttpResponse::BadRequest()
                .body(format!("Error reading multipart field: {error:#?}"));
        }
        None => {
            return HttpResponse::BadRequest()
                .body("No file was provided in the request. Include a field named 'logo' with the image file.");
        }
    };

    let content_type = field
        .content_type()
        .map(|mime| mime.to_string())
        .unwrap_or_default();

    if !PERMITTED_LOGO_CONTENT_TYPES.contains(&content_type.as_str()) {
        return HttpResponse::BadRequest().body(format!(
            "Logo file type '{content_type}' is not supported. \
             Allowed types: {}",
            PERMITTED_LOGO_CONTENT_TYPES.join(", "),
        ));
    }

    let mut file_bytes = Vec::new();
    while let Some(chunk_result) = field.next().await {
        let chunk = match chunk_result {
            Ok(bytes) => bytes,
            Err(error) => {
                return HttpResponse::BadRequest()
                    .body(format!("Error reading file data: {error:#?}"));
            }
        };
        if file_bytes.len() + chunk.len() > MAXIMUM_LOGO_FILE_SIZE_IN_BYTES {
            return HttpResponse::BadRequest().body(format!(
                "Logo file size exceeds the maximum allowed size of \
                 {MAXIMUM_LOGO_FILE_SIZE_IN_BYTES} bytes. Please resize the \
                 image and try again.",
            ));
        }
        file_bytes.extend_from_slice(&chunk);
    }

    let branding_directory = data.assets_path.join("branding");
    if std::fs::create_dir_all(&branding_directory).is_err() {
        return HttpResponse::InternalServerError()
            .body("Could not create the branding directory on disk.");
    }
    let logo_file_path = branding_directory.join("logo");
    if let Err(error) = std::fs::write(&logo_file_path, &file_bytes) {
        return HttpResponse::InternalServerError()
            .body(format!("Could not save the logo file to disk: {error:#?}"));
    }

    let mut branding_guard = data
        .branding
        .write()
        .expect("The branding RwLock should never be poisoned");
    branding_guard.logo_file_has_been_uploaded = true;
    let updated_branding = branding_guard.clone();
    drop(branding_guard);

    let tcp_handler = data.get_tcp_handler();
    if let Err(error) = tcp_handler.set_branding_settings(&updated_branding).await {
        return HttpResponse::InternalServerError().body(format!("Database error: {error:#?}"));
    }

    HttpResponse::Ok().json(updated_branding)
}

async fn delete_settings_logo<Backend>(
    request: actix_web::HttpRequest,
    payload: actix_web::web::Payload,
    data: web::Data<AppState<Backend>>,
) -> HttpResponse
where
    Backend: TcpBackendHandler + BackendHandler + 'static,
{
    let mut inner_payload = payload.into_inner();
    // Extract and validate the Bearer token.
    let bearer = match BearerAuth::from_request(&request, &mut inner_payload).await {
        Ok(bearer) => bearer,
        Err(_) => {
            return HttpResponse::Unauthorized().body("Missing or invalid Authorization header");
        }
    };
    if let Err(response) = verify_admin_access::<Backend>(&data, bearer.token()).await {
        return response;
    }

    let logo_file_path = data.assets_path.join("branding").join("logo");
    let _ = std::fs::remove_file(&logo_file_path);

    let mut branding_guard = data
        .branding
        .write()
        .expect("The branding RwLock should never be poisoned");
    branding_guard.logo_file_has_been_uploaded = false;
    let updated_branding = branding_guard.clone();
    drop(branding_guard);

    let tcp_handler = data.get_tcp_handler();
    if let Err(error) = tcp_handler.set_branding_settings(&updated_branding).await {
        return HttpResponse::InternalServerError().body(format!("Database error: {error:#?}"));
    }

    HttpResponse::Ok().json(updated_branding)
}

async fn get_branding_logo<Backend>(
    data: web::Data<AppState<Backend>>,
) -> actix_web::Result<impl Responder> {
    let logo_file_path = data.assets_path.join("branding").join("logo");
    Ok(actix_files::NamedFile::open_async(&logo_file_path).await?)
}

#[allow(clippy::too_many_arguments)]
fn http_config<Backend>(
    cfg: &mut web::ServiceConfig,
    backend_handler: Backend,
    jwt_secret: secstr::SecUtf8,
    jwt_blacklist: HashSet<u64>,
    server_url: url::Url,
    assets_path: PathBuf,
    mail_options: MailOptions,
    startup_branding: BrandingOptions,
) where
    Backend: TcpBackendHandler + BackendHandler + LoginHandler + OpaqueHandler + Clone + 'static,
{
    let enable_password_reset = mail_options.enable_password_reset;
    cfg.app_data(web::Data::new(AppState::<Backend> {
        backend_handler: AccessControlledBackendHandler::new(backend_handler),
        jwt_key: hmac::Mac::new_from_slice(jwt_secret.unsecure().as_bytes()).unwrap(),
        jwt_blacklist: RwLock::new(jwt_blacklist),
        server_url,
        assets_path: assets_path.clone(),
        mail_options,
        branding: RwLock::new(startup_branding),
    }))
    .route(
        "/health",
        web::get().to(async || HttpResponse::Ok().finish()),
    )
    .service(
        web::scope("/settings")
            .wrap(auth_service::CookieToHeaderTranslatorFactory)
            .route("", web::get().to(get_settings::<Backend>))
            .route("", web::put().to(put_settings::<Backend>))
            .route("/logo", web::put().to(put_settings_logo::<Backend>))
            .route("/logo", web::delete().to(delete_settings_logo::<Backend>)),
    )
    .service(
        web::scope("/auth")
            .configure(|cfg| auth_service::configure_server::<Backend>(cfg, enable_password_reset)),
    )
    // API endpoint.
    .service(
        web::scope("/api")
            .wrap(auth_service::CookieToHeaderTranslatorFactory)
            .configure(crate::graphql_server::configure_endpoint::<Backend>),
    )
    .service(
        web::resource("/pkg/lldap_app_bg.wasm.gz")
            .route(web::route().to(wasm_handler_compressed::<Backend>)),
    )
    .service(
        web::resource("/pkg/lldap_app_bg.wasm").route(web::route().to(wasm_handler::<Backend>)),
    )
    .service(web::resource("/static/main.js").route(web::route().to(main_js_handler::<Backend>)))
    // Serve uploaded branding assets (logo file).
    .route(
        "/branding/logo",
        web::get().to(get_branding_logo::<Backend>),
    )
    // Serve the /pkg path with the compiled WASM app.
    .service(Files::new("/pkg", assets_path.join("pkg")))
    // Serve static files
    .service(Files::new("/static", assets_path.join("static")))
    // Serve static fonts
    .service(Files::new(
        "/static/fonts",
        assets_path.join("static/fonts"),
    ))
    // Default to serve index.html for unknown routes, to support routing.
    .default_service(web::route().guard(guard::Get()).to(index::<Backend>));
}

pub(crate) struct AppState<Backend> {
    pub backend_handler: AccessControlledBackendHandler<Backend>,
    pub jwt_key: Hmac<Sha512>,
    pub jwt_blacklist: RwLock<HashSet<u64>>,
    pub server_url: url::Url,
    pub assets_path: PathBuf,
    pub mail_options: MailOptions,
    /// Branding settings served to the frontend via GET /settings and
    /// updated at runtime via PUT /settings (admin-only). Wrapped in a
    /// RwLock so the PUT handler can update it without restarting.
    pub branding: RwLock<BrandingOptions>,
}

impl<Backend: BackendHandler> AppState<Backend> {
    pub fn get_readonly_handler(&self) -> &(impl ReadonlyBackendHandler + use<Backend>) {
        self.backend_handler.unsafe_get_handler()
    }
}
impl<Backend: TcpBackendHandler> AppState<Backend> {
    pub fn get_tcp_handler(&self) -> &(impl TcpBackendHandler + use<Backend>) {
        self.backend_handler.unsafe_get_handler()
    }
}
impl<Backend: OpaqueHandler> AppState<Backend> {
    pub fn get_opaque_handler(&self) -> &(impl OpaqueHandler + use<Backend>) {
        self.backend_handler.unsafe_get_handler()
    }
}
impl<Backend: LoginHandler> AppState<Backend> {
    pub fn get_login_handler(&self) -> &(impl LoginHandler + use<Backend>) {
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
    let jwt_secret = config.jwt_secret.clone().unwrap();
    let jwt_blacklist = backend_handler
        .get_jwt_blacklist()
        .await
        .context("while getting the jwt blacklist")?;
    let server_url = config.http_url.0.clone();
    let assets_path = config.assets_path.clone();
    let mail_options = config.smtp_options.clone();
    let verbose = config.verbose;

    // Load branding from the database at startup and store it in a
    // RwLock so the PUT /settings endpoint can update it live.
    let branding_from_database = backend_handler
        .get_branding_settings()
        .await
        .unwrap_or_default()
        .unwrap_or_default();
    let startup_branding = branding_from_database;

    if !assets_path.join("index.html").exists() {
        warn!(
            "Cannot find {}, please ensure that assets_path is set correctly and that the front-end files exist.",
            assets_path.to_string_lossy()
        )
    }
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
                let assets_path = assets_path.clone();
                let mail_options = mail_options.clone();
                let startup_branding = startup_branding.clone();
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
                                    assets_path,
                                    mail_options,
                                    startup_branding,
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
