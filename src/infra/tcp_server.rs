use crate::{
    domain::{
        error::DomainError,
        handler::{BackendHandler, LoginHandler},
        opaque_handler::OpaqueHandler,
    },
    infra::{auth_service, configuration::Configuration, tcp_api, tcp_backend_handler::*},
};
use actix_files::{Files, NamedFile};
use actix_http::HttpServiceBuilder;
use actix_server::ServerBuilder;
use actix_service::map_config;
use actix_web::{dev::AppConfig, web, App, HttpRequest, HttpResponse};
use actix_web_httpauth::middleware::HttpAuthentication;
use anyhow::{Context, Result};
use hmac::{Hmac, NewMac};
use sha2::Sha512;
use std::collections::HashSet;
use std::path::PathBuf;
use std::sync::RwLock;

async fn index(req: HttpRequest) -> actix_web::Result<NamedFile> {
    let mut path = PathBuf::new();
    path.push("app");
    let file = req.match_info().query("filename");
    path.push(if file.is_empty() { "index.html" } else { file });
    Ok(NamedFile::open(path)?)
}

pub(crate) fn error_to_http_response(error: DomainError) -> HttpResponse {
    match error {
        DomainError::AuthenticationError(_) | DomainError::AuthenticationProtocolError(_) => {
            HttpResponse::Unauthorized()
        }
        DomainError::DatabaseError(_)
        | DomainError::InternalError(_)
        | DomainError::UnknownCryptoError(_) => HttpResponse::InternalServerError(),
        DomainError::Base64DecodeError(_) | DomainError::BinarySerializationError(_) => {
            HttpResponse::BadRequest()
        }
    }
    .body(error.to_string())
}

fn http_config<Backend>(
    cfg: &mut web::ServiceConfig,
    backend_handler: Backend,
    jwt_secret: String,
    jwt_blacklist: HashSet<u64>,
) where
    Backend: TcpBackendHandler + BackendHandler + LoginHandler + OpaqueHandler + 'static,
{
    cfg.data(AppState::<Backend> {
        backend_handler,
        jwt_key: Hmac::new_varkey(jwt_secret.as_bytes()).unwrap(),
        jwt_blacklist: RwLock::new(jwt_blacklist),
    })
    // Serve index.html and main.js, and default to index.html.
    .route(
        "/{filename:(index\\.html|main\\.js)?}",
        web::get().to(index),
    )
    .service(web::scope("/auth").configure(auth_service::configure_server::<Backend>))
    // API endpoint.
    .service(
        web::scope("/api")
            .wrap(HttpAuthentication::bearer(
                auth_service::token_validator::<Backend>,
            ))
            .wrap(auth_service::CookieToHeaderTranslatorFactory)
            .guard(actix_web::guard::Header("content-type", "application/json"))
            .configure(tcp_api::api_config::<Backend>),
    )
    // Serve the /pkg path with the compiled WASM app.
    .service(Files::new("/pkg", "./app/pkg"))
    // Default to serve index.html for unknown routes, to support routing.
    .service(web::scope("/").route("/.*", web::get().to(index)));
}

pub(crate) struct AppState<Backend> {
    pub backend_handler: Backend,
    pub jwt_key: Hmac<Sha512>,
    pub jwt_blacklist: RwLock<HashSet<u64>>,
}

pub async fn build_tcp_server<Backend>(
    config: &Configuration,
    backend_handler: Backend,
    server_builder: ServerBuilder,
) -> Result<ServerBuilder>
where
    Backend: TcpBackendHandler + BackendHandler + LoginHandler + OpaqueHandler + 'static,
{
    let jwt_secret = config.jwt_secret.clone();
    let jwt_blacklist = backend_handler.get_jwt_blacklist().await?;
    server_builder
        .bind("http", ("0.0.0.0", config.http_port), move || {
            let backend_handler = backend_handler.clone();
            let jwt_secret = jwt_secret.clone();
            let jwt_blacklist = jwt_blacklist.clone();
            HttpServiceBuilder::new()
                .finish(map_config(
                    App::new().configure(move |cfg| {
                        http_config(cfg, backend_handler, jwt_secret, jwt_blacklist)
                    }),
                    |_| AppConfig::default(),
                ))
                .tcp()
        })
        .with_context(|| {
            format!(
                "While bringing up the TCP server with port {}",
                config.http_port
            )
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use actix_web::test::TestRequest;
    use std::path::Path;

    #[actix_rt::test]
    async fn test_index_ok() {
        let req = TestRequest::default().to_http_request();
        let resp = index(req).await.unwrap();
        assert_eq!(resp.path(), Path::new("app/index.html"));
    }

    #[actix_rt::test]
    async fn test_index_main_js() {
        let req = TestRequest::default()
            .param("filename", "main.js")
            .to_http_request();
        let resp = index(req).await.unwrap();
        assert_eq!(resp.path(), Path::new("app/main.js"));
    }
}
