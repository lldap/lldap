use crate::domain::handler::*;
use crate::infra::configuration::Configuration;
use actix_files::{Files, NamedFile};
use actix_http::HttpServiceBuilder;
use actix_server::ServerBuilder;
use actix_service::map_config;
use actix_web::{dev::AppConfig, web, App, HttpRequest, HttpResponse};
use anyhow::{Context, Result};
use std::path::PathBuf;

async fn index(req: HttpRequest) -> actix_web::Result<NamedFile> {
    let mut path = PathBuf::new();
    path.push("app");
    let file = req.match_info().query("filename");
    path.push(if file.is_empty() { "index.html" } else { file });
    Ok(NamedFile::open(path)?)
}

type ApiResult<M> = actix_web::Either<web::Json<M>, HttpResponse>;

async fn user_list_handler(_info: web::Json<ListUsersRequest>) -> ApiResult<Vec<User>> {
    if true {
        ApiResult::Right(HttpResponse::Conflict().finish())
    } else {
        ApiResult::Left(web::Json(Vec::<User>::new()))
    }
}

fn api_config(cfg: &mut web::ServiceConfig) {
    let json_config = web::JsonConfig::default()
        .limit(4096)
        .error_handler(|err, _req| {
            // create custom error response
            actix_web::error::InternalError::from_response(
                err,
                HttpResponse::Conflict().finish().into(),
            )
            .into()
        });
    cfg.service(
        web::resource("/users")
            .app_data(json_config)
            .route(web::post().to(user_list_handler)),
    );
}

pub fn build_tcp_server<Backend>(
    config: &Configuration,
    _backend_handler: Backend,
    server_builder: ServerBuilder,
) -> Result<ServerBuilder>
where
    Backend: BackendHandler + 'static,
{
    server_builder
        .bind("http", ("0.0.0.0", config.http_port), move || {
            HttpServiceBuilder::new()
                .finish(map_config(
                    App::new()
                        // Serve index.html and main.js, and default to index.html.
                        .route(
                            "/{filename:(index\\.html|main\\.js)?}",
                            web::get().to(index),
                        )
                        // API endpoint.
                        .service(web::scope("/api").configure(api_config))
                        // Serve the /pkg path with the compiled WASM app.
                        .service(Files::new("/pkg", "./app/pkg")),
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
