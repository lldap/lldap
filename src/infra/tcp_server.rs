use crate::domain::handler::*;
use crate::infra::configuration::Configuration;
use actix_http::HttpServiceBuilder;
use actix_server::ServerBuilder;
use actix_service::map_config;
use actix_web::dev::AppConfig;
use actix_web::App;
use anyhow::{Context, Result};

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
                .finish(map_config(App::new(), |_| AppConfig::default()))
                .tcp()
        })
        .with_context(|| {
            format!(
                "While bringing up the TCP server with port {}",
                config.http_port
            )
        })
}
