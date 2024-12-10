use crate::infra::configuration::Configuration;
use actix_web::{
    dev::{ServiceRequest, ServiceResponse},
    Error,
};
use std::env;
use tracing::{debug, error, Span};
use tracing_actix_web::RootSpanBuilder;
use tracing_subscriber::{filter::EnvFilter, layer::SubscriberExt, util::SubscriberInitExt};

/// We will define a custom root span builder to capture additional fields, specific
/// to our application, on top of the ones provided by `DefaultRootSpanBuilder` out of the box.
pub struct CustomRootSpanBuilder;

impl RootSpanBuilder for CustomRootSpanBuilder {
    fn on_request_start(request: &ServiceRequest) -> Span {
        tracing::debug_span!(
            "HTTP request",
            method = request.method().to_string(),
            uri = request.uri().to_string()
        )
    }

    fn on_request_end<B>(_: Span, outcome: &Result<ServiceResponse<B>, Error>) {
        match &outcome {
            Ok(response) => {
                if let Some(error) = response.response().error() {
                    error!(?error);
                } else {
                    debug!(status_code = &response.response().status().as_u16());
                }
            }
            Err(error) => error!(?error),
        };
    }
}

pub fn init(config: &Configuration) -> anyhow::Result<()> {
    let env_filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| {
        EnvFilter::new(if config.verbose {
            "sqlx=warn,reqwest=warn,debug"
        } else {
            "sqlx=warn,reqwest=warn,info"
        })
    });
    let registry = tracing_subscriber::registry()
        .with(env_filter)
        .with(tracing_forest::ForestLayer::default());
    if env::var("LLDAP_RAW_LOG").is_ok() {
        registry.with(tracing_subscriber::fmt::layer()).init();
    } else {
        registry.init();
    }
    Ok(())
}

#[cfg(test)]
pub fn init_for_tests() {
    if let Err(e) = tracing_subscriber::FmtSubscriber::builder()
        .with_max_level(tracing::Level::DEBUG)
        .with_test_writer()
        .try_init()
    {
        log::warn!("Could not set up test logging: {:#}", e);
    }
}
