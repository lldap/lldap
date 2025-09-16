use crate::configuration::Configuration;
use actix_web::{
    Error,
    dev::{ServiceRequest, ServiceResponse},
};
use std::env;
use tracing::{Span, debug, error};
use tracing_actix_web::RootSpanBuilder;
use tracing_subscriber::{
    filter::EnvFilter, fmt::time::ChronoLocal, layer::SubscriberExt, util::SubscriberInitExt,
};

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
    let registry = tracing_subscriber::registry().with(env_filter);

    let raw_logs = env::var("LLDAP_RAW_LOG").is_ok();
    let local_tz = env::var("LLDAP_LOCAL_TZ_LOG").is_ok();

    if local_tz {
        registry
            .with(tracing_subscriber::fmt::layer().with_timer(ChronoLocal::rfc_3339()))
            .init();
    } else if raw_logs {
        registry.with(tracing_subscriber::fmt::layer()).init();
    } else {
        registry.with(tracing_forest::ForestLayer::default()).init();
    }

    Ok(())
}
