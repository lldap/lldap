use crate::infra::configuration::Configuration;
use actix_web::{
    dev::{ServiceRequest, ServiceResponse},
    Error,
};
use tracing::{error, info, Span};
use tracing_actix_web::{root_span, RootSpanBuilder};
use tracing_subscriber::{filter::EnvFilter, layer::SubscriberExt, util::SubscriberInitExt};

/// We will define a custom root span builder to capture additional fields, specific
/// to our application, on top of the ones provided by `DefaultRootSpanBuilder` out of the box.
pub struct CustomRootSpanBuilder;

impl RootSpanBuilder for CustomRootSpanBuilder {
    fn on_request_start(request: &ServiceRequest) -> Span {
        let span = root_span!(request);
        span.in_scope(|| {
            info!(uri = %request.uri());
        });
        span
    }

    fn on_request_end<B>(_: Span, outcome: &Result<ServiceResponse<B>, Error>) {
        match &outcome {
            Ok(response) => {
                if let Some(error) = response.response().error() {
                    error!(?error);
                } else {
                    info!(status_code = &response.response().status().as_u16());
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
    tracing_subscriber::registry()
        .with(env_filter)
        .with(tracing_forest::ForestLayer::default())
        .init();
    Ok(())
}
