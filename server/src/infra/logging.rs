use crate::infra::configuration::Configuration;
use tracing_subscriber::prelude::*;

pub fn init(config: &Configuration) -> anyhow::Result<()> {
    let max_log_level = log_level_from_config(config);
    let sqlx_max_log_level = sqlx_log_level_from_config(config);
    let filter = tracing_subscriber::filter::Targets::new()
        .with_target("lldap", max_log_level)
        .with_target("sqlx", sqlx_max_log_level);
    tracing_subscriber::registry()
        .with(tracing_subscriber::fmt::layer().with_filter(filter))
        .init();
    Ok(())
}

fn log_level_from_config(config: &Configuration) -> tracing::Level {
    if config.verbose {
        tracing::Level::DEBUG
    } else {
        tracing::Level::INFO
    }
}

fn sqlx_log_level_from_config(config: &Configuration) -> tracing::Level {
    if config.verbose {
        tracing::Level::INFO
    } else {
        tracing::Level::WARN
    }
}
