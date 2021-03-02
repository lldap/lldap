use crate::infra::configuration::Configuration;
use anyhow::Context;
use tracing::subscriber::set_global_default;
use tracing_log::LogTracer;

pub fn init(config: Configuration) -> anyhow::Result<()> {
    let max_log_level = log_level_from_config(config);
    let subscriber = tracing_subscriber::fmt()
        .with_timer(tracing_subscriber::fmt::time::time())
        .with_target(false)
        .with_level(true)
        .with_max_level(max_log_level)
        .finish();
    LogTracer::init().context("Failed to set logger")?;
    set_global_default(subscriber).context("Failed to set subscriber")?;
    Ok(())
}

fn log_level_from_config(config: Configuration) -> tracing::Level {
    if config.verbose {
        tracing::Level::DEBUG
    } else {
        tracing::Level::INFO
    }
}
