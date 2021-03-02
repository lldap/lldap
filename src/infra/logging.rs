use crate::infra::configuration::Configuration;
use anyhow::Context;
use tracing::subscriber::set_global_default;
use tracing_log::LogTracer;

pub fn init(_config: Configuration) -> anyhow::Result<()> {
    // TODO: use config.log_level_verbose to set level

    let subscriber = tracing_subscriber::fmt()
        .with_timer(tracing_subscriber::fmt::time::time())
        .with_target(false)
        .with_level(true)
        .finish();
    LogTracer::init().context("Failed to set logger")?;
    set_global_default(subscriber).context("Failed to set subscriber")?;
    Ok(())
}
