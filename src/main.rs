use anyhow::Result;
use log::*;

mod infra;

fn main() -> Result<()> {
    let cli_opts = infra::cli::init();
    let config = infra::configuration::init(cli_opts.clone())?;
    infra::logging::init(config.clone())?;

    info!("Starting....");
    debug!("Config: {:?}", config);
    debug!("CLI: {:?}", cli_opts);
    info!("End.");
    Ok(())
}
