use anyhow::Result;
use log::*;

mod infra;

fn main() -> Result<()> {
    let cli_opts = infra::cli::init();
    let config = infra::configuration::init(cli_opts.clone())?;
    infra::logging::init(config.clone())?;

    info!("Starting LLDAP....");

    debug!("CLI: {:#?}", cli_opts);
    debug!("Configuration: {:#?}", config);

    infra::tcp_server::init(config)?;

    info!("End.");
    Ok(())
}
