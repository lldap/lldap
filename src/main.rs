#![forbid(unsafe_code)]
use crate::domain::sql_tables::PoolOptions;
use crate::infra::configuration::Configuration;
use anyhow::Result;
use futures_util::TryFutureExt;
use log::*;

mod domain;
mod infra;

async fn run_server(config: Configuration) -> Result<()> {
    let sql_pool = PoolOptions::new()
        .max_connections(5)
        .connect(&config.database_url)
        .await?;
    domain::sql_tables::init_table(&sql_pool).await?;
    let backend_handler = domain::handler::SqlBackendHandler::new(config.clone(), sql_pool.clone());
    let server_builder = infra::ldap_server::build_ldap_server(
        &config,
        backend_handler.clone(),
        actix_server::Server::build(),
    )?;
    let server_builder =
        infra::tcp_server::build_tcp_server(&config, backend_handler, server_builder)?;
    server_builder.workers(1).run().await?;
    Ok(())
}

fn main() -> Result<()> {
    let cli_opts = infra::cli::init();
    let config = infra::configuration::init(cli_opts.clone())?;
    infra::logging::init(config.clone())?;

    info!("Starting LLDAP....");

    debug!("CLI: {:#?}", cli_opts);
    debug!("Configuration: {:#?}", config);

    actix::run(
        run_server(config).unwrap_or_else(|e| error!("Could not bring up the servers: {:?}", e)),
    )?;

    info!("End.");
    Ok(())
}
