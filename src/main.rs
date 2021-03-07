use crate::infra::configuration::Configuration;
use anyhow::Result;
use futures_util::TryFutureExt;
use log::*;
use sqlx::sqlite::{SqliteConnectOptions, SqlitePoolOptions};
use std::str::FromStr;

mod infra;

async fn run_server(config: Configuration) -> Result<()> {
    let sql_pool = SqlitePoolOptions::new()
        .max_connections(5)
        .connect_with(SqliteConnectOptions::from_str("sqlite://users.db")?.create_if_missing(true))
        .await?;
    let server_builder = infra::ldap_server::build_ldap_server(
        &config,
        sql_pool.clone(),
        actix_server::Server::build(),
    )?;
    let server_builder = infra::tcp_server::build_tcp_server(&config, sql_pool, server_builder)?;
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
