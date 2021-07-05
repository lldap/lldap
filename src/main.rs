#![forbid(unsafe_code)]
#![allow(clippy::nonstandard_macro_braces)]

use crate::{
    domain::{
        handler::BackendHandler, sql_backend_handler::SqlBackendHandler,
        sql_opaque_handler::register_password, sql_tables::PoolOptions,
    },
    infra::{configuration::Configuration, db_cleaner::Scheduler},
};
use actix::Actor;
use anyhow::{anyhow, Result};
use futures_util::TryFutureExt;
use log::*;

mod domain;
mod infra;

async fn create_admin_user(handler: &SqlBackendHandler, config: &Configuration) -> Result<()> {
    handler
        .create_user(lldap_model::CreateUserRequest {
            user_id: config.ldap_user_dn.clone(),
            ..Default::default()
        })
        .and_then(|_| register_password(handler, &config.ldap_user_dn, &config.ldap_user_pass))
        .await
        .map_err(|e| anyhow!("Error creating admin user: {}", e))?;
    let admin_group_id = handler
        .create_group(lldap_model::CreateGroupRequest {
            display_name: "lldap_admin".to_string(),
        })
        .await
        .map_err(|e| anyhow!("Error creating admin group: {}", e))?;
    handler
        .add_user_to_group(lldap_model::AddUserToGroupRequest {
            user_id: config.ldap_user_dn.clone(),
            group_id: admin_group_id,
        })
        .await
        .map_err(|e| anyhow!("Error adding admin user to group: {}", e))
}

async fn run_server(config: Configuration) -> Result<()> {
    let sql_pool = PoolOptions::new()
        .max_connections(5)
        .connect(&config.database_url)
        .await?;
    domain::sql_tables::init_table(&sql_pool).await?;
    let backend_handler = SqlBackendHandler::new(config.clone(), sql_pool.clone());
    create_admin_user(&backend_handler, &config)
        .await
        .unwrap_or_else(|e| warn!("Error setting up admin login/account: {}", e));
    let server_builder = infra::ldap_server::build_ldap_server(
        &config,
        backend_handler.clone(),
        actix_server::Server::build(),
    )?;
    infra::jwt_sql_tables::init_table(&sql_pool).await?;
    let server_builder =
        infra::tcp_server::build_tcp_server(&config, backend_handler, server_builder).await?;
    // Run every hour.
    let scheduler = Scheduler::new("0 0 * * * * *", sql_pool);
    scheduler.start();
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
