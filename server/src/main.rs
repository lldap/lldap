#![forbid(unsafe_code)]
#![allow(clippy::nonstandard_macro_braces)]

use crate::{
    domain::{
        handler::{BackendHandler, CreateUserRequest},
        sql_backend_handler::SqlBackendHandler,
        sql_opaque_handler::register_password,
        sql_tables::PoolOptions,
    },
    infra::{cli::*, configuration::Configuration, db_cleaner::Scheduler},
};
use actix::Actor;
use anyhow::{anyhow, Context, Result};
use futures_util::TryFutureExt;
use log::*;

mod domain;
mod infra;

async fn create_admin_user(handler: &SqlBackendHandler, config: &Configuration) -> Result<()> {
    assert!(
        config.ldap_user_pass.len() >= 8,
        "Minimum password length is 8 characters, got {} characters",
        config.ldap_user_pass.len()
    );
    handler
        .create_user(CreateUserRequest {
            user_id: config.ldap_user_dn.clone(),
            display_name: Some("Administrator".to_string()),
            ..Default::default()
        })
        .and_then(|_| register_password(handler, &config.ldap_user_dn, &config.ldap_user_pass))
        .await
        .context("Error creating admin user")?;
    let admin_group_id = handler
        .create_group("lldap_admin")
        .await
        .context("Error creating admin group")?;
    handler
        .add_user_to_group(&config.ldap_user_dn, admin_group_id)
        .await
        .context("Error adding admin user to group")
}

async fn run_server(config: Configuration) -> Result<()> {
    let sql_pool = PoolOptions::new()
        .max_connections(5)
        .connect(&config.database_url)
        .await
        .context("while connecting to the DB")?;
    domain::sql_tables::init_table(&sql_pool)
        .await
        .context("while creating the tables")?;
    let backend_handler = SqlBackendHandler::new(config.clone(), sql_pool.clone());
    if let Err(e) = backend_handler.get_user_details(&config.ldap_user_dn).await {
        warn!("Could not get admin user, trying to create it: {:#}", e);
        create_admin_user(&backend_handler, &config)
            .await
            .map_err(|e| anyhow!("Error setting up admin login/account: {:#}", e))
            .context("while creating the admin user")?;
    }
    let server_builder = infra::ldap_server::build_ldap_server(
        &config,
        backend_handler.clone(),
        actix_server::Server::build(),
    )
    .context("while binding the LDAP server")?;
    infra::jwt_sql_tables::init_table(&sql_pool).await?;
    let server_builder =
        infra::tcp_server::build_tcp_server(&config, backend_handler, server_builder)
            .await
            .context("while binding the TCP server")?;
    // Run every hour.
    let scheduler = Scheduler::new("0 0 * * * * *", sql_pool);
    scheduler.start();
    server_builder
        .workers(1)
        .run()
        .await
        .context("while starting the server")?;
    Ok(())
}

fn run_server_command(opts: RunOpts) -> Result<()> {
    let config = infra::configuration::init(opts.clone())?;
    infra::logging::init(config.clone())?;

    info!("Starting LLDAP....");

    debug!("CLI: {:#?}", opts);
    debug!("Configuration: {:#?}", config);

    actix::run(
        run_server(config).unwrap_or_else(|e| error!("Could not bring up the servers: {:#}", e)),
    )?;

    info!("End.");
    Ok(())
}

fn main() -> Result<()> {
    let cli_opts = infra::cli::init();
    match cli_opts.command {
        Command::ExportGraphQLSchema(opts) => infra::graphql::api::export_schema(opts),
        Command::Run(opts) => run_server_command(opts),
    }
}
