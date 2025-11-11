#![forbid(unsafe_code)]
#![forbid(non_ascii_idents)]
// TODO: Remove next line when it stops warning about async functions.
#![allow(clippy::blocks_in_conditions)]

mod auth_service;
mod cli;
mod configuration;
mod database_string;
mod db_cleaner;
mod graphql_server;
mod healthcheck;
mod jwt_sql_tables;
mod ldap_server;
mod logging;
mod mail;
mod sql_tcp_backend_handler;
mod tcp_backend_handler;
mod tcp_server;

use crate::{
    cli::{Command, RunOpts, TestEmailOpts},
    configuration::{Configuration, compare_private_key_hashes},
    database_string::DatabaseUrl,
    db_cleaner::Scheduler,
};
use actix::Actor;
use actix_server::ServerBuilder;
use anyhow::{Context, Result, anyhow, bail};
use futures_util::TryFutureExt;
use lldap_sql_backend_handler::{
    SqlBackendHandler, register_password,
    sql_tables::{self, get_private_key_info, set_private_key_info},
};
use sea_orm::{Database, DatabaseConnection};
use std::time::Duration;
use tracing::{Instrument, Level, debug, error, info, instrument, span, warn};

use lldap_domain::requests::{CreateGroupRequest, CreateUserRequest};
use lldap_domain_handlers::handler::{
    GroupBackendHandler, GroupListerBackendHandler, GroupRequestFilter, UserBackendHandler,
    UserListerBackendHandler, UserRequestFilter,
};

const ADMIN_PASSWORD_MISSING_ERROR: &str = "The LDAP admin password must be initialized. \
            Either set the `ldap_user_pass` config value or the `LLDAP_LDAP_USER_PASS` environment variable. \
            A minimum of 8 characters is recommended.";

async fn create_admin_user(handler: &SqlBackendHandler, config: &Configuration) -> Result<()> {
    let pass_length = config
        .ldap_user_pass
        .as_ref()
        .expect(ADMIN_PASSWORD_MISSING_ERROR)
        .unsecure()
        .len();
    assert!(
        pass_length >= 8,
        "Minimum password length is 8 characters, got {pass_length} characters"
    );
    handler
        .create_user(CreateUserRequest {
            user_id: config.ldap_user_dn.clone(),
            email: config.ldap_user_email.clone().into(),
            display_name: Some("Administrator".to_string()),
            ..Default::default()
        })
        .and_then(|_| {
            register_password(
                handler,
                config.ldap_user_dn.clone(),
                config.ldap_user_pass.as_ref().unwrap(),
            )
        })
        .await
        .context("Error creating admin user")?;
    let groups = handler
        .list_groups(Some(GroupRequestFilter::DisplayName("lldap_admin".into())))
        .await?;
    assert_eq!(groups.len(), 1);
    handler
        .add_user_to_group(&config.ldap_user_dn, groups[0].id)
        .await
        .context("Error adding admin user to group")
}

async fn ensure_group_exists(handler: &SqlBackendHandler, group_name: &str) -> Result<()> {
    if handler
        .list_groups(Some(GroupRequestFilter::DisplayName(group_name.into())))
        .await?
        .is_empty()
    {
        warn!("Could not find {} group, trying to create it", group_name);
        handler
            .create_group(CreateGroupRequest {
                display_name: group_name.into(),
                ..Default::default()
            })
            .await
            .context(format!("while creating {group_name} group"))?;
    }
    Ok(())
}

async fn setup_sql_tables(database_url: &DatabaseUrl) -> Result<DatabaseConnection> {
    let sql_pool = {
        let num_connections = if database_url.db_type() == "sqlite" {
            1
        } else {
            5
        };
        let mut sql_opt = sea_orm::ConnectOptions::new(database_url.to_string());
        sql_opt
            .max_connections(num_connections)
            .sqlx_logging(true)
            .sqlx_logging_level(log::LevelFilter::Debug);
        Database::connect(sql_opt).await?
    };
    sql_tables::init_table(&sql_pool)
        .await
        .context("while creating base tables")?;
    jwt_sql_tables::init_table(&sql_pool)
        .await
        .context("while creating jwt tables")?;
    Ok(sql_pool)
}

#[instrument(skip_all)]
async fn set_up_server(config: Configuration) -> Result<(ServerBuilder, DatabaseConnection)> {
    info!("Starting LLDAP version {}", env!("CARGO_PKG_VERSION"));

    let sql_pool = setup_sql_tables(&config.database_url).await?;
    let private_key_info = config.get_private_key_info();
    let force_update_private_key = config.force_update_private_key;
    match (
        compare_private_key_hashes(
            get_private_key_info(&sql_pool).await?.as_ref(),
            &private_key_info,
        ),
        force_update_private_key,
    ) {
        (Ok(false), true) => {
            bail!(
                "The private key has not changed, but force_update_private_key/LLDAP_FORCE_UPDATE_PRIVATE_KEY is set to true. Please set force_update_private_key to false and restart the server."
            );
        }
        (Ok(true), _) | (Err(_), true) => {
            set_private_key_info(&sql_pool, private_key_info).await?;
        }
        (Ok(false), false) => {}
        (Err(e), false) => {
            return Err(anyhow!("The private key encoding the passwords has changed since last successful startup. Changing the private key will invalidate all existing passwords. If you want to proceed, restart the server with the CLI arg --force-update-private-key=true or the env variable LLDAP_FORCE_UPDATE_PRIVATE_KEY=true. You probably also want --force-ldap-user-pass-reset / LLDAP_FORCE_LDAP_USER_PASS_RESET=true to reset the admin password to the value in the configuration.").context(e));
        }
    }
    let backend_handler =
        SqlBackendHandler::new(config.get_server_setup().clone(), sql_pool.clone());
    ensure_group_exists(&backend_handler, "lldap_admin").await?;
    ensure_group_exists(&backend_handler, "lldap_password_manager").await?;
    ensure_group_exists(&backend_handler, "lldap_strict_readonly").await?;
    let admin_present = if let Ok(admins) = backend_handler
        .list_users(
            Some(UserRequestFilter::MemberOf("lldap_admin".into())),
            false,
        )
        .await
    {
        !admins.is_empty()
    } else {
        false
    };
    if !admin_present {
        warn!(
            "Could not find an admin user, trying to create the user \"admin\" with the config-provided password"
        );
        create_admin_user(&backend_handler, &config)
            .await
            .map_err(|e| anyhow!("Error setting up admin login/account: {:#}", e))
            .context("while creating the admin user")?;
    } else if config.force_ldap_user_pass_reset.is_positive() {
        let span = if config.force_ldap_user_pass_reset.is_yes() {
            span!(
                Level::WARN,
                "Forcing admin password reset to the config-provided password"
            )
        } else {
            span!(Level::INFO, "Resetting admin password")
        };
        register_password(
            &backend_handler,
            config.ldap_user_dn.clone(),
            config
                .ldap_user_pass
                .as_ref()
                .expect(ADMIN_PASSWORD_MISSING_ERROR),
        )
        .instrument(span)
        .await
        .context(format!(
            "while resetting admin password for {}",
            &config.ldap_user_dn
        ))?;
    }
    if config.force_update_private_key || config.force_ldap_user_pass_reset.is_yes() {
        bail!(
            "Restart the server without --force-update-private-key or --force-ldap-user-pass-reset to continue."
        );
    }
    let server_builder = ldap_server::build_ldap_server(
        &config,
        backend_handler.clone(),
        actix_server::Server::build(),
    )
    .context("while binding the LDAP server")?;
    let server_builder = tcp_server::build_tcp_server(&config, backend_handler, server_builder)
        .await
        .context("while binding the TCP server")?;
    // Run every hour.
    let scheduler = Scheduler::new("0 0 * * * * *", sql_pool.clone());
    scheduler.start();
    Ok((server_builder, sql_pool))
}

async fn run_server_command(opts: RunOpts) -> Result<()> {
    debug!("CLI: {:#?}", &opts);

    let config = configuration::init(opts)?;
    logging::init(&config)?;

    let (server, sql_pool) = set_up_server(config).await?;
    let server = server.workers(1);

    let result = server.run().await.context("while starting the server");
    if let Err(e) = sql_pool.close().await {
        error!("Error closing database connection pool: {}", e);
    }
    result
}

async fn send_test_email_command(opts: TestEmailOpts) -> Result<()> {
    let to = opts.to.parse()?;
    let config = configuration::init(opts)?;
    logging::init(&config)?;

    mail::send_test_email(to, &config.smtp_options)
        .await
        .context("Could not send email: {:#}")
}

async fn run_healthcheck(opts: RunOpts) -> Result<()> {
    debug!("CLI: {:#?}", &opts);
    let config = configuration::init(opts)?;
    logging::init(&config)?;

    info!("Starting healthchecks");

    use tokio::time::timeout;
    let delay = Duration::from_millis(3000);
    let (ldap, ldaps, api) = tokio::join!(
        timeout(
            delay,
            healthcheck::check_ldap(&config.healthcheck_options.ldap_host, config.ldap_port)
        ),
        timeout(
            delay,
            healthcheck::check_ldaps(&config.healthcheck_options.ldap_host, &config.ldaps_options)
        ),
        timeout(
            delay,
            healthcheck::check_api(&config.healthcheck_options.http_host, config.http_port)
        ),
    );

    let failure = [ldap, ldaps, api]
        .into_iter()
        .flat_map(|res| {
            if let Err(e) = &res {
                error!("Error running the health check: {:#}", e);
            }
            res
        })
        .any(|r| r.is_err());
    if failure {
        bail!("Healthcheck failed")
    } else {
        Ok(())
    }
}

async fn create_schema_command(opts: RunOpts) -> Result<()> {
    debug!("CLI: {:#?}", &opts);
    let config = configuration::init(opts)?;
    logging::init(&config)?;
    let sql_pool = setup_sql_tables(&config.database_url).await?;
    info!("Schema created successfully.");
    if let Err(e) = sql_pool.close().await {
        error!("Error closing database connection pool: {}", e);
    }
    Ok(())
}

#[actix::main]
async fn main() -> Result<()> {
    let cli_opts = cli::init();
    match cli_opts.command {
        Command::ExportGraphQLSchema(opts) => {
            lldap_graphql_server::api::export_schema(opts.output_file)
        }
        Command::Run(opts) => run_server_command(opts).await,
        Command::HealthCheck(opts) => run_healthcheck(opts).await,
        Command::SendTestEmail(opts) => send_test_email_command(opts).await,
        Command::CreateSchema(opts) => create_schema_command(opts).await,
    }
}
