#![forbid(unsafe_code)]
#![forbid(non_ascii_idents)]
// TODO: Remove next line once ubuntu upgrades rustc to >=1.67.1
#![allow(clippy::uninlined_format_args)]

use std::time::Duration;

use crate::{
    domain::{
        handler::{
            CreateGroupRequest, CreateUserRequest, GroupBackendHandler, GroupListerBackendHandler,
            GroupRequestFilter, UserBackendHandler, UserListerBackendHandler, UserRequestFilter,
        },
        sql_backend_handler::SqlBackendHandler,
        sql_opaque_handler::register_password,
        sql_tables::{get_private_key_info, set_private_key_info},
    },
    infra::{
        cli::*,
        configuration::{compare_private_key_hashes, Configuration},
        db_cleaner::Scheduler,
        healthcheck, mail,
    },
};
use actix::Actor;
use actix_server::ServerBuilder;
use anyhow::{anyhow, bail, Context, Result};
use futures_util::TryFutureExt;
use sea_orm::Database;
use tracing::*;

mod domain;
mod infra;

async fn create_admin_user(handler: &SqlBackendHandler, config: &Configuration) -> Result<()> {
    let pass_length = config.ldap_user_pass.unsecure().len();
    assert!(
        pass_length >= 8,
        "Minimum password length is 8 characters, got {} characters",
        pass_length
    );
    handler
        .create_user(CreateUserRequest {
            user_id: config.ldap_user_dn.clone(),
            email: config.ldap_user_email.clone().into(),
            display_name: Some("Administrator".to_string()),
            ..Default::default()
        })
        .and_then(|_| {
            register_password(handler, config.ldap_user_dn.clone(), &config.ldap_user_pass)
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
            .context(format!("while creating {} group", group_name))?;
    }
    Ok(())
}

#[instrument(skip_all)]
async fn set_up_server(config: Configuration) -> Result<ServerBuilder> {
    info!("Starting LLDAP version {}", env!("CARGO_PKG_VERSION"));

    let sql_pool = {
        let mut sql_opt = sea_orm::ConnectOptions::new(config.database_url.clone());
        sql_opt
            .max_connections(5)
            .sqlx_logging(true)
            .sqlx_logging_level(log::LevelFilter::Debug);
        Database::connect(sql_opt).await?
    };
    domain::sql_tables::init_table(&sql_pool)
        .await
        .context("while creating the tables")?;
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
            bail!("The private key has not changed, but force_update_private_key/LLDAP_FORCE_UPDATE_PRIVATE_KEY is set to true. Please set force_update_private_key to false and restart the server.");
        }
        (Ok(true), _) | (Err(_), true) => {
            set_private_key_info(&sql_pool, private_key_info).await?;
        }
        (Ok(false), false) => {}
        (Err(e), false) => {
            return Err(anyhow!("The private key encoding the passwords has changed since last successful startup. Changing the private key will invalidate all existing passwords. If you want to proceed, restart the server with the CLI arg --force-update-private-key=true or the env variable LLDAP_FORCE_UPDATE_PRIVATE_KEY=true. You probably also want --force-ldap-user-pass-reset / LLDAP_FORCE_LDAP_USER_PASS_RESET=true to reset the admin password to the value in the configuration.").context(e));
        }
    }
    let backend_handler = SqlBackendHandler::new(config.clone(), sql_pool.clone());
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
        warn!("Could not find an admin user, trying to create the user \"admin\" with the config-provided password");
        create_admin_user(&backend_handler, &config)
            .await
            .map_err(|e| anyhow!("Error setting up admin login/account: {:#}", e))
            .context("while creating the admin user")?;
    } else if config.force_ldap_user_pass_reset {
        warn!("Forcing admin password reset to the config-provided password");
        register_password(
            &backend_handler,
            config.ldap_user_dn.clone(),
            &config.ldap_user_pass,
        )
        .await
        .context(format!(
            "while resetting admin password for {}",
            &config.ldap_user_dn
        ))?;
    }
    if config.force_update_private_key || config.force_ldap_user_pass_reset {
        bail!("Restart the server without --force-update-private-key or --force-ldap-user-pass-reset to continue.");
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
    Ok(server_builder)
}

async fn run_server(config: Configuration) -> Result<()> {
    set_up_server(config)
        .await?
        .workers(1)
        .run()
        .await
        .context("while starting the server")?;
    Ok(())
}

fn run_server_command(opts: RunOpts) -> Result<()> {
    debug!("CLI: {:#?}", &opts);

    let config = infra::configuration::init(opts)?;
    infra::logging::init(&config)?;

    use std::sync::{Arc, Mutex};
    let result = Arc::new(Mutex::new(Ok(())));
    let result_async = Arc::clone(&result);
    actix::run(run_server(config).unwrap_or_else(move |e| *result_async.lock().unwrap() = Err(e)))?;
    if let Err(e) = result.lock().unwrap().as_ref() {
        anyhow::bail!(format!("Could not set up servers: {:#}", e));
    }

    info!("End.");
    Ok(())
}

fn send_test_email_command(opts: TestEmailOpts) -> Result<()> {
    let to = opts.to.parse()?;
    let config = infra::configuration::init(opts)?;
    infra::logging::init(&config)?;

    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;

    runtime.block_on(
        mail::send_test_email(to, &config.smtp_options)
            .unwrap_or_else(|e| error!("Could not send email: {:#}", e)),
    );
    Ok(())
}

fn run_healthcheck(opts: RunOpts) -> Result<()> {
    debug!("CLI: {:#?}", &opts);
    let config = infra::configuration::init(opts)?;
    infra::logging::init(&config)?;

    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;

    info!("Starting healthchecks");

    use tokio::time::timeout;
    let delay = Duration::from_millis(3000);
    let (ldap, ldaps, api) = runtime.block_on(async {
        tokio::join!(
            timeout(delay, healthcheck::check_ldap(config.ldap_port)),
            timeout(delay, healthcheck::check_ldaps(&config.ldaps_options)),
            timeout(delay, healthcheck::check_api(config.http_port)),
        )
    });

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
        error!("Healthcheck failed");
    }
    std::process::exit(i32::from(failure))
}

async fn create_schema(database_url: String) -> Result<()> {
    let sql_pool = {
        let mut sql_opt = sea_orm::ConnectOptions::new(database_url.clone());
        sql_opt
            .max_connections(1)
            .sqlx_logging(true)
            .sqlx_logging_level(log::LevelFilter::Debug);
        Database::connect(sql_opt).await?
    };
    domain::sql_tables::init_table(&sql_pool)
        .await
        .context("while creating base tables")?;
    infra::jwt_sql_tables::init_table(&sql_pool)
        .await
        .context("while creating jwt tables")?;
    Ok(())
}

fn create_schema_command(opts: RunOpts) -> Result<()> {
    debug!("CLI: {:#?}", &opts);
    let config = infra::configuration::init(opts)?;
    infra::logging::init(&config)?;
    let database_url = config.database_url;

    actix::run(
        create_schema(database_url).unwrap_or_else(|e| error!("Could not create schema: {:#}", e)),
    )?;

    info!("Schema created successfully.");
    Ok(())
}

fn main() -> Result<()> {
    let cli_opts = infra::cli::init();
    match cli_opts.command {
        Command::ExportGraphQLSchema(opts) => infra::graphql::api::export_schema(opts),
        Command::Run(opts) => run_server_command(opts),
        Command::HealthCheck(opts) => run_healthcheck(opts),
        Command::SendTestEmail(opts) => send_test_email_command(opts),
        Command::CreateSchema(opts) => create_schema_command(opts),
    }
}
