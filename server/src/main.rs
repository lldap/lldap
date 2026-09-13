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
mod tls;

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
    sql_migrations::OPAQUE_V4_SCHEMA_VERSION,
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

/// Count users whose password is still in the opaque-ke v0.7 format.
async fn count_v07_passwords(sql_pool: &DatabaseConnection) -> Result<u64> {
    use lldap_domain_model::model::users;
    use lldap_sql_backend_handler::OpaqueProtocolVersion;
    use sea_orm::{ColumnTrait, EntityTrait, PaginatorTrait, QueryFilter};
    let count = users::Entity::find()
        .filter(ColumnTrait::eq(
            &users::Column::PasswordVersion,
            OpaqueProtocolVersion::V07.db_value(),
        ))
        .filter(users::Column::PasswordHash.is_not_null())
        .count(sql_pool)
        .await?;
    Ok(count)
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
    let migrated_from = sql_tables::init_table(&sql_pool)
        .await
        .context("while creating base tables")?;
    jwt_sql_tables::init_table(&sql_pool)
        .await
        .context("while creating jwt tables")?;
    // Sessions issued before the opaque-ke 4.0 upgrade must not outlive it:
    // a password reset through a pre-upgrade session could otherwise race
    // the lazy password upgrade. This runs only in the process that applied
    // the migration (`run`, or the explicit `create_schema` subcommand),
    // after the JWT tables exist. It cannot live inside the v12 migration
    // transaction: those tables belong to this crate and do not exist yet
    // on a fresh database. A crash between the migration commit and this
    // step is not retried; the web client's change-password flow refusing
    // to run against a v0.7 password is the backstop.
    if migrated_from.is_some_and(|version| version < OPAQUE_V4_SCHEMA_VERSION) {
        info!(
            "Schema migrated across the opaque-ke 4.0 upgrade: invalidating every existing \
             session, users will have to log in again."
        );
        jwt_sql_tables::invalidate_all_sessions(&sql_pool)
            .await
            .context("while invalidating pre-upgrade sessions")?;
    }
    Ok(sql_pool)
}

/// What to do with the server key at startup, given what the database
/// recorded at the last successful startup.
#[derive(Debug, PartialEq, Eq)]
enum KeyAction {
    /// Same key as last time: nothing to record.
    Keep,
    /// Record the key hash: first startup or forced rotation.
    Record,
    /// Record the key hash: the recorded hash is the preserved v0.7 key's,
    /// so this is the automatic opaque-ke 0.7 -> 4.0 upgrade.
    RecordV07Upgrade,
    /// Refuse to start.
    Reject(KeyRejection),
}

#[derive(Debug, PartialEq, Eq)]
enum KeyRejection {
    /// `force_update_private_key` is set but the key did not change.
    ForceWithoutChange,
    /// The key file is a valid v0.7 key, but not the one this database was
    /// last used with (wrong file restored).
    ForeignV07Key,
    /// The key changed and no override was given.
    Changed,
}

/// Pure decision for the startup key handshake, kept free of IO so every
/// arm is unit-tested. `comparison` is `compare_private_key_hashes`'s
/// verdict (`Ok(true)`: nothing recorded yet, `Ok(false)`: same key, `Err`:
/// different key), `stored_is_v07_key` whether the recorded hash is the
/// preserved v0.7 key's, and `derived_from_v07_key_file` whether the current
/// key is derived from a v0.7 key file.
///
/// Every instance of a multi-instance deployment derives the same key from
/// the same file or seed, so `Record` / `RecordV07Upgrade` write the same
/// hash and are idempotent however the instances interleave.
fn decide_key_action(
    comparison: &Result<bool>,
    force_update: bool,
    stored_is_v07_key: bool,
    derived_from_v07_key_file: bool,
) -> KeyAction {
    match (comparison, force_update) {
        (Ok(false), true) => KeyAction::Reject(KeyRejection::ForceWithoutChange),
        (Ok(false), false) => KeyAction::Keep,
        (Ok(true), _) | (Err(_), true) => KeyAction::Record,
        (Err(_), false) if stored_is_v07_key => KeyAction::RecordV07Upgrade,
        (Err(_), false) if derived_from_v07_key_file => {
            KeyAction::Reject(KeyRejection::ForeignV07Key)
        }
        (Err(_), false) => KeyAction::Reject(KeyRejection::Changed),
    }
}

#[instrument(skip_all)]
async fn set_up_server(config: Configuration) -> Result<(ServerBuilder, DatabaseConnection)> {
    info!("Starting LLDAP version {}", env!("CARGO_PKG_VERSION"));

    let sql_pool = setup_sql_tables(&config.database_url).await?;
    let private_key_info = config.get_private_key_info();
    let stored_key_info = get_private_key_info(&sql_pool).await?;
    let comparison = compare_private_key_hashes(stored_key_info.as_ref(), &private_key_info);
    let stored_hash = stored_key_info.as_ref().map(|info| &info.private_key_hash);
    let stored_is_v07_key =
        stored_hash.is_some() && stored_hash == config.get_v07_private_key_hash().as_ref();
    match decide_key_action(
        &comparison,
        config.force_update_private_key,
        stored_is_v07_key,
        config.is_derived_from_v07_key_file(),
    ) {
        KeyAction::Keep => {}
        KeyAction::Record => set_private_key_info(&sql_pool, private_key_info).await?,
        KeyAction::RecordV07Upgrade => {
            // The key recorded at the last successful startup is exactly the
            // preserved v0.7 key (from the key file, or re-derived from the
            // key_seed): this is the automatic opaque-ke 0.7 -> 4.0 upgrade,
            // not an accidental key change. Existing passwords stay valid
            // (checked against the v0.7 key) and are re-registered under the
            // new key on each user's next login. Nothing is written to the
            // key file: the 4.0 key is derived from it on every startup.
            info!(
                "Detected the opaque-ke 0.7 -> 4.0 upgrade: the server key from the \
                 last startup matches the preserved v0.7 key. Existing passwords are \
                 kept and will be upgraded automatically on each user's next login."
            );
            set_private_key_info(&sql_pool, private_key_info).await?;
        }
        KeyAction::Reject(KeyRejection::ForceWithoutChange) => {
            bail!(
                "The private key has not changed, but force_update_private_key/LLDAP_FORCE_UPDATE_PRIVATE_KEY is set to true. Please set force_update_private_key to false and restart the server."
            );
        }
        KeyAction::Reject(KeyRejection::ForeignV07Key) => {
            let e = comparison.expect_err("rejections only arise from a key mismatch");
            return Err(anyhow!(
                "The key file holds a valid opaque-ke 0.7 (pre-upgrade) key, but it does \
                 not match the key from the last successful startup. This usually means \
                 the wrong key file was restored. Restore the matching key file, or, to \
                 proceed anyway and invalidate all existing passwords, restart with \
                 --force-update-private-key=true (LLDAP_FORCE_UPDATE_PRIVATE_KEY=true), \
                 probably together with --force-ldap-user-pass-reset / \
                 LLDAP_FORCE_LDAP_USER_PASS_RESET=true to reset the admin password."
            )
            .context(e));
        }
        KeyAction::Reject(KeyRejection::Changed) => {
            let e = comparison.expect_err("rejections only arise from a key mismatch");
            return Err(anyhow!("The private key encoding the passwords has changed since last successful startup. Changing the private key will invalidate all existing passwords. If you want to proceed, restart the server with the CLI arg --force-update-private-key=true or the env variable LLDAP_FORCE_UPDATE_PRIVATE_KEY=true. You probably also want --force-ldap-user-pass-reset / LLDAP_FORCE_LDAP_USER_PASS_RESET=true to reset the admin password to the value in the configuration.").context(e));
        }
    }
    let backend_handler = SqlBackendHandler::new(
        config.get_server_setup().clone(),
        config.get_v07_server_key_bytes().map(|b| b.to_vec()),
        sql_pool.clone(),
    );

    // Warn about users still using OPAQUE v0.7 passwords.
    match count_v07_passwords(&sql_pool).await {
        Ok(0) => {}
        Ok(v07_count) => {
            if config.get_v07_server_key_bytes().is_some() {
                warn!(
                    "{} user(s) still have OPAQUE v0.7 passwords. \
                     They will be automatically upgraded to v4.0 on next login.",
                    v07_count
                );
            } else {
                warn!(
                    "{} user(s) have OPAQUE v0.7 passwords but no v0.7 \
                     server key is available. These users will NOT be able to log in \
                     until they reset their passwords.",
                    v07_count
                );
            }
        }
        Err(e) => {
            warn!("Failed to count OPAQUE v0.7 passwords at startup: {:#}", e);
        }
    }

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

#[cfg(test)]
mod tests {
    use super::*;

    fn changed() -> Result<bool> {
        Err(anyhow!("key changed"))
    }

    #[test]
    fn key_action_same_key_is_kept() {
        assert_eq!(
            decide_key_action(&Ok(false), false, false, false),
            KeyAction::Keep
        );
        // Even when the recorded hash happens to be a v0.7 hash.
        assert_eq!(
            decide_key_action(&Ok(false), false, true, true),
            KeyAction::Keep
        );
    }

    #[test]
    fn key_action_force_without_change_is_rejected() {
        assert_eq!(
            decide_key_action(&Ok(false), true, false, false),
            KeyAction::Reject(KeyRejection::ForceWithoutChange)
        );
    }

    #[test]
    fn key_action_first_startup_records() {
        assert_eq!(
            decide_key_action(&Ok(true), false, false, false),
            KeyAction::Record
        );
        assert_eq!(
            decide_key_action(&Ok(true), true, false, true),
            KeyAction::Record
        );
    }

    #[test]
    fn key_action_forced_rotation_records() {
        assert_eq!(
            decide_key_action(&changed(), true, false, false),
            KeyAction::Record
        );
        assert_eq!(
            decide_key_action(&changed(), true, true, true),
            KeyAction::Record
        );
    }

    #[test]
    fn key_action_v07_upgrade_records() {
        // File mode (derived from the v0.7 file) and seed mode alike.
        assert_eq!(
            decide_key_action(&changed(), false, true, true),
            KeyAction::RecordV07Upgrade
        );
        assert_eq!(
            decide_key_action(&changed(), false, true, false),
            KeyAction::RecordV07Upgrade
        );
    }

    #[test]
    fn key_action_foreign_v07_key_is_rejected() {
        assert_eq!(
            decide_key_action(&changed(), false, false, true),
            KeyAction::Reject(KeyRejection::ForeignV07Key)
        );
    }

    #[test]
    fn key_action_changed_key_is_rejected() {
        assert_eq!(
            decide_key_action(&changed(), false, false, false),
            KeyAction::Reject(KeyRejection::Changed)
        );
    }
}
