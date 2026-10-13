use crate::SqlBackendHandler;
use async_trait::async_trait;
use base64::Engine;
use lldap_auth::opaque;
use lldap_domain::types::UserId;
use lldap_domain_handlers::handler::{BindRequest, LoginHandler, UserBackendHandler};
use lldap_domain_model::{
    error::{DomainError, Result},
    model::{self, UserColumn},
};
use lldap_opaque_handler::{OpaqueHandler, ValidationResults, login, registration};
use sea_orm::{ColumnTrait, EntityTrait, QueryFilter, QuerySelect};
use secstr::SecUtf8;
use tracing::{debug, info, instrument, warn};

type SqlOpaqueHandler = SqlBackendHandler;

#[instrument(skip_all, level = "debug", err, fields(username = %username.as_str()))]
fn passwords_match(
    password_file_bytes: &[u8],
    clear_password: &str,
    opaque_setup: &opaque::server::ServerSetup,
    username: &UserId,
) -> Result<()> {
    use opaque::{client, server};
    let mut rng = rand::rngs::OsRng;
    let client_login_start_result = client::login::start_login(clear_password, &mut rng)?;

    let password_file = server::ServerRegistration::deserialize(password_file_bytes)
        .map_err(opaque::AuthenticationError::ProtocolError)?;
    let server_login_start_result = server::login::start_login(
        &mut rng,
        opaque_setup,
        Some(password_file),
        client_login_start_result.message,
        username,
    )?;
    client::login::finish_login(
        client_login_start_result.state,
        server_login_start_result.message,
    )?;
    Ok(())
}

impl SqlBackendHandler {
    fn get_orion_secret_key(&self) -> Result<orion::aead::SecretKey> {
        Ok(orion::aead::SecretKey::from_slice(
            self.opaque_setup.keypair().private(),
        )?)
    }

    #[instrument(skip(self), level = "debug", err)]
    async fn get_password_file_for_user(&self, user_id: UserId) -> Result<Option<Vec<u8>>> {
        // Fetch the previously registered password file from the DB.
        Ok(model::User::find_by_id(user_id)
            .select_only()
            .column(UserColumn::PasswordHash)
            .into_tuple::<(Option<Vec<u8>>,)>()
            .one(&self.sql_pool)
            .await?
            .and_then(|u| u.0))
    }

    #[instrument(skip(self, user_id), level = "debug", err)]
    async fn get_password_modified_date_for_user(
        &self,
        user_id: UserId,
    ) -> Result<Option<chrono::NaiveDateTime>> {
        // Fetch the date at which the user's password was last modified; `None` if
        // the user doesn't exist.
        Ok(model::User::find_by_id(user_id)
            .select_only()
            .column(UserColumn::PasswordModifiedDate)
            .into_tuple::<(Option<chrono::NaiveDateTime>,)>()
            .one(&self.sql_pool)
            .await?
            .and_then(|u| u.0))
    }
}

/// How long a registration transaction (start -> finish) stays usable after it was
/// started. After that, the client has to restart the password change.
const REGISTRATION_TRANSACTION_TTL_SECS: i64 = 10 * 60;

/// Expiry of a registration transaction, as a Unix timestamp in nanoseconds.
fn registration_transaction_expiry() -> i64 {
    (chrono::Utc::now() + chrono::Duration::seconds(REGISTRATION_TRANSACTION_TTL_SECS))
        .timestamp_nanos_opt()
        // An expiry that cannot be represented must never validate.
        .unwrap_or(i64::MAX)
}

#[async_trait]
impl LoginHandler for SqlBackendHandler {
    #[instrument(skip_all, level = "debug", err)]
    async fn bind(&self, request: BindRequest) -> Result<()> {
        if let Some(password_hash) = self
            .get_password_file_for_user(request.name.clone())
            .await?
        {
            info!(r#"Login attempt for "{}""#, &request.name);
            if passwords_match(
                &password_hash,
                &request.password,
                &self.opaque_setup,
                &request.name,
            )
            .is_ok()
            {
                return Ok(());
            }
        } else {
            debug!(
                r#"User "{}" doesn't exist or has no password"#,
                &request.name
            );
        }
        Err(DomainError::AuthenticationError(format!(
            r#"for user "{}""#,
            request.name
        )))
    }
}

#[async_trait]
impl OpaqueHandler for SqlOpaqueHandler {
    #[instrument(skip_all, level = "debug", err)]
    async fn login_start(
        &self,
        request: login::ClientLoginStartRequest,
    ) -> Result<login::ServerLoginStartResponse> {
        let user_id = request.username;
        info!(r#"OPAQUE login attempt for "{}""#, &user_id);
        let maybe_password_file = self
            .get_password_file_for_user(user_id.clone())
            .await?
            .map(|bytes| {
                opaque::server::ServerRegistration::deserialize(&bytes).map_err(|_| {
                    DomainError::InternalError(format!("Corrupted password file for {}", &user_id))
                })
            })
            .transpose()?;

        let mut rng = rand::rngs::OsRng;
        // Get the CredentialResponse for the user, or a dummy one if no user/no password.
        let start_response = opaque::server::login::start_login(
            &mut rng,
            &self.opaque_setup,
            maybe_password_file,
            request.login_start_request,
            &user_id,
        )?;
        let secret_key = self.get_orion_secret_key()?;
        let server_data = login::ServerData {
            username: user_id,
            server_login: start_response.state,
        };
        let encrypted_state = orion::aead::seal(&secret_key, &bincode::serialize(&server_data)?)?;

        Ok(login::ServerLoginStartResponse {
            server_data: base64::engine::general_purpose::STANDARD.encode(encrypted_state),
            credential_response: start_response.message,
        })
    }

    #[instrument(skip_all, level = "debug", err)]
    async fn login_finish(&self, request: login::ClientLoginFinishRequest) -> Result<UserId> {
        let secret_key = self.get_orion_secret_key()?;
        let login::ServerData {
            username,
            server_login,
        } = bincode::deserialize(&orion::aead::open(
            &secret_key,
            &base64::engine::general_purpose::STANDARD.decode(&request.server_data)?,
        )?)?;
        // Finish the login: this makes sure the client data is correct, and gives a session key we
        // don't need.
        match opaque::server::login::finish_login(server_login, request.credential_finalization) {
            Ok(session) => {
                info!(r#"OPAQUE login successful for "{}""#, &username);
                let _ = session.session_key;
            }
            Err(e) => {
                warn!(r#"OPAQUE login attempt failed for "{}""#, &username);
                return Err(e.into());
            }
        };

        Ok(username)
    }

    #[instrument(skip_all, level = "debug", err)]
    async fn registration_start(
        &self,
        request: registration::ClientRegistrationStartRequest,
    ) -> Result<registration::ServerRegistrationStartResponse> {
        // Bind the transaction to the user's current password epoch: the finish is
        // rejected if the password changed in between (e.g. by an admin reset), which
        // also makes the transaction one-time.
        let password_epoch = match self
            .get_password_modified_date_for_user(request.username.clone())
            .await?
        {
            Some(date) => date,
            None => {
                return Err(DomainError::EntityNotFound(format!(
                    "User not found: {}",
                    &request.username
                )));
            }
        };
        // Generate the server-side key and derive the data to send back.
        let start_response = opaque::server::registration::start_registration(
            &self.opaque_setup,
            request.registration_start_request,
            &request.username,
        )?;
        let secret_key = self.get_orion_secret_key()?;
        let server_data = registration::ServerData {
            username: request.username,
            expires_at: registration_transaction_expiry(),
            password_epoch,
        };
        let encrypted_state = orion::aead::seal(&secret_key, &bincode::serialize(&server_data)?)?;
        Ok(registration::ServerRegistrationStartResponse {
            server_data: base64::engine::general_purpose::STANDARD.encode(encrypted_state),
            registration_response: start_response.message,
        })
    }

    #[instrument(skip_all, level = "debug", err)]
    async fn registration_finish(
        &self,
        request: registration::ClientRegistrationFinishRequest,
        validation_results: &ValidationResults,
    ) -> Result<()> {
        let secret_key = self.get_orion_secret_key()?;
        let registration::ServerData {
            username,
            expires_at,
            password_epoch,
        } = bincode::deserialize(&orion::aead::open(
            &secret_key,
            &base64::engine::general_purpose::STANDARD.decode(&request.server_data)?,
        )?)?;
        // Reject transactions that are past their expiry: a retained finish request
        // must not stay a usable password-replacement capability.
        if chrono::Utc::now().timestamp_nanos_opt().unwrap_or(i64::MAX) >= expires_at {
            warn!(
                r#"Rejected expired registration request for "{}""#,
                &username
            );
            return Err(DomainError::AuthenticationError(
                "Registration request expired; restart the password change".to_string(),
            ));
        }
        // The finish must carry the same authorization as the start: valid
        // credentials that are allowed to change the target user's password.
        let user_is_admin = self
            .get_user_groups(&username)
            .await?
            .iter()
            .any(|g| g.display_name == "lldap_admin".into());
        if !validation_results.can_change_password(&username, user_is_admin) {
            warn!(
                r#"User "{}" is not authorized to change the password of "{}""#,
                &validation_results.user, &username
            );
            return Err(DomainError::AuthenticationError(
                "Not authorized to change the user's password".to_string(),
            ));
        }
        // Atomically consume the transaction: the update only applies while the
        // password epoch is unchanged, so an admin reset, another password change
        // or a concurrent replay of the same transaction cannot ride on it.
        let password_file =
            opaque::server::registration::get_password_file(request.registration_upload);
        // Set the user password to the new password.
        let now = chrono::Utc::now().naive_utc();
        let update_result = model::User::update_many()
            .col_expr(
                UserColumn::PasswordHash,
                sea_orm::sea_query::Expr::value(password_file.serialize()),
            )
            .col_expr(
                UserColumn::PasswordModifiedDate,
                sea_orm::sea_query::Expr::value(now),
            )
            .col_expr(
                UserColumn::ModifiedDate,
                sea_orm::sea_query::Expr::value(now),
            )
            .filter(ColumnTrait::eq(&UserColumn::UserId, username.clone()))
            .filter(ColumnTrait::eq(
                &UserColumn::PasswordModifiedDate,
                password_epoch,
            ))
            .exec(&self.sql_pool)
            .await?;
        if update_result.rows_affected == 0 {
            return Err(
                match self
                    .get_password_modified_date_for_user(username.clone())
                    .await?
                {
                    Some(_) => {
                        warn!(
                            r#"Rejected stale registration request for "{}": the password changed since it was started"#,
                            &username
                        );
                        DomainError::AuthenticationError(
                        "The password was changed since the registration was started; restart the password change"
                            .to_string(),
                    )
                    }
                    None => DomainError::EntityNotFound(format!("User not found: {}", &username)),
                },
            );
        }
        info!(r#"Successfully (re)set password for "{}""#, &username);
        Ok(())
    }
}

/// Convenience function to set a user's password.
#[instrument(skip_all, level = "debug", err, fields(username = %username.as_str()))]
pub async fn register_password(
    opaque_handler: &SqlOpaqueHandler,
    validation_results: &ValidationResults,
    username: UserId,
    password: &SecUtf8,
) -> Result<()> {
    let mut rng = rand::rngs::OsRng;
    use registration::*;
    let registration_start =
        opaque::client::registration::start_registration(password.unsecure().as_bytes(), &mut rng)?;
    let start_response = opaque_handler
        .registration_start(ClientRegistrationStartRequest {
            username,
            registration_start_request: registration_start.message,
        })
        .await?;
    let registration_finish = opaque::client::registration::finish_registration(
        registration_start.state,
        start_response.registration_response,
        &mut rng,
    )?;
    opaque_handler
        .registration_finish(
            ClientRegistrationFinishRequest {
                server_data: start_response.server_data,
                registration_upload: registration_finish.message,
            },
            validation_results,
        )
        .await
}

#[cfg(test)]
mod tests {
    use self::opaque::server::generate_random_private_key;

    use super::*;
    use crate::sql_backend_handler::tests::{
        get_initialized_db, insert_user, insert_user_no_password,
    };
    use chrono::TimeZone;
    use lldap_auth::access_control::Permission;

    fn self_credentials(username: &str) -> ValidationResults {
        ValidationResults {
            user: UserId::new(username),
            permission: Permission::Regular,
        }
    }

    fn admin_credentials() -> ValidationResults {
        ValidationResults {
            user: UserId::new("admin"),
            permission: Permission::Admin,
        }
    }

    /// Performs the client side of the registration protocol for `username` and
    /// returns the not-yet-submitted finish request.
    async fn start_registration_transaction(
        handler: &SqlBackendHandler,
        username: &str,
        password: &str,
    ) -> Result<registration::ClientRegistrationFinishRequest> {
        let mut rng = rand::rngs::OsRng;
        let registration_start =
            opaque::client::registration::start_registration(password.as_bytes(), &mut rng)?;
        let start_response = handler
            .registration_start(registration::ClientRegistrationStartRequest {
                username: UserId::new(username),
                registration_start_request: registration_start.message,
            })
            .await?;
        let registration_finish = opaque::client::registration::finish_registration(
            registration_start.state,
            start_response.registration_response,
            &mut rng,
        )?;
        Ok(registration::ClientRegistrationFinishRequest {
            server_data: start_response.server_data,
            registration_upload: registration_finish.message,
        })
    }

    async fn attempt_login(
        opaque_handler: &SqlOpaqueHandler,
        username: &str,
        password: &str,
    ) -> Result<()> {
        let mut rng = rand::rngs::OsRng;
        use login::*;
        let login_start = opaque::client::login::start_login(password, &mut rng)?;
        let start_response = opaque_handler
            .login_start(ClientLoginStartRequest {
                username: UserId::new(username),
                login_start_request: login_start.message,
            })
            .await?;
        let login_finish = opaque::client::login::finish_login(
            login_start.state,
            start_response.credential_response,
        )?;
        opaque_handler
            .login_finish(ClientLoginFinishRequest {
                server_data: start_response.server_data,
                credential_finalization: login_finish.message,
            })
            .await?;
        Ok(())
    }

    #[tokio::test]
    async fn test_opaque_flow() -> Result<()> {
        let sql_pool = get_initialized_db().await;
        crate::logging::init_for_tests();
        let backend_handler = SqlBackendHandler::new(generate_random_private_key(), sql_pool);
        insert_user_no_password(&backend_handler, "bob").await;
        insert_user_no_password(&backend_handler, "john").await;
        attempt_login(&backend_handler, "bob", "bob00")
            .await
            .unwrap_err();
        register_password(
            &backend_handler,
            &admin_credentials(),
            UserId::new("bob"),
            &secstr::SecUtf8::from("bob00"),
        )
        .await?;
        attempt_login(&backend_handler, "bob", "wrong_password")
            .await
            .unwrap_err();
        attempt_login(&backend_handler, "bob", "bob00").await?;
        Ok(())
    }

    #[tokio::test]
    async fn test_bind_user() {
        let sql_pool = get_initialized_db().await;
        let handler = SqlOpaqueHandler::new(generate_random_private_key(), sql_pool.clone());
        insert_user(&handler, "bob", "bob00").await;

        handler
            .bind(BindRequest {
                name: UserId::new("bob"),
                password: "bob00".to_string(),
            })
            .await
            .unwrap();
        handler
            .bind(BindRequest {
                name: UserId::new("andrew"),
                password: "bob00".to_string(),
            })
            .await
            .unwrap_err();
        handler
            .bind(BindRequest {
                name: UserId::new("bob"),
                password: "wrong_password".to_string(),
            })
            .await
            .unwrap_err();
    }

    #[tokio::test]
    async fn test_registration_finish_requires_matching_credentials() -> Result<()> {
        let sql_pool = get_initialized_db().await;
        let handler = SqlBackendHandler::new(generate_random_private_key(), sql_pool);
        insert_user_no_password(&handler, "bob").await;

        let finish_request = start_registration_transaction(&handler, "bob", "bob00").await?;
        // A different regular user cannot finish a transaction for bob.
        let err = handler
            .registration_finish(finish_request.clone(), &self_credentials("john"))
            .await
            .unwrap_err();
        assert!(matches!(err, DomainError::AuthenticationError(_)));
        // The right credentials still work: the failed attempt did not consume the
        // transaction.
        handler
            .registration_finish(finish_request, &self_credentials("bob"))
            .await
            .unwrap();
        attempt_login(&handler, "bob", "bob00").await.unwrap();
        Ok(())
    }

    #[tokio::test]
    async fn test_registration_finish_admin_can_change_other_users() -> Result<()> {
        let sql_pool = get_initialized_db().await;
        let handler = SqlBackendHandler::new(generate_random_private_key(), sql_pool);
        insert_user_no_password(&handler, "bob").await;

        let finish_request = start_registration_transaction(&handler, "bob", "bob00").await?;
        handler
            .registration_finish(finish_request, &admin_credentials())
            .await
            .unwrap();
        attempt_login(&handler, "bob", "bob00").await.unwrap();
        Ok(())
    }

    #[tokio::test]
    async fn test_registration_finish_replay_rejected() -> Result<()> {
        let sql_pool = get_initialized_db().await;
        let handler = SqlBackendHandler::new(generate_random_private_key(), sql_pool);
        insert_user_no_password(&handler, "bob").await;

        let finish_request = start_registration_transaction(&handler, "bob", "bob00").await?;
        handler
            .registration_finish(finish_request.clone(), &self_credentials("bob"))
            .await
            .unwrap();
        // Replaying the exact same finish request must fail: the successful finish
        // bumped the password epoch and consumed the transaction.
        let err = handler
            .registration_finish(finish_request, &self_credentials("bob"))
            .await
            .unwrap_err();
        assert!(matches!(err, DomainError::AuthenticationError(_)));
        // The password set by the first finish is the one that stays.
        attempt_login(&handler, "bob", "bob00").await.unwrap();
        Ok(())
    }

    #[tokio::test]
    async fn test_registration_finish_rejected_after_password_change() -> Result<()> {
        let sql_pool = get_initialized_db().await;
        let handler = SqlBackendHandler::new(generate_random_private_key(), sql_pool);
        insert_user_no_password(&handler, "bob").await;

        // Stage a finish request, then an admin resets the password in between.
        let finish_request =
            start_registration_transaction(&handler, "bob", "staged_password").await?;
        register_password(
            &handler,
            &admin_credentials(),
            UserId::new("bob"),
            &secstr::SecUtf8::from("recovery_password"),
        )
        .await
        .unwrap();
        // The staged transaction is dead, even with the right credentials.
        let err = handler
            .registration_finish(finish_request, &self_credentials("bob"))
            .await
            .unwrap_err();
        assert!(matches!(err, DomainError::AuthenticationError(_)));
        // The admin-set recovery password is the one that stays.
        attempt_login(&handler, "bob", "recovery_password")
            .await
            .unwrap();
        attempt_login(&handler, "bob", "staged_password")
            .await
            .unwrap_err();
        Ok(())
    }

    #[tokio::test]
    async fn test_registration_finish_expired_rejected() -> Result<()> {
        let sql_pool = get_initialized_db().await;
        let handler = SqlBackendHandler::new(generate_random_private_key(), sql_pool);
        insert_user_no_password(&handler, "bob").await;

        let finish_request = start_registration_transaction(&handler, "bob", "bob00").await?;
        // Recreate the server data with an expiry in the past.
        let secret_key =
            orion::aead::SecretKey::from_slice(handler.opaque_setup.keypair().private())?;
        let server_data = registration::ServerData {
            username: UserId::new("bob"),
            expires_at: 0,
            password_epoch: chrono::Utc.timestamp_opt(0, 0).unwrap().naive_utc(),
        };
        let encrypted_state = orion::aead::seal(&secret_key, &bincode::serialize(&server_data)?)?;
        let expired_request = registration::ClientRegistrationFinishRequest {
            server_data: base64::engine::general_purpose::STANDARD.encode(encrypted_state),
            registration_upload: finish_request.registration_upload,
        };
        let err = handler
            .registration_finish(expired_request, &self_credentials("bob"))
            .await
            .unwrap_err();
        assert!(matches!(err, DomainError::AuthenticationError(_)));
        // The password was not touched.
        attempt_login(&handler, "bob", "bob00").await.unwrap_err();
        Ok(())
    }

    #[tokio::test]
    async fn test_registration_start_requires_existing_user() -> Result<()> {
        let sql_pool = get_initialized_db().await;
        let handler = SqlBackendHandler::new(generate_random_private_key(), sql_pool);
        let mut rng = rand::rngs::OsRng;
        let registration_start =
            opaque::client::registration::start_registration("bob00".as_bytes(), &mut rng)?;
        let err = handler
            .registration_start(registration::ClientRegistrationStartRequest {
                username: UserId::new("ghost"),
                registration_start_request: registration_start.message,
            })
            .await
            .err()
            .expect("registration should fail for a nonexistent user");
        assert!(matches!(err, DomainError::EntityNotFound(_)));
        Ok(())
    }

    #[tokio::test]
    async fn test_user_no_password() {
        let sql_pool = get_initialized_db().await;
        let handler = SqlBackendHandler::new(generate_random_private_key(), sql_pool.clone());
        insert_user_no_password(&handler, "bob").await;

        handler
            .bind(BindRequest {
                name: UserId::new("bob"),
                password: "bob00".to_string(),
            })
            .await
            .unwrap_err();
    }
}
