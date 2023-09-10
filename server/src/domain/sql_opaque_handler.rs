use super::{
    error::{DomainError, Result},
    handler::{BindRequest, LoginHandler},
    model::{self, UserColumn},
    opaque_handler::{login, registration, OpaqueHandler},
    sql_backend_handler::SqlBackendHandler,
    types::UserId,
};
use async_trait::async_trait;
use base64::Engine;
use lldap_auth::opaque;
use sea_orm::{ActiveModelTrait, ActiveValue, EntityTrait, QuerySelect};
use secstr::SecUtf8;
use tracing::{debug, instrument};

type SqlOpaqueHandler = SqlBackendHandler;

#[instrument(skip_all, level = "debug", err, fields(username = %username.as_str()))]
fn passwords_match(
    password_file_bytes: &[u8],
    clear_password: &str,
    server_setup: &opaque::server::ServerSetup,
    username: &UserId,
) -> Result<()> {
    use opaque::{client, server};
    let mut rng = rand::rngs::OsRng;
    let client_login_start_result = client::login::start_login(clear_password, &mut rng)?;

    let password_file = server::ServerRegistration::deserialize(password_file_bytes)
        .map_err(opaque::AuthenticationError::ProtocolError)?;
    let server_login_start_result = server::login::start_login(
        &mut rng,
        server_setup,
        Some(password_file),
        client_login_start_result.message,
        username.as_str(),
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
            self.config.get_server_keys().private(),
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
}

#[async_trait]
impl LoginHandler for SqlBackendHandler {
    #[instrument(skip_all, level = "debug", err)]
    async fn bind(&self, request: BindRequest) -> Result<()> {
        if let Some(password_hash) = self
            .get_password_file_for_user(request.name.clone())
            .await?
        {
            if let Err(e) = passwords_match(
                &password_hash,
                &request.password,
                self.config.get_server_setup(),
                &request.name,
            ) {
                debug!(r#"Invalid password for "{}": {}"#, &request.name, e);
            } else {
                return Ok(());
            }
        } else {
            debug!(
                r#"User "{}" doesn't exist or has no password"#,
                &request.name
            );
        }
        Err(DomainError::AuthenticationError(format!(
            " for user '{}'",
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
        let maybe_password_file = self
            .get_password_file_for_user(UserId::new(&request.username))
            .await?
            .map(|bytes| {
                opaque::server::ServerRegistration::deserialize(&bytes).map_err(|_| {
                    DomainError::InternalError(format!(
                        "Corrupted password file for {}",
                        &request.username
                    ))
                })
            })
            .transpose()?;

        let mut rng = rand::rngs::OsRng;
        // Get the CredentialResponse for the user, or a dummy one if no user/no password.
        let start_response = opaque::server::login::start_login(
            &mut rng,
            self.config.get_server_setup(),
            maybe_password_file,
            request.login_start_request,
            &request.username,
        )?;
        let secret_key = self.get_orion_secret_key()?;
        let server_data = login::ServerData {
            username: request.username,
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
        let _session_key =
            opaque::server::login::finish_login(server_login, request.credential_finalization)?
                .session_key;

        Ok(UserId::new(&username))
    }

    #[instrument(skip_all, level = "debug", err)]
    async fn registration_start(
        &self,
        request: registration::ClientRegistrationStartRequest,
    ) -> Result<registration::ServerRegistrationStartResponse> {
        // Generate the server-side key and derive the data to send back.
        let start_response = opaque::server::registration::start_registration(
            self.config.get_server_setup(),
            request.registration_start_request,
            &request.username,
        )?;
        let secret_key = self.get_orion_secret_key()?;
        let server_data = registration::ServerData {
            username: request.username,
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
    ) -> Result<()> {
        let secret_key = self.get_orion_secret_key()?;
        let registration::ServerData { username } = bincode::deserialize(&orion::aead::open(
            &secret_key,
            &base64::engine::general_purpose::STANDARD.decode(&request.server_data)?,
        )?)?;

        let password_file =
            opaque::server::registration::get_password_file(request.registration_upload);
        // Set the user password to the new password.
        let user_update = model::users::ActiveModel {
            user_id: ActiveValue::Set(UserId::new(&username)),
            password_hash: ActiveValue::Set(Some(password_file.serialize())),
            ..Default::default()
        };
        user_update.update(&self.sql_pool).await?;
        Ok(())
    }
}

/// Convenience function to set a user's password.
#[instrument(skip_all, level = "debug", err, fields(username = %username.as_str()))]
pub(crate) async fn register_password(
    opaque_handler: &SqlOpaqueHandler,
    username: &UserId,
    password: &SecUtf8,
) -> Result<()> {
    let mut rng = rand::rngs::OsRng;
    use registration::*;
    let registration_start =
        opaque::client::registration::start_registration(password.unsecure().as_bytes(), &mut rng)?;
    let start_response = opaque_handler
        .registration_start(ClientRegistrationStartRequest {
            username: username.to_string(),
            registration_start_request: registration_start.message,
        })
        .await?;
    let registration_finish = opaque::client::registration::finish_registration(
        registration_start.state,
        start_response.registration_response,
        &mut rng,
    )?;
    opaque_handler
        .registration_finish(ClientRegistrationFinishRequest {
            server_data: start_response.server_data,
            registration_upload: registration_finish.message,
        })
        .await
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::sql_backend_handler::tests::*;

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
                username: username.to_string(),
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
        crate::infra::logging::init_for_tests();
        let config = get_default_config();
        let backend_handler = SqlBackendHandler::new(config.clone(), sql_pool.clone());
        let opaque_handler = SqlOpaqueHandler::new(config, sql_pool);
        insert_user_no_password(&backend_handler, "bob").await;
        insert_user_no_password(&backend_handler, "john").await;
        attempt_login(&opaque_handler, "bob", "bob00")
            .await
            .unwrap_err();
        register_password(
            &opaque_handler,
            &UserId::new("bob"),
            &secstr::SecUtf8::from("bob00"),
        )
        .await?;
        attempt_login(&opaque_handler, "bob", "wrong_password")
            .await
            .unwrap_err();
        attempt_login(&opaque_handler, "bob", "bob00").await?;
        Ok(())
    }

    #[tokio::test]
    async fn test_bind_user() {
        let sql_pool = get_initialized_db().await;
        let config = get_default_config();
        let handler = SqlOpaqueHandler::new(config, sql_pool.clone());
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
    async fn test_user_no_password() {
        let sql_pool = get_initialized_db().await;
        let config = get_default_config();
        let handler = SqlBackendHandler::new(config, sql_pool.clone());
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
