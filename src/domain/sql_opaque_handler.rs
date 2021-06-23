use super::{
    error::*, handler::LoginHandler, opaque_handler::*, sql_backend_handler::SqlBackendHandler,
    sql_tables::*,
};
use async_trait::async_trait;
use lldap_model::{opaque, BindRequest};
use log::*;
use sea_query::{Expr, Iden, Query};
use sqlx::Row;

type SqlOpaqueHandler = SqlBackendHandler;

fn passwords_match(
    password_file_bytes: &[u8],
    clear_password: &str,
    server_setup: &opaque::server::ServerSetup,
    username: &str,
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
            self.config.get_server_keys().private(),
        )?)
    }

    async fn get_password_file_for_user(
        &self,
        username: &str,
    ) -> Result<Option<opaque::server::ServerRegistration>> {
        // Fetch the previously registered password file from the DB.
        let password_file_bytes = {
            let query = Query::select()
                .column(Users::PasswordHash)
                .from(Users::Table)
                .and_where(Expr::col(Users::UserId).eq(username))
                .to_string(DbQueryBuilder {});
            if let Some(row) = sqlx::query(&query).fetch_optional(&self.sql_pool).await? {
                row.get::<Option<Vec<u8>>, _>(&*Users::PasswordHash.to_string())
                    // If no password, always fail.
                    .ok_or_else(|| DomainError::AuthenticationError(username.to_string()))?
            } else {
                return Ok(None);
            }
        };
        opaque::server::ServerRegistration::deserialize(&password_file_bytes)
            .map(Option::Some)
            .map_err(|_| {
                DomainError::InternalError(format!("Corrupted password file for {}", username))
            })
    }
}

#[async_trait]
impl LoginHandler for SqlBackendHandler {
    async fn bind(&self, request: BindRequest) -> Result<()> {
        if request.name == self.config.ldap_user_dn {
            if request.password == self.config.ldap_user_pass {
                return Ok(());
            } else {
                debug!(r#"Invalid password for LDAP bind user"#);
                return Err(DomainError::AuthenticationError(request.name));
            }
        }
        let query = Query::select()
            .column(Users::PasswordHash)
            .from(Users::Table)
            .and_where(Expr::col(Users::UserId).eq(request.name.as_str()))
            .to_string(DbQueryBuilder {});
        if let Ok(row) = sqlx::query(&query).fetch_one(&self.sql_pool).await {
            if let Some(password_hash) =
                row.get::<Option<Vec<u8>>, _>(&*Users::PasswordHash.to_string())
            {
                if let Err(e) = passwords_match(
                    &password_hash,
                    &request.password,
                    self.config.get_server_setup(),
                    &request.name,
                ) {
                    debug!(r#"Invalid password for "{}": {}"#, request.name, e);
                } else {
                    return Ok(());
                }
            } else {
                debug!(r#"User "{}" has no password"#, request.name);
            }
        } else {
            debug!(r#"No user found for "{}""#, request.name);
        }
        Err(DomainError::AuthenticationError(request.name))
    }
}

#[async_trait]
impl OpaqueHandler for SqlOpaqueHandler {
    async fn login_start(
        &self,
        request: login::ClientLoginStartRequest,
    ) -> Result<login::ServerLoginStartResponse> {
        let maybe_password_file = self.get_password_file_for_user(&request.username).await?;

        let mut rng = rand::rngs::OsRng;
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
            server_data: base64::encode(&encrypted_state),
            credential_response: start_response.message,
        })
    }

    async fn login_finish(&self, request: login::ClientLoginFinishRequest) -> Result<String> {
        let secret_key = self.get_orion_secret_key()?;
        let login::ServerData {
            username,
            server_login,
        } = bincode::deserialize(&orion::aead::open(
            &secret_key,
            &base64::decode(&request.server_data)?,
        )?)?;
        // Finish the login: this makes sure the client data is correct, and gives a session key we
        // don't need.
        let _session_key =
            opaque::server::login::finish_login(server_login, request.credential_finalization)?
                .session_key;

        Ok(username)
    }

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
            server_data: base64::encode(encrypted_state),
            registration_response: start_response.message,
        })
    }

    async fn registration_finish(
        &self,
        request: registration::ClientRegistrationFinishRequest,
    ) -> Result<()> {
        let secret_key = self.get_orion_secret_key()?;
        let registration::ServerData { username } = bincode::deserialize(&orion::aead::open(
            &secret_key,
            &base64::decode(&request.server_data)?,
        )?)?;

        let password_file =
            opaque::server::registration::get_password_file(request.registration_upload);
        {
            // Set the user password to the new password.
            let update_query = Query::update()
                .table(Users::Table)
                .values(vec![(
                    Users::PasswordHash,
                    password_file.serialize().into(),
                )])
                .and_where(Expr::col(Users::UserId).eq(username))
                .to_string(DbQueryBuilder {});
            sqlx::query(&update_query).execute(&self.sql_pool).await?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        domain::{
            handler::BackendHandler, sql_backend_handler::SqlBackendHandler, sql_tables::init_table,
        },
        infra::configuration::{Configuration, ConfigurationBuilder},
    };
    use lldap_model::*;

    fn get_default_config() -> Configuration {
        ConfigurationBuilder::default()
            .verbose(true)
            .build()
            .unwrap()
    }

    async fn get_in_memory_db() -> Pool {
        PoolOptions::new().connect("sqlite::memory:").await.unwrap()
    }

    async fn get_initialized_db() -> Pool {
        let sql_pool = get_in_memory_db().await;
        init_table(&sql_pool).await.unwrap();
        sql_pool
    }

    async fn insert_user_no_password(handler: &SqlBackendHandler, name: &str) {
        handler
            .create_user(CreateUserRequest {
                user_id: name.to_string(),
                email: "bob@bob.bob".to_string(),
                ..Default::default()
            })
            .await
            .unwrap();
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

    async fn attempt_registration(
        opaque_handler: &SqlOpaqueHandler,
        username: &str,
        password: &str,
    ) -> Result<()> {
        let mut rng = rand::rngs::OsRng;
        use registration::*;
        let registration_start =
            opaque::client::registration::start_registration(password, &mut rng)?;
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

    #[tokio::test]
    async fn test_flow() -> Result<()> {
        let sql_pool = get_initialized_db().await;
        let config = get_default_config();
        let backend_handler = SqlBackendHandler::new(config.clone(), sql_pool.clone());
        let opaque_handler = SqlOpaqueHandler::new(config, sql_pool);
        insert_user_no_password(&backend_handler, "bob").await;
        attempt_login(&opaque_handler, "bob", "bob00")
            .await
            .unwrap_err();
        attempt_registration(&opaque_handler, "bob", "bob00").await?;
        attempt_login(&opaque_handler, "bob", "wrong_password")
            .await
            .unwrap_err();
        attempt_login(&opaque_handler, "bob", "bob00").await?;
        Ok(())
    }
}
