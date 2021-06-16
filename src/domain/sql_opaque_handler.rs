use super::{
    error::*, handler::LoginHandler, opaque_handler::*, sql_backend_handler::SqlBackendHandler,
    sql_tables::*,
};
use async_trait::async_trait;
use lldap_model::{opaque, BindRequest};
use log::*;
use rand::{CryptoRng, RngCore};
use sea_query::{Expr, Iden, Query};
use sqlx::Row;

type SqlOpaqueHandler = SqlBackendHandler;

fn generate_random_id<R: RngCore + CryptoRng>(rng: &mut R) -> String {
    use rand::{distributions::Alphanumeric, Rng};
    std::iter::repeat(())
        .map(|()| rng.sample(Alphanumeric))
        .map(char::from)
        .take(32)
        .collect()
}

fn passwords_match(
    password_file_bytes: &[u8],
    clear_password: &str,
    server_private_key: &opaque::PrivateKey,
) -> Result<()> {
    use opaque::{client, server};
    let mut rng = rand::rngs::OsRng;
    let client_login_start_result = client::login::start_login(clear_password, &mut rng)?;

    let password_file = server::ServerRegistration::deserialize(password_file_bytes)
        .map_err(opaque::AuthenticationError::ProtocolError)?;
    let server_login_start_result = server::login::start_login(
        &mut rng,
        password_file,
        server_private_key,
        client_login_start_result.message,
    )?;
    client::login::finish_login(
        client_login_start_result.state,
        server_login_start_result.message,
    )?;
    Ok(())
}

#[async_trait]
impl LoginHandler for SqlBackendHandler {
    async fn bind(&self, request: BindRequest) -> Result<()> {
        if request.name == self.config.ldap_user_dn {
            if request.password == self.config.ldap_user_pass {
                return Ok(());
            } else {
                debug!(r#"Invalid password for LDAP bind user"#);
                return Err(Error::AuthenticationError(request.name));
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
                    &&password_hash,
                    &request.password,
                    self.config.get_server_keys().private(),
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
        Err(Error::AuthenticationError(request.name))
    }
}

#[async_trait]
impl OpaqueHandler for SqlOpaqueHandler {
    async fn login_start(
        &self,
        request: login::ClientLoginStartRequest,
    ) -> Result<login::ServerLoginStartResponse> {
        // Fetch the previously registered password file from the DB.
        let password_file_bytes = {
            let query = Query::select()
                .column(Users::PasswordHash)
                .from(Users::Table)
                .and_where(Expr::col(Users::UserId).eq(request.username.as_str()))
                .to_string(DbQueryBuilder {});
            sqlx::query(&query)
                .fetch_one(&self.sql_pool)
                .await?
                .get::<Option<Vec<u8>>, _>(&*Users::PasswordHash.to_string())
                // If no password, always fail.
                .ok_or_else(|| Error::AuthenticationError(request.username.clone()))?
        };
        let password_file = opaque::server::ServerRegistration::deserialize(&password_file_bytes)
            .map_err(|_| {
            Error::InternalError(format!("Corrupted password file for {}", request.username))
        })?;

        let mut rng = rand::rngs::OsRng;
        let start_response = opaque::server::login::start_login(
            &mut rng,
            password_file,
            self.config.get_server_keys().private(),
            request.login_start_request,
        )?;
        let login_attempt_id = generate_random_id(&mut rng);

        {
            // Insert the current login attempt in the DB.
            let query = Query::insert()
                .into_table(LoginAttempts::Table)
                .columns(vec![
                    LoginAttempts::RandomId,
                    LoginAttempts::UserId,
                    LoginAttempts::ServerLoginData,
                    LoginAttempts::Timestamp,
                ])
                .values_panic(vec![
                    login_attempt_id.as_str().into(),
                    request.username.as_str().into(),
                    start_response.state.serialize().into(),
                    chrono::Utc::now().naive_utc().into(),
                ])
                .to_string(DbQueryBuilder {});
            sqlx::query(&query).execute(&self.sql_pool).await?;
        }

        Ok(login::ServerLoginStartResponse {
            login_key: login_attempt_id,
            credential_response: start_response.message,
        })
    }

    async fn login_finish(&self, request: login::ClientLoginFinishRequest) -> Result<String> {
        // Fetch the previous data from this login attempt.
        let row = {
            let query = Query::select()
                .column(LoginAttempts::UserId)
                .column(LoginAttempts::ServerLoginData)
                .from(LoginAttempts::Table)
                .and_where(Expr::col(LoginAttempts::RandomId).eq(request.login_key.as_str()))
                .and_where(
                    Expr::col(LoginAttempts::Timestamp)
                        .gt(chrono::Utc::now().naive_utc() - chrono::Duration::minutes(5)),
                )
                .to_string(DbQueryBuilder {});
            sqlx::query(&query).fetch_one(&self.sql_pool).await?
        };
        let username = row.get::<String, _>(&*LoginAttempts::UserId.to_string());
        let login_data = opaque::server::login::ServerLogin::deserialize(
            &row.get::<Vec<u8>, _>(&*LoginAttempts::ServerLoginData.to_string()),
        )
        .map_err(|_| {
            Error::InternalError(format!(
                "Corrupted login data for user `{}` [id `{}`]",
                username, request.login_key
            ))
        })?;
        // Finish the login: this makes sure the client data is correct, and gives a session key we
        // don't need.
        let _session_key =
            opaque::server::login::finish_login(login_data, request.credential_finalization)?
                .session_key;

        {
            // Login was successful, we can delete the login attempt from the table.
            let delete_query = Query::delete()
                .from_table(LoginAttempts::Table)
                .and_where(Expr::col(LoginAttempts::RandomId).eq(request.login_key))
                .to_string(DbQueryBuilder {});
            sqlx::query(&delete_query).execute(&self.sql_pool).await?;
        }
        Ok(username)
    }

    async fn registration_start(
        &self,
        request: registration::ClientRegistrationStartRequest,
    ) -> Result<registration::ServerRegistrationStartResponse> {
        let mut rng = rand::rngs::OsRng;
        // Generate the server-side key and derive the data to send back.
        let start_response = opaque::server::registration::start_registration(
            &mut rng,
            request.registration_start_request,
            self.config.get_server_keys().public(),
        )?;
        // Unique ID to identify the registration attempt.
        let registration_attempt_id = generate_random_id(&mut rng);
        {
            // Write the registration attempt to the DB for the later turn.
            let query = Query::insert()
                .into_table(RegistrationAttempts::Table)
                .columns(vec![
                    RegistrationAttempts::RandomId,
                    RegistrationAttempts::UserId,
                    RegistrationAttempts::ServerRegistrationData,
                    RegistrationAttempts::Timestamp,
                ])
                .values_panic(vec![
                    registration_attempt_id.as_str().into(),
                    request.username.as_str().into(),
                    start_response.state.serialize().into(),
                    chrono::Utc::now().naive_utc().into(),
                ])
                .to_string(DbQueryBuilder {});
            sqlx::query(&query).execute(&self.sql_pool).await?;
        }
        Ok(registration::ServerRegistrationStartResponse {
            registration_key: registration_attempt_id,
            registration_response: start_response.message,
        })
    }

    async fn registration_finish(
        &self,
        request: registration::ClientRegistrationFinishRequest,
    ) -> Result<()> {
        // Fetch the previous state.
        let row = {
            let query = Query::select()
                .column(RegistrationAttempts::UserId)
                .column(RegistrationAttempts::ServerRegistrationData)
                .from(RegistrationAttempts::Table)
                .and_where(
                    Expr::col(RegistrationAttempts::RandomId).eq(request.registration_key.as_str()),
                )
                .and_where(
                    Expr::col(RegistrationAttempts::Timestamp)
                        .gt(chrono::Utc::now().naive_utc() - chrono::Duration::minutes(5)),
                )
                .to_string(DbQueryBuilder {});
            sqlx::query(&query).fetch_one(&self.sql_pool).await?
        };
        let username = row.get::<String, _>(&*RegistrationAttempts::UserId.to_string());
        let registration_data = opaque::server::registration::ServerRegistration::deserialize(
            &row.get::<Vec<u8>, _>(&*RegistrationAttempts::ServerRegistrationData.to_string()),
        )
        .map_err(|_| {
            Error::InternalError(format!(
                "Corrupted registration data for user `{}` [id `{}`]",
                username, request.registration_key
            ))
        })?;

        let password_file = opaque::server::registration::get_password_file(
            registration_data,
            request.registration_upload,
        )?;
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
        {
            // Delete the registration attempt.
            let delete_query = Query::delete()
                .from_table(RegistrationAttempts::Table)
                .and_where(Expr::col(RegistrationAttempts::RandomId).eq(request.registration_key))
                .to_string(DbQueryBuilder {});
            sqlx::query(&delete_query).execute(&self.sql_pool).await?;
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
                login_key: start_response.login_key,
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
                registration_key: start_response.registration_key,
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
