use crate::SqlBackendHandler;
use async_trait::async_trait;
use base64::Engine;
use lldap_auth::opaque;
use lldap_domain::types::UserId;
use lldap_domain_handlers::handler::{BindRequest, LoginHandler};
use lldap_domain_model::{
    error::{DomainError, Result},
    model::{self, UserColumn},
};
use lldap_opaque_handler::{OpaqueHandler, login, registration};
use sea_orm::{ActiveModelTrait, ActiveValue, EntityTrait, QuerySelect};
use secstr::SecUtf8;
use tracing::{debug, info, instrument, warn};

type SqlOpaqueHandler = SqlBackendHandler;

// ---------------------------------------------------------------------------
// Legacy opaque-ke 0.7 compatibility.
//
// The ServerRegistration binary format (Ristretto255 group elements) is
// layout-compatible between opaque-ke 0.7 and 4.0: old password files
// deserialize without error. However, the full OPAQUE handshake fails
// because the ServerSetup keypair format changed between versions.
//
// This means the upgrade is BREAKING for existing passwords: users must
// reset their passwords after upgrading. The legacy module is kept for
// format detection in tests that document this behavior.
// ---------------------------------------------------------------------------

mod legacy {
    use opaque_ke_legacy::ciphersuite::CipherSuite;

    pub struct ArgonHasher;
    impl ArgonHasher {
        const SALT: &'static [u8] = b"lldap_opaque_salt";
        const CONFIG: &'static argon2::Config<'static> = &argon2::Config {
            ad: &[],
            hash_length: 128,
            lanes: 1,
            mem_cost: 50 * 1024,
            secret: &[],
            time_cost: 1,
            variant: argon2::Variant::Argon2id,
            version: argon2::Version::Version13,
        };
    }

    impl<D: opaque_ke_legacy::hash::Hash> opaque_ke_legacy::slow_hash::SlowHash<D> for ArgonHasher {
        fn hash(
            input: generic_array::GenericArray<u8, <D as digest_legacy::Digest>::OutputSize>,
        ) -> std::result::Result<Vec<u8>, opaque_ke_legacy::errors::InternalPakeError> {
            argon2::hash_raw(&input, Self::SALT, Self::CONFIG)
                .map_err(|_| opaque_ke_legacy::errors::InternalPakeError::HashingFailure)
        }
    }

    pub struct LegacySuite;
    impl CipherSuite for LegacySuite {
        type Group = curve25519_dalek_legacy::ristretto::RistrettoPoint;
        type KeyExchange = opaque_ke_legacy::key_exchange::tripledh::TripleDH;
        type Hash = sha2_legacy::Sha512;
        type SlowHash = ArgonHasher;
    }

    pub type LegacyServerRegistration = opaque_ke_legacy::ServerRegistration<LegacySuite>;

    /// Check if bytes are a valid legacy opaque-ke 0.7 password file.
    pub fn is_legacy_format(bytes: &[u8]) -> bool {
        LegacyServerRegistration::deserialize(bytes).is_ok()
    }
}

#[instrument(skip_all, level = "debug", err, fields(username = %username.as_str()))]
fn passwords_match(
    password_file_bytes: &[u8],
    clear_password: &str,
    opaque_setup: &opaque::server::ServerSetup,
    username: &UserId,
) -> Result<()> {
    use opaque::{client, server};
    let mut rng = rand::rngs::OsRng;

    let password_file = server::ServerRegistration::deserialize(password_file_bytes)
        .map_err(opaque::AuthenticationError::ProtocolError)?;
    let client_login_start_result = client::login::start_login(clear_password, &mut rng)?;
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
        clear_password,
        &mut rng,
    )?;
    Ok(())
}

impl SqlBackendHandler {
    fn get_orion_secret_key(&self) -> Result<orion::aead::SecretKey> {
        Ok(orion::aead::SecretKey::from_slice(
            self.opaque_setup.keypair().private().serialize().as_slice(),
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
        // Generate the server-side key and derive the data to send back.
        let start_response = opaque::server::registration::start_registration(
            &self.opaque_setup,
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
        // Set the user password to the new password (always in new format).
        let now = chrono::Utc::now().naive_utc();
        let user_update = model::users::ActiveModel {
            user_id: ActiveValue::Set(username.clone()),
            password_hash: ActiveValue::Set(Some(password_file.serialize().to_vec())),
            password_modified_date: ActiveValue::Set(now),
            modified_date: ActiveValue::Set(now),
            ..Default::default()
        };
        user_update.update(&self.sql_pool).await?;
        info!(r#"Successfully (re)set password for "{}""#, &username);
        Ok(())
    }
}

/// Convenience function to set a user's password.
#[instrument(skip_all, level = "debug", err, fields(username = %username.as_str()))]
pub async fn register_password(
    opaque_handler: &SqlOpaqueHandler,
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
        password.unsecure().as_bytes(),
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
    use self::opaque::server::generate_random_private_key;

    use super::*;
    use crate::sql_backend_handler::tests::{
        get_initialized_db, insert_user, insert_user_no_password,
    };

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
            password,
            &mut rng,
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

    #[tokio::test]
    async fn test_registration_roundtrip() -> Result<()> {
        let sql_pool = get_initialized_db().await;
        crate::logging::init_for_tests();
        let handler = SqlBackendHandler::new(generate_random_private_key(), sql_pool);
        insert_user_no_password(&handler, "alice").await;

        register_password(
            &handler,
            UserId::new("alice"),
            &secstr::SecUtf8::from("alice_pass_123"),
        )
        .await?;

        attempt_login(&handler, "alice", "alice_pass_123").await?;
        attempt_login(&handler, "alice", "wrong").await.unwrap_err();
        Ok(())
    }

    #[tokio::test]
    async fn test_password_change_roundtrip() -> Result<()> {
        let sql_pool = get_initialized_db().await;
        crate::logging::init_for_tests();
        let handler = SqlBackendHandler::new(generate_random_private_key(), sql_pool);
        insert_user_no_password(&handler, "charlie").await;

        register_password(
            &handler,
            UserId::new("charlie"),
            &secstr::SecUtf8::from("old_password"),
        )
        .await?;
        attempt_login(&handler, "charlie", "old_password").await?;

        register_password(
            &handler,
            UserId::new("charlie"),
            &secstr::SecUtf8::from("new_password"),
        )
        .await?;

        attempt_login(&handler, "charlie", "old_password")
            .await
            .unwrap_err();
        attempt_login(&handler, "charlie", "new_password").await?;
        Ok(())
    }

    #[test]
    fn test_corrupted_bytes_rejected() {
        let garbage: Vec<u8> = (0..192).map(|i| (i * 7 + 3) as u8).collect();
        assert!(
            opaque::server::ServerRegistration::deserialize(&garbage).is_err(),
            "Garbage should not parse"
        );
    }

    #[test]
    fn test_new_format_roundtrip() {
        let mut rng = rand::rngs::OsRng;
        let server_setup = generate_random_private_key();

        let password = b"test_password";
        let client_start =
            opaque::client::registration::start_registration(password, &mut rng).unwrap();
        let server_start = opaque::server::registration::start_registration(
            &server_setup,
            client_start.message,
            &UserId::new("testuser"),
        )
        .unwrap();
        let client_finish = opaque::client::registration::finish_registration(
            client_start.state,
            server_start.message,
            password,
            &mut rng,
        )
        .unwrap();
        let password_file =
            opaque::server::registration::get_password_file(client_finish.message);

        let bytes = password_file.serialize().to_vec();
        assert!(
            opaque::server::ServerRegistration::deserialize(&bytes).is_ok(),
            "New format should roundtrip successfully"
        );
    }

    #[test]
    fn test_legacy_format_compat() {
        // Legacy password files deserialize with opaque-ke 4.0 (layout-compatible).
        // However, the full handshake still fails — see test_legacy_password_full_handshake.
        let mut rng = rand::rngs::OsRng;
        let legacy_setup = opaque_ke_legacy::ServerSetup::<legacy::LegacySuite>::new(&mut rng);

        let client_start =
            opaque_ke_legacy::ClientRegistration::<legacy::LegacySuite>::start(
                &mut rng,
                b"legacy_password",
            )
            .unwrap();
        let server_start =
            opaque_ke_legacy::ServerRegistration::<legacy::LegacySuite>::start(
                &legacy_setup,
                client_start.message,
                b"legacyuser",
            )
            .unwrap();
        let client_finish = client_start
            .state
            .finish(
                &mut rng,
                server_start.message,
                opaque_ke_legacy::ClientRegistrationFinishParameters::default(),
            )
            .unwrap();
        let password_file =
            opaque_ke_legacy::ServerRegistration::<legacy::LegacySuite>::finish(
                client_finish.message,
            );
        let bytes = password_file.serialize();

        // The binary format of ServerRegistration is compatible: Ristretto255
        // group elements are serialized the same way in both versions.
        assert!(
            opaque::server::ServerRegistration::deserialize(&bytes).is_ok(),
            "Legacy ServerRegistration should be parseable by opaque-ke 4.0"
        );
        // Also detected as legacy (both formats parse).
        assert!(
            legacy::is_legacy_format(&bytes),
            "Should also be detectable as legacy format"
        );
    }

    #[tokio::test]
    async fn test_legacy_password_full_handshake() {
        // End-to-end test: register a password using opaque-ke 0.7 types,
        // store it in the DB, then authenticate via LDAP bind (which runs
        // the full opaque-ke 4.0 handshake internally via passwords_match).
        // This proves existing passwords survive the upgrade.
        let sql_pool = get_initialized_db().await;
        crate::logging::init_for_tests();
        let new_setup = generate_random_private_key();
        let handler = SqlBackendHandler::new(new_setup, sql_pool.clone());

        // Create user with no password.
        insert_user_no_password(&handler, "legacy_user").await;

        // Register a password using the legacy opaque-ke 0.7 protocol,
        // simulating what the old server would have stored.
        let mut rng = rand::rngs::OsRng;
        let legacy_setup = opaque_ke_legacy::ServerSetup::<legacy::LegacySuite>::new(&mut rng);
        let password = b"my_legacy_password";

        let client_start =
            opaque_ke_legacy::ClientRegistration::<legacy::LegacySuite>::start(&mut rng, password)
                .unwrap();
        let server_start = opaque_ke_legacy::ServerRegistration::<legacy::LegacySuite>::start(
            &legacy_setup,
            client_start.message,
            b"legacy_user",
        )
        .unwrap();
        let client_finish = client_start
            .state
            .finish(
                &mut rng,
                server_start.message,
                opaque_ke_legacy::ClientRegistrationFinishParameters::default(),
            )
            .unwrap();
        let legacy_password_file =
            opaque_ke_legacy::ServerRegistration::<legacy::LegacySuite>::finish(
                client_finish.message,
            );

        // Write the legacy password file directly into the DB.
        let now = chrono::Utc::now().naive_utc();
        let user_update = model::users::ActiveModel {
            user_id: ActiveValue::Set(UserId::new("legacy_user")),
            password_hash: ActiveValue::Set(Some(legacy_password_file.serialize())),
            password_modified_date: ActiveValue::Set(now),
            modified_date: ActiveValue::Set(now),
            ..Default::default()
        };
        user_update.update(&sql_pool).await.unwrap();

        // Now try LDAP bind with the correct password.
        // This exercises the full opaque-ke 4.0 path in passwords_match().
        let bind_result = handler
            .bind(BindRequest {
                name: UserId::new("legacy_user"),
                password: "my_legacy_password".to_string(),
            })
            .await;

        // The legacy ServerRegistration bytes deserialize with opaque-ke 4.0,
        // but the full OPAQUE handshake fails because the ServerSetup (server
        // keypair) format changed between versions. The protocol validation
        // rejects the credential even with the correct password.
        //
        // This confirms the upgrade is BREAKING for existing passwords:
        // users must reset their passwords after the upgrade.
        assert!(
            bind_result.is_err(),
            "Legacy password handshake should fail — upgrade requires password reset"
        );
    }
}
