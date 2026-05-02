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
use lldap_opaque_handler::{OpaqueHandler, login, login_base64, registration};
use sea_orm::{ActiveModelTrait, ActiveValue, EntityTrait, QuerySelect};
use secstr::SecUtf8;
use serde::{Deserialize, Serialize};
use tracing::{debug, info, instrument, warn};

type SqlOpaqueHandler = SqlBackendHandler;

// ---------------------------------------------------------------------------
// Typed protocol version (replaces a raw `i32` magic number).
//
// The DB column stays `i32` for sea-orm compatibility, but every business
// path goes through this enum. Adding a future v5 forces an exhaustive
// `match` to be updated everywhere it matters.
// ---------------------------------------------------------------------------

#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum OpaqueProtocolVersion {
    /// opaque-ke 0.7 password file (pre-RFC-9807). Validated only when a
    /// v0.7 `ServerSetup` is preserved in memory; auto-upgraded to
    /// `Current` on the next successful login.
    V07,
    /// opaque-ke 4.0 password file (RFC 9807-compliant). The current format.
    Current,
}

impl OpaqueProtocolVersion {
    pub const V07_DB_VALUE: i32 = 0;
    pub const CURRENT_DB_VALUE: i32 = 1;

    pub fn from_db(value: i32) -> Self {
        // Anything we don't recognise is conservatively treated as v0.7
        // so we don't accidentally let an unknown future format slip past
        // the validator. The startup migration warning will surface this.
        match value {
            Self::CURRENT_DB_VALUE => Self::Current,
            _ => Self::V07,
        }
    }

    pub fn is_v07(self) -> bool {
        matches!(self, Self::V07)
    }

    pub fn db_value(self) -> i32 {
        match self {
            Self::V07 => Self::V07_DB_VALUE,
            Self::Current => Self::CURRENT_DB_VALUE,
        }
    }
}

// ---------------------------------------------------------------------------
// Opaque-ke 0.7 support for progressive password migration.
//
// Existing passwords stored with opaque-ke 0.7 remain valid. On login,
// if the password version is 0 (v0.7), we validate using the v0.7
// OPAQUE types and then silently re-register the password with v4.0.
// ---------------------------------------------------------------------------

/// Encrypted server state carried across the two round-trips of the v0.7
/// OPAQUE login. Analogous to `login::ServerData` but with v0.7 types.
#[derive(Serialize, Deserialize)]
struct V07ServerData {
    username: UserId,
    server_login: lldap_auth::v07::V07ServerLoginState,
}

/// Validate a password against a v4.0 (current) password file.
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

/// Validate a password against a v0.7 (opaque-ke 0.7) password file.
#[instrument(skip_all, level = "debug", err, fields(username = %username.as_str()))]
fn passwords_match_v07(
    password_file_bytes: &[u8],
    clear_password: &str,
    v07_setup: &lldap_auth::v07::V07ServerSetup,
    username: &UserId,
) -> Result<()> {
    lldap_auth::v07::validate_password(
        password_file_bytes,
        clear_password,
        v07_setup,
        username.as_str(),
    )
    .map_err(DomainError::InternalError)
}

/// In-process validator that runs both sides of an OPAQUE login handshake
/// locally to verify a plaintext password against a stored password file.
/// Used by `bind()` and `simple_login`, where the server has the cleartext
/// password and just needs a yes/no answer (no session key escapes).
enum Validator<'a> {
    /// Current (opaque-ke 4.0) handshake using the v4.0 ServerSetup.
    Current(&'a opaque::server::ServerSetup),
    /// Opaque-ke 0.7 handshake using a deserialized v0.7
    /// ServerSetup. Owned because it's recovered from raw bytes on demand.
    V07(Box<lldap_auth::v07::V07ServerSetup>),
}

impl<'a> Validator<'a> {
    fn validate(&self, password_file: &[u8], cleartext: &str, user: &UserId) -> Result<()> {
        match self {
            Validator::Current(setup) => passwords_match(password_file, cleartext, setup, user),
            Validator::V07(setup) => passwords_match_v07(password_file, cleartext, setup, user),
        }
    }
}

impl SqlBackendHandler {
    fn get_orion_secret_key(&self) -> Result<orion::aead::SecretKey> {
        Ok(orion::aead::SecretKey::from_slice(
            self.opaque_setup.keypair().private().serialize().as_slice(),
        )?)
    }

    /// Encrypt a server-side state object for round-tripping through the
    /// untrusted client between two halves of an OPAQUE handshake. The
    /// orion key is derived from the v4.0 ServerSetup, but the encryption
    /// itself is OPAQUE-version-agnostic (it's just AEAD over bincode).
    fn seal_state<T: Serialize>(&self, state: &T) -> Result<String> {
        let secret_key = self.get_orion_secret_key()?;
        let encrypted = orion::aead::seal(&secret_key, &bincode::serialize(state)?)?;
        Ok(base64::engine::general_purpose::STANDARD.encode(encrypted))
    }

    /// Inverse of `seal_state`.
    fn open_state<T: serde::de::DeserializeOwned>(&self, blob: &str) -> Result<T> {
        let secret_key = self.get_orion_secret_key()?;
        let encrypted = base64::engine::general_purpose::STANDARD.decode(blob)?;
        Ok(bincode::deserialize(&orion::aead::open(
            &secret_key,
            &encrypted,
        )?)?)
    }

    /// Construct the in-process validator appropriate for the given
    /// password version. Returns an error when a user has a v0.7
    /// password but no v0.7 ServerSetup is available (e.g. seed-based
    /// deployments cannot recover the v0.7 key).
    fn validator_for(&self, version: OpaqueProtocolVersion) -> Result<Validator<'_>> {
        match version {
            OpaqueProtocolVersion::Current => Ok(Validator::Current(&self.opaque_setup)),
            OpaqueProtocolVersion::V07 => {
                let bytes = self.v07_server_key_bytes.as_deref().ok_or_else(|| {
                    DomainError::InternalError(
                        "v0.7 password validation requested but no v0.7 server key is loaded"
                            .to_string(),
                    )
                })?;
                let setup =
                    lldap_auth::v07::V07ServerSetup::deserialize(bytes).ok_or_else(|| {
                        DomainError::InternalError(
                            "failed to deserialize the v0.7 server setup".to_string(),
                        )
                    })?;
                Ok(Validator::V07(Box::new(setup)))
            }
        }
    }

    #[instrument(skip(self), level = "debug", err)]
    async fn get_password_file_for_user(
        &self,
        user_id: UserId,
    ) -> Result<Option<(Vec<u8>, OpaqueProtocolVersion)>> {
        // Fetch the previously registered password file and version from the DB.
        Ok(model::User::find_by_id(user_id)
            .select_only()
            .column(UserColumn::PasswordHash)
            .column(UserColumn::PasswordVersion)
            .into_tuple::<(Option<Vec<u8>>, i32)>()
            .one(&self.sql_pool)
            .await?
            .and_then(|(hash, version)| hash.map(|h| (h, OpaqueProtocolVersion::from_db(version)))))
    }

    /// Upgrade a v0.7 password to the current format after successful
    /// validation. The caller must have already verified the password
    /// against the v0.7 `Validator` — this re-runs the full v4.0
    /// registration flow and updates `password_version` in the DB.
    async fn upgrade_password(&self, username: &UserId, password: &str) -> Result<()> {
        info!(
            r#"Upgrading password for "{}" from v0.7 to current format"#,
            username
        );
        register_password(self, username.clone(), &SecUtf8::from(password)).await
    }
}

#[async_trait]
impl LoginHandler for SqlBackendHandler {
    #[instrument(skip_all, level = "debug", err)]
    async fn bind(&self, request: BindRequest) -> Result<()> {
        let auth_error =
            || DomainError::AuthenticationError(format!(r#"for user "{}""#, &request.name));

        let Some((password_hash, version)) = self
            .get_password_file_for_user(request.name.clone())
            .await?
        else {
            debug!(
                r#"User "{}" doesn't exist or has no password"#,
                &request.name
            );
            return Err(auth_error());
        };

        info!(
            r#"Login attempt for "{}" (version={:?})"#,
            &request.name, version
        );

        // Look up the validator for this user's password format. If the user
        // has a v0.7 password but we have no v0.7 server key (e.g. a
        // seed-based deployment, or a fresh install where the v0.7 key was
        // never preserved), the validator construction itself fails.
        let validator = self.validator_for(version).map_err(|e| {
            warn!(r#"No validator available for "{}": {}"#, &request.name, e);
            auth_error()
        })?;

        // Run the OPAQUE handshake locally. A protocol-level failure (wrong
        // password, corrupted file, …) is collapsed into a generic auth
        // error so we don't leak which version the user has.
        validator
            .validate(&password_hash, &request.password, &request.name)
            .map_err(|_| auth_error())?;

        // On a successful v0.7 validation, opportunistically re-register
        // the password in the current format. This is best-effort: a
        // failed upgrade does NOT fail the login — the user is still
        // authenticated, and the upgrade will be retried on the next bind.
        if version.is_v07()
            && let Err(e) = self
                .upgrade_password(&request.name, &request.password)
                .await
        {
            warn!(
                r#"Failed to upgrade password for "{}": {}"#,
                &request.name, e
            );
        }
        Ok(())
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
        let maybe_password_entry = self.get_password_file_for_user(user_id.clone()).await?;

        // If the user has a v0.7 password, reject v4.0 login attempts
        // with a structured error signal. The client detects this error code and
        // retries via /auth/opaque/v07/login/*, which re-registers with v4.0 on
        // success.
        if let Some((_, version)) = maybe_password_entry.as_ref()
            && version.is_v07()
        {
            info!(
                r#"OPAQUE v4.0 login attempted for "{}" with v0.7 password; client should retry via /auth/opaque/v07/login/*"#,
                &user_id
            );
            return Err(DomainError::OpaqueV07Version(user_id.to_string()));
        }

        let maybe_password_file = maybe_password_entry
            .map(|(bytes, _version)| {
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
        let server_data = login::ServerData {
            username: user_id,
            server_login: start_response.state,
        };

        Ok(login::ServerLoginStartResponse {
            server_data: self.seal_state(&server_data)?,
            credential_response: start_response.message,
        })
    }

    #[instrument(skip_all, level = "debug", err)]
    async fn login_finish(&self, request: login::ClientLoginFinishRequest) -> Result<UserId> {
        let login::ServerData {
            username,
            server_login,
        } = self.open_state(&request.server_data)?;
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
    async fn login_start_v07(
        &self,
        request: login_base64::ClientLoginStartRequest,
    ) -> Result<login_base64::ServerLoginStartResponse> {
        let user_id = request.username;
        info!(r#"v0.7 OPAQUE login attempt for "{}""#, &user_id);

        // Recover the v0.7 ServerSetup. This fails fast on seed-based or
        // fresh deployments where no v0.7 key was preserved.
        let v07_setup = match self.validator_for(OpaqueProtocolVersion::V07)? {
            Validator::V07(setup) => *setup,
            // `validator_for(V07)` only returns Validator::V07, but
            // matches must be exhaustive.
            Validator::Current(_) => unreachable!("validator_for(V07) must return V07"),
        };

        // Decode the client's CredentialRequest bytes.
        let credential_request_bytes =
            base64::engine::general_purpose::STANDARD.decode(&request.login_start_request)?;

        // Fetch the user's password file. Only v0.7 passwords are handled
        // here — a current-version user routed to this endpoint is rejected.
        let maybe_password_bytes = match self.get_password_file_for_user(user_id.clone()).await? {
            Some((bytes, OpaqueProtocolVersion::V07)) => Some(bytes),
            Some((_, OpaqueProtocolVersion::Current)) => {
                return Err(DomainError::AuthenticationError(format!(
                    r#"user "{}" does not have a v0.7 password"#,
                    user_id
                )));
            }
            None => None, // Dummy handshake (user doesn't exist).
        };

        let (server_login_state, response_bytes) = lldap_auth::v07::server_login_start(
            &v07_setup,
            &credential_request_bytes,
            maybe_password_bytes.as_deref(),
            user_id.as_str(),
        )
        .map_err(DomainError::InternalError)?;

        // Encrypt the server state. The orion key is derived from the v4.0
        // ServerSetup but the encryption is OPAQUE-version-agnostic — it's
        // just AEAD over bincode.
        let server_data = V07ServerData {
            username: user_id,
            server_login: server_login_state,
        };

        Ok(login_base64::ServerLoginStartResponse {
            server_data: self.seal_state(&server_data)?,
            credential_response: base64::engine::general_purpose::STANDARD.encode(response_bytes),
        })
    }

    #[instrument(skip_all, level = "debug", err)]
    async fn login_finish_v07(
        &self,
        request: login_base64::ClientLoginFinishRequest,
    ) -> Result<UserId> {
        let V07ServerData {
            username,
            server_login,
        } = self.open_state(&request.server_data)?;

        // Decode the client's CredentialFinalization bytes.
        let credential_finalization_bytes =
            base64::engine::general_purpose::STANDARD.decode(&request.credential_finalization)?;

        match lldap_auth::v07::server_login_finish(server_login, &credential_finalization_bytes) {
            Ok(()) => {
                info!(
                    r#"v0.7 OPAQUE login successful for "{}" — client should now re-register the password"#,
                    &username
                );
            }
            Err(e) => {
                warn!(r#"v0.7 OPAQUE login attempt failed for "{}""#, &username);
                return Err(DomainError::AuthenticationError(e));
            }
        }

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
        let server_data = registration::ServerData {
            username: request.username,
        };
        Ok(registration::ServerRegistrationStartResponse {
            server_data: self.seal_state(&server_data)?,
            registration_response: start_response.message,
        })
    }

    #[instrument(skip_all, level = "debug", err)]
    async fn registration_finish(
        &self,
        request: registration::ClientRegistrationFinishRequest,
    ) -> Result<()> {
        let registration::ServerData { username } = self.open_state(&request.server_data)?;

        let password_file =
            opaque::server::registration::get_password_file(request.registration_upload);
        // Set the user password to the new password — always in the current format.
        let now = chrono::Utc::now().naive_utc();
        let user_update = model::users::ActiveModel {
            user_id: ActiveValue::Set(username.clone()),
            password_hash: ActiveValue::Set(Some(password_file.serialize().to_vec())),
            password_version: ActiveValue::Set(OpaqueProtocolVersion::Current.db_value()),
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
        let backend_handler = SqlBackendHandler::new(generate_random_private_key(), None, sql_pool);
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
        let handler = SqlOpaqueHandler::new(generate_random_private_key(), None, sql_pool.clone());
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
        let handler = SqlBackendHandler::new(generate_random_private_key(), None, sql_pool.clone());
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
        let handler = SqlBackendHandler::new(generate_random_private_key(), None, sql_pool);
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
        let handler = SqlBackendHandler::new(generate_random_private_key(), None, sql_pool);
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
        let password_file = opaque::server::registration::get_password_file(client_finish.message);

        let bytes = password_file.serialize().to_vec();
        assert!(
            opaque::server::ServerRegistration::deserialize(&bytes).is_ok(),
            "New format should roundtrip successfully"
        );
    }

    #[test]
    fn test_v07_format_compat() {
        // v0.7 password files deserialize with opaque-ke 4.0 (layout-compatible).
        let (bytes, _) =
            lldap_auth::v07::create_test_password_file("legacyuser", "legacy_password");

        // The binary format of ServerRegistration is compatible: Ristretto255
        // group elements are serialized the same way in both versions.
        assert!(
            opaque::server::ServerRegistration::deserialize(&bytes).is_ok(),
            "v0.7 ServerRegistration should be parseable by opaque-ke 4.0"
        );
        // Also detected as v0.7 (both formats parse).
        assert!(
            lldap_auth::v07::is_v07_format(&bytes),
            "Should also be detectable as v0.7 format"
        );
    }

    /// Helper: create a v0.7 (opaque-ke 0.7) password file for the given user.
    /// Delegates to `lldap_auth::v07::create_test_password_file`.
    fn create_v07_password_file(username: &str, password: &str) -> (Vec<u8>, Vec<u8>) {
        lldap_auth::v07::create_test_password_file(username, password)
    }

    #[tokio::test]
    async fn test_v07_bind_auto_upgrade() {
        // End-to-end test: v0.7 password → LDAP bind succeeds
        // → password is auto-upgraded to v4.0 → bind still works.
        let sql_pool = get_initialized_db().await;
        crate::logging::init_for_tests();
        let new_setup = generate_random_private_key();

        // Create a v0.7 password file, simulating what opaque-ke 0.7 would have stored.
        let (v07_password_bytes, v07_setup_bytes) =
            create_v07_password_file("legacy_user", "my_legacy_password");

        let handler = SqlBackendHandler::new(new_setup, Some(v07_setup_bytes), sql_pool.clone());

        // Create user with no password.
        insert_user_no_password(&handler, "legacy_user").await;

        // Write the v0.7 password file directly into the DB with version 0.
        let now = chrono::Utc::now().naive_utc();
        let user_update = model::users::ActiveModel {
            user_id: ActiveValue::Set(UserId::new("legacy_user")),
            password_hash: ActiveValue::Set(Some(v07_password_bytes)),
            password_version: ActiveValue::Set(OpaqueProtocolVersion::V07.db_value()),
            password_modified_date: ActiveValue::Set(now),
            modified_date: ActiveValue::Set(now),
            ..Default::default()
        };
        user_update.update(&sql_pool).await.unwrap();

        // LDAP bind with the correct v0.7 password.
        // The handler should validate with v0.7 setup, then auto-upgrade to v4.0.
        handler
            .bind(BindRequest {
                name: UserId::new("legacy_user"),
                password: "my_legacy_password".to_string(),
            })
            .await
            .expect("v0.7 bind should succeed");

        // Verify the password was auto-upgraded to v4.0 (password_version = 1).
        let upgraded = handler
            .get_password_file_for_user(UserId::new("legacy_user"))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            upgraded.1,
            OpaqueProtocolVersion::Current,
            "Password should be auto-upgraded to version 1 after successful v0.7 bind"
        );

        // Verify the new (v4.0) password file works via a second bind.
        handler
            .bind(BindRequest {
                name: UserId::new("legacy_user"),
                password: "my_legacy_password".to_string(),
            })
            .await
            .expect("Bind with upgraded v4.0 password should succeed");

        // Wrong password still fails.
        handler
            .bind(BindRequest {
                name: UserId::new("legacy_user"),
                password: "wrong_password".to_string(),
            })
            .await
            .expect_err("Wrong password should fail");
    }

    #[tokio::test]
    async fn test_v07_bind_wrong_password() {
        // Wrong password against a v0.7 file should fail without upgrading.
        let sql_pool = get_initialized_db().await;
        crate::logging::init_for_tests();
        let new_setup = generate_random_private_key();

        let (v07_password_bytes, v07_setup_bytes) =
            create_v07_password_file("legacy_user", "correct_password");

        let handler = SqlBackendHandler::new(new_setup, Some(v07_setup_bytes), sql_pool.clone());
        insert_user_no_password(&handler, "legacy_user").await;

        let now = chrono::Utc::now().naive_utc();
        let user_update = model::users::ActiveModel {
            user_id: ActiveValue::Set(UserId::new("legacy_user")),
            password_hash: ActiveValue::Set(Some(v07_password_bytes)),
            password_version: ActiveValue::Set(OpaqueProtocolVersion::V07.db_value()),
            password_modified_date: ActiveValue::Set(now),
            modified_date: ActiveValue::Set(now),
            ..Default::default()
        };
        user_update.update(&sql_pool).await.unwrap();

        handler
            .bind(BindRequest {
                name: UserId::new("legacy_user"),
                password: "wrong_password".to_string(),
            })
            .await
            .expect_err("Wrong v0.7 password should fail");

        // Version should still be 0 (no upgrade on failure).
        let entry = handler
            .get_password_file_for_user(UserId::new("legacy_user"))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            entry.1,
            OpaqueProtocolVersion::V07,
            "Failed bind should not upgrade the password"
        );
    }

    #[tokio::test]
    async fn test_new_registration_sets_v1() {
        // A fresh registration via register_password should set password_version = 1.
        let sql_pool = get_initialized_db().await;
        crate::logging::init_for_tests();
        let handler = SqlBackendHandler::new(generate_random_private_key(), None, sql_pool.clone());
        insert_user_no_password(&handler, "fresh_user").await;

        register_password(
            &handler,
            UserId::new("fresh_user"),
            &SecUtf8::from("fresh_password"),
        )
        .await
        .unwrap();

        let entry = handler
            .get_password_file_for_user(UserId::new("fresh_user"))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            entry.1,
            OpaqueProtocolVersion::Current,
            "Fresh registration should set password_version = 1"
        );

        // Bind should work.
        handler
            .bind(BindRequest {
                name: UserId::new("fresh_user"),
                password: "fresh_password".to_string(),
            })
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn test_mixed_users_both_bind() {
        // One v0.7 user, one v4.0 user, both can bind.
        let sql_pool = get_initialized_db().await;
        crate::logging::init_for_tests();
        let new_setup = generate_random_private_key();

        let (v07_password_bytes, v07_setup_bytes) =
            create_v07_password_file("legacy_alice", "alice_password");

        let handler = SqlBackendHandler::new(new_setup, Some(v07_setup_bytes), sql_pool.clone());

        // v0.7 user.
        insert_user_no_password(&handler, "legacy_alice").await;
        let now = chrono::Utc::now().naive_utc();
        model::users::ActiveModel {
            user_id: ActiveValue::Set(UserId::new("legacy_alice")),
            password_hash: ActiveValue::Set(Some(v07_password_bytes)),
            password_version: ActiveValue::Set(OpaqueProtocolVersion::V07.db_value()),
            password_modified_date: ActiveValue::Set(now),
            modified_date: ActiveValue::Set(now),
            ..Default::default()
        }
        .update(&sql_pool)
        .await
        .unwrap();

        // Current v4.0 user.
        insert_user_no_password(&handler, "new_bob").await;
        register_password(
            &handler,
            UserId::new("new_bob"),
            &SecUtf8::from("bob_password"),
        )
        .await
        .unwrap();

        // Both can bind.
        handler
            .bind(BindRequest {
                name: UserId::new("legacy_alice"),
                password: "alice_password".to_string(),
            })
            .await
            .expect("v0.7 user should bind");
        handler
            .bind(BindRequest {
                name: UserId::new("new_bob"),
                password: "bob_password".to_string(),
            })
            .await
            .expect("New user should bind");
    }

    // ---------------------------------------------------------------------
    // v0.7 OPAQUE login flow tests (Phase 5 integration tests at the
    // handler level — faster and more reliable than a full-server fixture).
    // ---------------------------------------------------------------------

    #[tokio::test]
    async fn test_opaque_login_start_returns_v07_version_error() {
        // A user with password_version = 0 should get OpaqueV07Version on v4.0 login_start.
        let sql_pool = get_initialized_db().await;
        crate::logging::init_for_tests();
        let new_setup = generate_random_private_key();

        let (v07_password_bytes, v07_setup_bytes) =
            create_v07_password_file("legacy_user", "my_password");

        let handler = SqlBackendHandler::new(new_setup, Some(v07_setup_bytes), sql_pool.clone());
        insert_user_no_password(&handler, "legacy_user").await;

        let now = chrono::Utc::now().naive_utc();
        model::users::ActiveModel {
            user_id: ActiveValue::Set(UserId::new("legacy_user")),
            password_hash: ActiveValue::Set(Some(v07_password_bytes)),
            password_version: ActiveValue::Set(OpaqueProtocolVersion::V07.db_value()),
            password_modified_date: ActiveValue::Set(now),
            modified_date: ActiveValue::Set(now),
            ..Default::default()
        }
        .update(&sql_pool)
        .await
        .unwrap();

        // Build a v4.0 login start request — the server should reject it with
        // DomainError::OpaqueV07Version before even attempting the handshake.
        let mut rng = rand::rngs::OsRng;
        let client_start = opaque::client::login::start_login("my_password", &mut rng).unwrap();
        let req = login::ClientLoginStartRequest {
            username: UserId::new("legacy_user"),
            login_start_request: client_start.message,
        };
        let result = handler.login_start(req).await;
        match result {
            Ok(_) => panic!("Expected OpaqueV07Version error, got Ok"),
            Err(DomainError::OpaqueV07Version(ref u)) => assert_eq!(u, "legacy_user"),
            Err(other) => panic!("Expected OpaqueV07Version error, got {:?}", other),
        }
    }

    #[tokio::test]
    async fn test_v07_opaque_login_full_flow() {
        // Full v0.7 login handshake: start -> finish -> returns username.
        // Then re-register via v4.0 -> password_version becomes 1.
        use base64::Engine;
        let sql_pool = get_initialized_db().await;
        crate::logging::init_for_tests();
        let new_setup = generate_random_private_key();

        let (v07_password_bytes, v07_setup_bytes) =
            create_v07_password_file("legacy_alice", "alice_password");

        let handler = SqlBackendHandler::new(new_setup, Some(v07_setup_bytes), sql_pool.clone());
        insert_user_no_password(&handler, "legacy_alice").await;

        let now = chrono::Utc::now().naive_utc();
        model::users::ActiveModel {
            user_id: ActiveValue::Set(UserId::new("legacy_alice")),
            password_hash: ActiveValue::Set(Some(v07_password_bytes)),
            password_version: ActiveValue::Set(OpaqueProtocolVersion::V07.db_value()),
            password_modified_date: ActiveValue::Set(now),
            modified_date: ActiveValue::Set(now),
            ..Default::default()
        }
        .update(&sql_pool)
        .await
        .unwrap();

        // Step 1: client-side v0.7 start_login.
        let (v07_client_state, v07_request_bytes) =
            lldap_auth::v07::client_login_start("alice_password").unwrap();
        let req = login_base64::ClientLoginStartRequest {
            username: UserId::new("legacy_alice"),
            login_start_request: base64::engine::general_purpose::STANDARD
                .encode(&v07_request_bytes),
        };

        // Step 2: server v0.7 login_start.
        let start_response = handler.login_start_v07(req).await.unwrap();

        // Step 3: client-side v0.7 finish_login.
        let server_response_bytes = base64::engine::general_purpose::STANDARD
            .decode(&start_response.credential_response)
            .unwrap();
        let finalization_bytes =
            lldap_auth::v07::client_login_finish(v07_client_state, &server_response_bytes).unwrap();
        let finish_req = login_base64::ClientLoginFinishRequest {
            server_data: start_response.server_data,
            credential_finalization: base64::engine::general_purpose::STANDARD
                .encode(&finalization_bytes),
        };

        // Step 4: server v0.7 login_finish — validates the password.
        let username = handler.login_finish_v07(finish_req).await.unwrap();
        assert_eq!(username.as_str(), "legacy_alice");

        // Step 5: simulate the client's post-login re-registration (this is
        // what the WASM client does after a successful v0.7 login).
        // password_version should still be 0 at this point.
        let before = handler
            .get_password_file_for_user(UserId::new("legacy_alice"))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            before.1,
            OpaqueProtocolVersion::V07,
            "Should still be v0.7 before re-registration"
        );

        // Re-register using the convenience function (mirrors what the
        // client does via /opaque/register/{start,finish}).
        register_password(
            &handler,
            UserId::new("legacy_alice"),
            &SecUtf8::from("alice_password"),
        )
        .await
        .unwrap();

        // Step 6: verify the password is now v4.0.
        let after = handler
            .get_password_file_for_user(UserId::new("legacy_alice"))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            after.1,
            OpaqueProtocolVersion::Current,
            "Should be v4.0 after re-registration"
        );

        // Step 7: v4.0 login_start no longer returns OpaqueV07Version.
        let mut rng = rand::rngs::OsRng;
        let client_v4 = opaque::client::login::start_login("alice_password", &mut rng).unwrap();
        let v4_req = login::ClientLoginStartRequest {
            username: UserId::new("legacy_alice"),
            login_start_request: client_v4.message,
        };
        assert!(
            handler.login_start(v4_req).await.is_ok(),
            "v4.0 login_start should now succeed"
        );
    }

    #[tokio::test]
    async fn test_v07_login_wrong_password_fails() {
        // A wrong password on the v0.7 endpoint should fail validation.
        use base64::Engine;
        let sql_pool = get_initialized_db().await;
        crate::logging::init_for_tests();
        let new_setup = generate_random_private_key();

        let (v07_password_bytes, v07_setup_bytes) =
            create_v07_password_file("legacy_user", "correct_password");

        let handler = SqlBackendHandler::new(new_setup, Some(v07_setup_bytes), sql_pool.clone());
        insert_user_no_password(&handler, "legacy_user").await;

        let now = chrono::Utc::now().naive_utc();
        model::users::ActiveModel {
            user_id: ActiveValue::Set(UserId::new("legacy_user")),
            password_hash: ActiveValue::Set(Some(v07_password_bytes)),
            password_version: ActiveValue::Set(OpaqueProtocolVersion::V07.db_value()),
            password_modified_date: ActiveValue::Set(now),
            modified_date: ActiveValue::Set(now),
            ..Default::default()
        }
        .update(&sql_pool)
        .await
        .unwrap();

        // Client uses the WRONG password.
        let (v07_client_state, v07_request_bytes) =
            lldap_auth::v07::client_login_start("wrong_password").unwrap();
        let req = login_base64::ClientLoginStartRequest {
            username: UserId::new("legacy_user"),
            login_start_request: base64::engine::general_purpose::STANDARD
                .encode(&v07_request_bytes),
        };
        let start_response = handler.login_start_v07(req).await.unwrap();

        // Client finishes with the wrong password — the server should reject it.
        let server_response_bytes = base64::engine::general_purpose::STANDARD
            .decode(&start_response.credential_response)
            .unwrap();
        // The client-side finish may fail (wrong password can't complete the
        // OPAQUE handshake), or it may succeed locally and then the server
        // rejects it. Either outcome is a failure — i.e. no upgrade.
        if let Ok(finalization_bytes) =
            lldap_auth::v07::client_login_finish(v07_client_state, &server_response_bytes)
        {
            let finish_req = login_base64::ClientLoginFinishRequest {
                server_data: start_response.server_data,
                credential_finalization: base64::engine::general_purpose::STANDARD
                    .encode(&finalization_bytes),
            };
            assert!(
                handler.login_finish_v07(finish_req).await.is_err(),
                "Wrong password should not complete v0.7 login"
            );
        }

        // Version must still be 0.
        let entry = handler
            .get_password_file_for_user(UserId::new("legacy_user"))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(entry.1, OpaqueProtocolVersion::V07);
    }

    #[tokio::test]
    async fn test_v07_login_rejected_for_v4_user() {
        // A user with password_version = 1 should be rejected by the v0.7 endpoint.
        use base64::Engine;
        let sql_pool = get_initialized_db().await;
        crate::logging::init_for_tests();
        let new_setup = generate_random_private_key();

        // The v0.7 setup is not strictly needed for this test, but is
        // provided to exercise the full code path.
        let (_, v07_setup_bytes) = create_v07_password_file("unused", "unused");
        let handler = SqlBackendHandler::new(new_setup, Some(v07_setup_bytes), sql_pool.clone());

        // Register a fresh v4.0 user.
        insert_user_no_password(&handler, "new_user").await;
        register_password(
            &handler,
            UserId::new("new_user"),
            &SecUtf8::from("new_password"),
        )
        .await
        .unwrap();

        // Try to log in via the v0.7 endpoint — should fail because the
        // user has password_version = 1.
        let (_v07_client_state, v07_request_bytes) =
            lldap_auth::v07::client_login_start("new_password").unwrap();
        let req = login_base64::ClientLoginStartRequest {
            username: UserId::new("new_user"),
            login_start_request: base64::engine::general_purpose::STANDARD
                .encode(&v07_request_bytes),
        };
        assert!(
            handler.login_start_v07(req).await.is_err(),
            "v0.7 login should reject v4.0 users"
        );
    }
}
