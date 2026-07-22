use crate::SqlBackendHandler;
use async_trait::async_trait;
use base64::Engine;
use lldap_domain::types::{TotpEnrollmentStart, UserId, Uuid};
use lldap_domain_handlers::handler::MfaBackendHandler;
use lldap_domain_model::{
    error::{DomainError, Result},
    model,
};
use lldap_mfa::MFA_TYPE_TOTP;
use sea_orm::{ActiveModelTrait, ActiveValue, EntityTrait};
use serde::{Deserialize, Serialize};
use tracing::{info, instrument};

// Issuer displayed by authenticator apps for the enrolled account.
const TOTP_ISSUER: &str = "LLDAP";

// Discriminates the sealed pending-state blobs (bincode ignores trailing bytes).
const STATE_KIND_ENROLLMENT: u8 = 1;
const STATE_KIND_LOGIN: u8 = 2;

// Pending enrollment, sealed with the server key until the code is verified.
#[derive(Serialize, Deserialize)]
struct TotpEnrollmentState {
    kind: u8,
    user_id: UserId,
    seed: [u8; lldap_mfa::TOTP_SEED_LEN],
    expiry_unix: i64,
}

// Pending login: the password step succeeded, awaiting the TOTP code.
#[derive(Serialize, Deserialize)]
struct TotpLoginState {
    kind: u8,
    user_id: UserId,
    expiry_unix: i64,
}

impl SqlBackendHandler {
    async fn get_user_uuid(&self, user_id: &UserId) -> Result<Uuid> {
        Ok(model::User::find_by_id(user_id.clone())
            .one(&self.sql_pool)
            .await?
            .ok_or_else(|| DomainError::EntityNotFound(user_id.to_string()))?
            .uuid)
    }

    // Both columns are always written together: no orphan sealed secrets.
    async fn write_mfa_columns(
        &self,
        user_id: &UserId,
        totp_secret: Option<String>,
        mfa_type: Option<String>,
    ) -> Result<()> {
        let now = chrono::Utc::now().naive_utc();
        let user_update = model::users::ActiveModel {
            user_id: ActiveValue::Set(user_id.clone()),
            totp_secret: ActiveValue::Set(totp_secret),
            mfa_type: ActiveValue::Set(mfa_type),
            modified_date: ActiveValue::Set(now),
            ..Default::default()
        };
        user_update.update(&self.sql_pool).await?;
        Ok(())
    }
}

#[async_trait]
impl MfaBackendHandler for SqlBackendHandler {
    #[instrument(skip_all, level = "debug", err)]
    async fn reset_user_mfa(&self, user_id: &UserId) -> Result<()> {
        // Surface missing users as EntityNotFound rather than a bare DB update error.
        let _ = self.get_user_uuid(user_id).await?;
        self.write_mfa_columns(user_id, None, None).await?;
        info!(r#"Cleared MFA state for "{}""#, user_id);
        Ok(())
    }

    #[instrument(skip_all, level = "debug", err)]
    async fn start_totp_enrollment(&self, user_id: &UserId) -> Result<TotpEnrollmentStart> {
        let seed = lldap_mfa::generate_seed();
        let secret_base32 = lldap_mfa::seed_base32(&seed);
        let otpauth_uri = lldap_mfa::otpauth_uri(TOTP_ISSUER, user_id.as_str(), &secret_base32);
        // Nothing is persisted until the user proves possession of the seed.
        let state = TotpEnrollmentState {
            kind: STATE_KIND_ENROLLMENT,
            user_id: user_id.clone(),
            seed,
            // Pending enrollment is valid for 5 minutes.
            expiry_unix: (chrono::Utc::now() + chrono::Duration::minutes(5)).timestamp(),
        };
        let sealed_state = lldap_mfa::seal_enrollment_state(
            self.opaque_setup.keypair().private(),
            &bincode::serialize(&state)?,
        )
        .map_err(|e| DomainError::InternalError(format!("Could not seal enrollment state: {e}")))?;
        Ok(TotpEnrollmentStart {
            otpauth_uri,
            secret_base32,
            state: base64::engine::general_purpose::STANDARD.encode(sealed_state),
        })
    }

    #[instrument(skip_all, level = "debug", err)]
    async fn finish_totp_enrollment(
        &self,
        user_id: &UserId,
        state: &str,
        code: &str,
    ) -> Result<()> {
        let state = lldap_mfa::open_enrollment_state(
            self.opaque_setup.keypair().private(),
            &base64::engine::general_purpose::STANDARD.decode(state)?,
        )
        .map_err(|_| {
            DomainError::InternalError(format!("Corrupted enrollment state for {user_id}"))
        })?;
        let state: TotpEnrollmentState = bincode::deserialize(&state)?;
        if state.kind != STATE_KIND_ENROLLMENT {
            return Err(DomainError::InternalError(format!(
                "Not an enrollment state for {user_id}"
            )));
        }
        if state.user_id != *user_id {
            return Err(DomainError::InternalError(format!(
                "Enrollment state does not belong to {user_id}"
            )));
        }
        let now = chrono::Utc::now();
        if state.expiry_unix < now.timestamp() {
            return Err(DomainError::AuthenticationError(format!(
                "Expired TOTP enrollment for {user_id}"
            )));
        }
        if !lldap_mfa::totp_verify(&state.seed, code, now.timestamp() as u64)
            .map_err(|e| DomainError::InternalError(format!("TOTP verification failed: {e}")))?
        {
            return Err(DomainError::AuthenticationError(format!(
                "Invalid TOTP code for {user_id}"
            )));
        }
        let uuid = self.get_user_uuid(user_id).await?;
        let sealed_secret = lldap_mfa::seal_totp_secret(
            self.opaque_setup.keypair().private(),
            uuid.as_str(),
            &state.seed,
        )
        .map_err(|e| DomainError::InternalError(format!("Could not seal TOTP secret: {e}")))?;
        self.write_mfa_columns(user_id, Some(sealed_secret), Some(MFA_TYPE_TOTP.to_owned()))
            .await?;
        info!(r#"TOTP enrollment completed for "{}""#, user_id);
        Ok(())
    }

    #[instrument(skip_all, level = "debug", err)]
    async fn verify_user_totp(&self, user_id: &UserId, code: &str) -> Result<()> {
        let not_enrolled = || {
            DomainError::AuthenticationError(format!("User {user_id} is not enrolled in TOTP MFA"))
        };
        let user = model::User::find_by_id(user_id.clone())
            .one(&self.sql_pool)
            .await?
            .ok_or_else(not_enrolled)?;
        if user.mfa_type.as_deref() != Some(MFA_TYPE_TOTP) {
            return Err(not_enrolled());
        }
        let sealed = user.totp_secret.ok_or_else(not_enrolled)?;
        // Decrypt failure means the server key changed: require re-enrollment, never a 500.
        let seed = lldap_mfa::open_totp_secret(
            self.opaque_setup.keypair().private(),
            user.uuid.as_str(),
            &sealed,
        )
        .map_err(|_| {
            DomainError::AuthenticationError(format!("TOTP re-enrollment required for {user_id}"))
        })?;
        let now = chrono::Utc::now().timestamp() as u64;
        if !lldap_mfa::totp_verify(&seed, code, now)
            .map_err(|e| DomainError::InternalError(format!("TOTP verification failed: {e}")))?
        {
            return Err(DomainError::AuthenticationError(format!(
                "Invalid TOTP code for {user_id}"
            )));
        }
        Ok(())
    }

    #[instrument(skip_all, level = "debug", err)]
    async fn start_totp_login(&self, user_id: &UserId) -> Result<String> {
        let state = TotpLoginState {
            kind: STATE_KIND_LOGIN,
            user_id: user_id.clone(),
            // The verified password step stays valid for 5 minutes.
            expiry_unix: (chrono::Utc::now() + chrono::Duration::minutes(5)).timestamp(),
        };
        let sealed_state = lldap_mfa::seal_enrollment_state(
            self.opaque_setup.keypair().private(),
            &bincode::serialize(&state)?,
        )
        .map_err(|e| DomainError::InternalError(format!("Could not seal login state: {e}")))?;
        Ok(base64::engine::general_purpose::STANDARD.encode(sealed_state))
    }

    #[instrument(skip_all, level = "debug", err)]
    async fn finish_totp_login(&self, state: &str, code: &str) -> Result<UserId> {
        // All state failures look the same to the caller: an authentication error.
        let invalid_state = || DomainError::AuthenticationError("Invalid login state".to_owned());
        let state = base64::engine::general_purpose::STANDARD
            .decode(state)
            .map_err(|_| invalid_state())?;
        let state = lldap_mfa::open_enrollment_state(self.opaque_setup.keypair().private(), &state)
            .map_err(|_| invalid_state())?;
        let state: TotpLoginState = bincode::deserialize(&state).map_err(|_| invalid_state())?;
        if state.kind != STATE_KIND_LOGIN {
            return Err(invalid_state());
        }
        if state.expiry_unix < chrono::Utc::now().timestamp() {
            return Err(DomainError::AuthenticationError(format!(
                "Expired TOTP login for {}",
                state.user_id
            )));
        }
        self.verify_user_totp(&state.user_id, code).await?;
        Ok(state.user_id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sql_backend_handler::tests::{get_initialized_db, insert_user_no_password};
    use lldap_auth::opaque::server::{ServerSetup, generate_random_private_key};
    use lldap_mfa::{format_code, open_totp_secret, seed_base32, totp_code};
    use pretty_assertions::assert_eq;

    async fn get_mfa_columns(
        handler: &SqlBackendHandler,
        user_id: &str,
    ) -> (Option<String>, Option<String>) {
        let user = model::User::find_by_id(UserId::new(user_id))
            .one(&handler.sql_pool)
            .await
            .unwrap()
            .unwrap();
        (user.totp_secret, user.mfa_type)
    }

    fn open_state(setup: &ServerSetup, state: &str) -> TotpEnrollmentState {
        let bytes = lldap_mfa::open_enrollment_state(
            setup.keypair().private(),
            &base64::engine::general_purpose::STANDARD
                .decode(state)
                .unwrap(),
        )
        .unwrap();
        bincode::deserialize(&bytes).unwrap()
    }

    fn seal_state<T: Serialize>(setup: &ServerSetup, state: &T) -> String {
        let sealed = lldap_mfa::seal_enrollment_state(
            setup.keypair().private(),
            &bincode::serialize(state).unwrap(),
        )
        .unwrap();
        base64::engine::general_purpose::STANDARD.encode(sealed)
    }

    #[tokio::test]
    async fn test_totp_enrollment_flow() {
        let sql_pool = get_initialized_db().await;
        let setup = generate_random_private_key();
        let handler = SqlBackendHandler::new(setup.clone(), sql_pool);
        insert_user_no_password(&handler, "bob").await;
        let user_id = UserId::new("bob");

        let start = handler.start_totp_enrollment(&user_id).await.unwrap();
        assert!(start.otpauth_uri.starts_with("otpauth://totp/"));
        assert!(start.otpauth_uri.contains(&start.secret_base32));
        // No state is persisted before the code is verified.
        assert_eq!(get_mfa_columns(&handler, "bob").await, (None, None));

        let state = open_state(&setup, &start.state);
        assert_eq!(seed_base32(&state.seed), start.secret_base32);
        let now = chrono::Utc::now().timestamp() as u64;
        let code = format_code(totp_code(&state.seed, now).unwrap());
        handler
            .finish_totp_enrollment(&user_id, &start.state, &code)
            .await
            .unwrap();

        let (totp_secret, mfa_type) = get_mfa_columns(&handler, "bob").await;
        let sealed = totp_secret.unwrap();
        assert!(sealed.starts_with("v1."));
        assert_eq!(sealed.len(), 57);
        assert_eq!(mfa_type.as_deref(), Some(MFA_TYPE_TOTP));
        let uuid = handler.get_user_uuid(&user_id).await.unwrap();
        assert_eq!(
            open_totp_secret(setup.keypair().private(), uuid.as_str(), &sealed).unwrap(),
            state.seed
        );
    }

    #[tokio::test]
    async fn test_finish_totp_enrollment_rejected() {
        let sql_pool = get_initialized_db().await;
        let setup = generate_random_private_key();
        let handler = SqlBackendHandler::new(setup.clone(), sql_pool);
        insert_user_no_password(&handler, "bob").await;
        insert_user_no_password(&handler, "john").await;
        let user_id = UserId::new("bob");

        let start = handler.start_totp_enrollment(&user_id).await.unwrap();
        let state = open_state(&setup, &start.state);
        let now = chrono::Utc::now().timestamp() as u64;
        let code = format_code(totp_code(&state.seed, now).unwrap());
        // A code that is valid in none of the accepted time steps.
        let valid: Vec<u32> = [now - 30, now, now + 30]
            .iter()
            .map(|t| totp_code(&state.seed, *t).unwrap())
            .collect();
        let wrong = (0..).find(|c| !valid.contains(c)).unwrap();
        let err = handler
            .finish_totp_enrollment(&user_id, &start.state, &format_code(wrong))
            .await
            .unwrap_err();
        assert!(matches!(err, DomainError::AuthenticationError(_)));
        // A correct code, but an expired pending state.
        let expired = TotpEnrollmentState {
            kind: STATE_KIND_ENROLLMENT,
            user_id: user_id.clone(),
            seed: state.seed,
            expiry_unix: chrono::Utc::now().timestamp() - 1,
        };
        let err = handler
            .finish_totp_enrollment(&user_id, &seal_state(&setup, &expired), &code)
            .await
            .unwrap_err();
        assert!(matches!(err, DomainError::AuthenticationError(_)));
        // A state sealed for another user.
        let err = handler
            .finish_totp_enrollment(&UserId::new("john"), &start.state, &code)
            .await
            .unwrap_err();
        assert!(matches!(err, DomainError::InternalError(_)));
        assert_eq!(get_mfa_columns(&handler, "bob").await, (None, None));
        assert_eq!(get_mfa_columns(&handler, "john").await, (None, None));
    }

    #[tokio::test]
    async fn test_reset_user_mfa() {
        let sql_pool = get_initialized_db().await;
        let setup = generate_random_private_key();
        let handler = SqlBackendHandler::new(setup.clone(), sql_pool);
        insert_user_no_password(&handler, "bob").await;
        let user_id = UserId::new("bob");

        let start = handler.start_totp_enrollment(&user_id).await.unwrap();
        let state = open_state(&setup, &start.state);
        let now = chrono::Utc::now().timestamp() as u64;
        let code = format_code(totp_code(&state.seed, now).unwrap());
        handler
            .finish_totp_enrollment(&user_id, &start.state, &code)
            .await
            .unwrap();
        assert!(get_mfa_columns(&handler, "bob").await.0.is_some());

        handler.reset_user_mfa(&user_id).await.unwrap();
        assert_eq!(get_mfa_columns(&handler, "bob").await, (None, None));
        // Resetting a user without MFA is a no-op, not an error.
        handler.reset_user_mfa(&user_id).await.unwrap();
        // Unknown users surface EntityNotFound.
        let err = handler
            .reset_user_mfa(&UserId::new("nobody"))
            .await
            .unwrap_err();
        assert!(matches!(err, DomainError::EntityNotFound(_)));
    }

    #[tokio::test]
    async fn test_verify_user_totp() {
        let sql_pool = get_initialized_db().await;
        let setup = generate_random_private_key();
        let handler = SqlBackendHandler::new(setup.clone(), sql_pool);
        insert_user_no_password(&handler, "bob").await;
        insert_user_no_password(&handler, "john").await;
        let user_id = UserId::new("bob");
        let start = handler.start_totp_enrollment(&user_id).await.unwrap();
        let state = open_state(&setup, &start.state);
        let now = chrono::Utc::now().timestamp() as u64;
        let code = format_code(totp_code(&state.seed, now).unwrap());
        handler
            .finish_totp_enrollment(&user_id, &start.state, &code)
            .await
            .unwrap();

        handler.verify_user_totp(&user_id, &code).await.unwrap();
        // Wrong code and unenrolled user are authentication errors.
        let valid: Vec<u32> = [now - 30, now, now + 30]
            .iter()
            .map(|t| totp_code(&state.seed, *t).unwrap())
            .collect();
        let wrong = (0..).find(|c| !valid.contains(c)).unwrap();
        let err = handler
            .verify_user_totp(&user_id, &format_code(wrong))
            .await
            .unwrap_err();
        assert!(matches!(err, DomainError::AuthenticationError(_)));
        let err = handler
            .verify_user_totp(&UserId::new("john"), &code)
            .await
            .unwrap_err();
        assert!(matches!(err, DomainError::AuthenticationError(_)));
        // An undecryptable stored blob requires re-enrollment, never a 500.
        handler
            .write_mfa_columns(
                &user_id,
                Some(format!("v1.{}", "A".repeat(54))),
                Some(MFA_TYPE_TOTP.to_owned()),
            )
            .await
            .unwrap();
        let err = handler.verify_user_totp(&user_id, &code).await.unwrap_err();
        assert!(matches!(err, DomainError::AuthenticationError(_)));
        assert!(err.to_string().contains("re-enrollment"));
    }

    #[tokio::test]
    async fn test_totp_login_flow() {
        let sql_pool = get_initialized_db().await;
        let setup = generate_random_private_key();
        let handler = SqlBackendHandler::new(setup.clone(), sql_pool);
        insert_user_no_password(&handler, "bob").await;
        let user_id = UserId::new("bob");
        let start = handler.start_totp_enrollment(&user_id).await.unwrap();
        let state = open_state(&setup, &start.state);
        let now = chrono::Utc::now().timestamp() as u64;
        let code = format_code(totp_code(&state.seed, now).unwrap());
        handler
            .finish_totp_enrollment(&user_id, &start.state, &code)
            .await
            .unwrap();

        let login_state = handler.start_totp_login(&user_id).await.unwrap();
        assert_eq!(
            handler
                .finish_totp_login(&login_state, &code)
                .await
                .unwrap(),
            user_id
        );
        // Expired login state.
        let expired = TotpLoginState {
            kind: STATE_KIND_LOGIN,
            user_id: user_id.clone(),
            expiry_unix: chrono::Utc::now().timestamp() - 1,
        };
        let err = handler
            .finish_totp_login(&seal_state(&setup, &expired), &code)
            .await
            .unwrap_err();
        assert!(matches!(err, DomainError::AuthenticationError(_)));
        // An enrollment state cannot be replayed as a login state, nor can garbage.
        let err = handler
            .finish_totp_login(&start.state, &code)
            .await
            .unwrap_err();
        assert!(matches!(err, DomainError::AuthenticationError(_)));
        let err = handler
            .finish_totp_login("not-base64!", &code)
            .await
            .unwrap_err();
        assert!(matches!(err, DomainError::AuthenticationError(_)));
    }
}
