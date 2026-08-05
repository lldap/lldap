use crate::SqlBackendHandler;
use async_trait::async_trait;
use lldap_domain::types::{MFA_TYPE_TOTP, TotpEnrollmentStart, UserId, Uuid};
use lldap_domain_handlers::handler::MfaBackendHandler;
use lldap_domain_model::{
    error::{DomainError, Result},
    model,
};
use lldap_mfa::{
    MfaError, TOTP_CODE_ALREADY_USED, TOTP_CURRENT_CODE_REQUIRED, TOTP_TOO_MANY_ATTEMPTS,
};
use sea_orm::{ActiveModelTrait, ActiveValue, EntityTrait};
use tracing::{info, instrument};

const TOTP_ISSUER: &str = "LLDAP";

impl SqlBackendHandler {
    async fn get_user(&self, user_id: &UserId) -> Result<model::users::Model> {
        model::User::find_by_id(user_id.clone())
            .one(&self.sql_pool)
            .await?
            .ok_or_else(|| DomainError::EntityNotFound(user_id.to_string()))
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

    // Both sealing purposes derive from the server key, HKDF-separated.
    fn sealing_key(&self) -> &[u8] {
        self.opaque_setup.keypair().private()
    }

    fn mark_code_used(&self, user_id: &UserId, uuid: &Uuid, code: &str) -> Result<()> {
        let now = chrono::Utc::now().timestamp();
        if !self.used_totp_codes.mark_used(uuid.as_str(), code, now) {
            return Err(DomainError::AuthenticationError(format!(
                "{TOTP_CODE_ALREADY_USED} for {user_id}"
            )));
        }
        Ok(())
    }
}

#[async_trait]
impl MfaBackendHandler for SqlBackendHandler {
    #[instrument(skip_all, level = "debug", err)]
    async fn reset_user_mfa(&self, user_id: &UserId) -> Result<()> {
        // Surface missing users as EntityNotFound rather than a bare DB update error.
        let _ = self.get_user(user_id).await?;
        self.write_mfa_columns(user_id, None, None).await?;
        info!(r#"Cleared MFA state for "{}""#, user_id);
        Ok(())
    }

    #[instrument(skip_all, level = "debug", err)]
    async fn reset_own_mfa(&self, user_id: &UserId, code: &str) -> Result<()> {
        // Only the authenticator holder may give up the factor.
        self.verify_user_totp(user_id, code).await?;
        self.write_mfa_columns(user_id, None, None).await?;
        info!(r#"Cleared own MFA state for "{}""#, user_id);
        Ok(())
    }

    #[instrument(skip_all, level = "debug", err)]
    async fn start_totp_enrollment(
        &self,
        user_id: &UserId,
        current_code: Option<String>,
    ) -> Result<TotpEnrollmentStart> {
        let replaces_existing = self.get_user(user_id).await?.mfa_type.is_some();
        // Replacing a factor needs the old one, so a stolen session cannot rebind it.
        if replaces_existing {
            let current = current_code.ok_or_else(|| {
                DomainError::AuthenticationError(format!(
                    "{TOTP_CURRENT_CODE_REQUIRED} for {user_id}"
                ))
            })?;
            self.verify_user_totp(user_id, &current).await?;
        }
        let seed = lldap_mfa::generate_seed();
        let secret_base32 = lldap_mfa::seed_base32(&seed);
        let otpauth_uri = lldap_mfa::otpauth_uri(TOTP_ISSUER, user_id.as_str(), &secret_base32);
        // Nothing is persisted until the user proves possession of the seed.
        let state = lldap_mfa::seal_enrollment(
            self.sealing_key(),
            user_id.as_str(),
            &seed,
            replaces_existing,
            chrono::Utc::now().timestamp(),
        )
        .map_err(|e| DomainError::InternalError(format!("Could not seal enrollment state: {e}")))?;
        Ok(TotpEnrollmentStart {
            otpauth_uri,
            secret_base32,
            state,
        })
    }

    #[instrument(skip_all, level = "debug", err)]
    async fn finish_totp_enrollment(
        &self,
        user_id: &UserId,
        state: &str,
        code: &str,
    ) -> Result<()> {
        let now = chrono::Utc::now().timestamp();
        let state =
            lldap_mfa::open_enrollment(self.sealing_key(), state, now).map_err(|e| match e {
                MfaError::EnrollmentExpired => {
                    DomainError::AuthenticationError(format!("{e} for {user_id}"))
                }
                _ => {
                    DomainError::InternalError(format!("Corrupted enrollment state for {user_id}"))
                }
            })?;
        // UserId comparison is case-insensitive, unlike the sealed string.
        if UserId::new(&state.user_id) != *user_id {
            return Err(DomainError::InternalError(format!(
                "Enrollment state does not belong to {user_id}"
            )));
        }
        if !lldap_mfa::totp_verify(&state.seed, code, now as u64)
            .map_err(|e| DomainError::InternalError(format!("TOTP verification failed: {e}")))?
        {
            return Err(DomainError::AuthenticationError(format!(
                "Invalid TOTP code for {user_id}"
            )));
        }
        let user = self.get_user(user_id).await?;
        // The gate ran at enrollment start, so the factor must not have moved since.
        if state.replaces_existing != user.mfa_type.is_some() {
            return Err(DomainError::AuthenticationError(format!(
                "Two-factor changed during enrollment for {user_id}"
            )));
        }
        let uuid = user.uuid;
        self.mark_code_used(user_id, &uuid, code)?;
        let sealed_secret =
            lldap_mfa::seal_totp_secret(self.sealing_key(), uuid.as_str(), &state.seed).map_err(
                |e| DomainError::InternalError(format!("Could not seal TOTP secret: {e}")),
            )?;
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
        // A decrypt failure means the server key changed: ask for re-enrollment.
        let seed = lldap_mfa::open_totp_secret(self.sealing_key(), user.uuid.as_str(), &sealed)
            .map_err(|_| {
                DomainError::AuthenticationError(format!(
                    "TOTP re-enrollment required for {user_id}"
                ))
            })?;
        let now = chrono::Utc::now().timestamp() as u64;
        // Gate before verifying, so a spent allowance cannot keep testing codes.
        if !self.failed_totp_attempts.allowed(user.uuid.as_str(), now) {
            return Err(DomainError::AuthenticationError(format!(
                "{TOTP_TOO_MANY_ATTEMPTS} for {user_id}"
            )));
        }
        if !lldap_mfa::totp_verify(&seed, code, now)
            .map_err(|e| DomainError::InternalError(format!("TOTP verification failed: {e}")))?
        {
            self.failed_totp_attempts
                .record_failure(user.uuid.as_str(), now);
            return Err(DomainError::AuthenticationError(format!(
                "Invalid TOTP code for {user_id}"
            )));
        }
        self.mark_code_used(user_id, &user.uuid, code)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sql_backend_handler::tests::{get_initialized_db, insert_user_no_password};
    use lldap_auth::opaque::server::{ServerSetup, generate_random_private_key};
    use lldap_mfa::{
        EnrollmentState, SEALED_BLOB_LEN, SEALED_PREFIX, TOTP_ENROLLMENT_EXPIRED,
        TOTP_ENROLLMENT_TTL_SECS, TOTP_SEED_LEN, format_code, open_totp_secret, seed_base32,
        totp_code,
    };
    use pretty_assertions::assert_eq;

    async fn setup_handler() -> (ServerSetup, SqlBackendHandler) {
        let setup = generate_random_private_key();
        let handler = SqlBackendHandler::new(setup.clone(), get_initialized_db().await);
        (setup, handler)
    }

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

    fn open_state(setup: &ServerSetup, state: &str) -> EnrollmentState {
        lldap_mfa::open_enrollment(
            setup.keypair().private(),
            state,
            chrono::Utc::now().timestamp(),
        )
        .unwrap()
    }

    fn current_code(seed: &[u8]) -> (u64, String) {
        let now = chrono::Utc::now().timestamp() as u64;
        (now, format_code(totp_code(seed, now).unwrap()))
    }

    fn wrong_code(seed: &[u8], now: u64) -> String {
        let valid: Vec<u32> = [now - 30, now, now + 30]
            .iter()
            .map(|t| totp_code(seed, *t).unwrap())
            .collect();
        format_code((0..).find(|c| !valid.contains(c)).unwrap())
    }

    async fn enroll_user(
        handler: &SqlBackendHandler,
        setup: &ServerSetup,
        user: &str,
    ) -> (UserId, [u8; TOTP_SEED_LEN], String) {
        insert_user_no_password(handler, user).await;
        let user_id = UserId::new(user);
        let start = handler.start_totp_enrollment(&user_id, None).await.unwrap();
        let state = open_state(setup, &start.state);
        let (_, code) = current_code(&state.seed);
        handler
            .finish_totp_enrollment(&user_id, &start.state, &code)
            .await
            .unwrap();
        (user_id, state.seed, code)
    }

    #[tokio::test]
    async fn test_totp_enrollment_flow() {
        let (setup, handler) = setup_handler().await;
        insert_user_no_password(&handler, "bob").await;
        let user_id = UserId::new("bob");

        let start = handler.start_totp_enrollment(&user_id, None).await.unwrap();
        assert!(start.otpauth_uri.starts_with("otpauth://totp/"));
        assert!(start.otpauth_uri.contains(&start.secret_base32));
        assert!(!format!("{start:?}").contains(&start.secret_base32));
        assert_eq!(get_mfa_columns(&handler, "bob").await, (None, None));

        let state = open_state(&setup, &start.state);
        assert_eq!(seed_base32(&state.seed), start.secret_base32);
        assert!(!state.replaces_existing);
        let (_, code) = current_code(&state.seed);
        handler
            .finish_totp_enrollment(&user_id, &start.state, &code)
            .await
            .unwrap();

        let (totp_secret, mfa_type) = get_mfa_columns(&handler, "bob").await;
        assert_eq!(mfa_type.as_deref(), Some(MFA_TYPE_TOTP));
        let sealed = totp_secret.unwrap();
        let uuid = handler.get_user(&user_id).await.unwrap().uuid;
        assert_eq!(
            open_totp_secret(setup.keypair().private(), uuid.as_str(), &sealed).unwrap(),
            state.seed
        );
    }

    #[tokio::test]
    async fn test_finish_totp_enrollment_rejected() {
        let (setup, handler) = setup_handler().await;
        insert_user_no_password(&handler, "bob").await;
        insert_user_no_password(&handler, "john").await;
        let user_id = UserId::new("bob");

        let start = handler.start_totp_enrollment(&user_id, None).await.unwrap();
        let state = open_state(&setup, &start.state);
        let (now, code) = current_code(&state.seed);

        let err = handler
            .finish_totp_enrollment(&user_id, &start.state, &wrong_code(&state.seed, now))
            .await
            .unwrap_err();
        assert!(matches!(err, DomainError::AuthenticationError(_)));

        let stale = now as i64 - TOTP_ENROLLMENT_TTL_SECS as i64 - 1;
        let expired =
            lldap_mfa::seal_enrollment(setup.keypair().private(), "bob", &state.seed, false, stale)
                .unwrap();
        let err = handler
            .finish_totp_enrollment(&user_id, &expired, &code)
            .await
            .unwrap_err();
        assert!(err.to_string().contains(TOTP_ENROLLMENT_EXPIRED));

        let err = handler
            .finish_totp_enrollment(&UserId::new("john"), &start.state, &code)
            .await
            .unwrap_err();
        assert!(matches!(err, DomainError::InternalError(_)));

        // A state issued for a replacement cannot enroll a user who has no factor.
        let replacing = lldap_mfa::seal_enrollment(
            setup.keypair().private(),
            "bob",
            &state.seed,
            true,
            now as i64,
        )
        .unwrap();
        let err = handler
            .finish_totp_enrollment(&user_id, &replacing, &code)
            .await
            .unwrap_err();
        assert!(err.to_string().contains("changed during enrollment"));
        assert_eq!(get_mfa_columns(&handler, "bob").await, (None, None));
        assert_eq!(get_mfa_columns(&handler, "john").await, (None, None));
    }

    #[tokio::test]
    async fn test_start_totp_enrollment_requires_current_code() {
        let (setup, handler) = setup_handler().await;
        let (user_id, seed, enroll_code) = enroll_user(&handler, &setup, "bob").await;
        let sealed_before = get_mfa_columns(&handler, "bob").await.0.unwrap();
        let now = chrono::Utc::now().timestamp() as u64;

        let err = handler
            .start_totp_enrollment(&user_id, None)
            .await
            .unwrap_err();
        assert!(err.to_string().contains(TOTP_CURRENT_CODE_REQUIRED));

        let err = handler
            .start_totp_enrollment(&user_id, Some(wrong_code(&seed, now)))
            .await
            .unwrap_err();
        assert!(matches!(err, DomainError::AuthenticationError(_)));
        assert_eq!(
            get_mfa_columns(&handler, "bob").await.0,
            Some(sealed_before)
        );

        let current = [now + 30, now - 30]
            .iter()
            .map(|t| format_code(totp_code(&seed, *t).unwrap()))
            .find(|c| *c != enroll_code)
            .unwrap();
        let restart = handler
            .start_totp_enrollment(&user_id, Some(current))
            .await
            .unwrap();
        let new_state = open_state(&setup, &restart.state);
        assert!(new_state.replaces_existing);
        let (_, new_code) = current_code(&new_state.seed);
        handler
            .finish_totp_enrollment(&user_id, &restart.state, &new_code)
            .await
            .unwrap();
        let uuid = handler.get_user(&user_id).await.unwrap().uuid;
        let sealed_after = get_mfa_columns(&handler, "bob").await.0.unwrap();
        assert_eq!(
            open_totp_secret(setup.keypair().private(), uuid.as_str(), &sealed_after).unwrap(),
            new_state.seed
        );
    }

    #[tokio::test]
    async fn test_reset_own_mfa() {
        let (setup, handler) = setup_handler().await;
        let (user_id, seed, enroll_code) = enroll_user(&handler, &setup, "bob").await;
        let now = chrono::Utc::now().timestamp() as u64;

        let err = handler
            .reset_own_mfa(&user_id, &wrong_code(&seed, now))
            .await
            .unwrap_err();
        assert!(matches!(err, DomainError::AuthenticationError(_)));
        assert!(get_mfa_columns(&handler, "bob").await.0.is_some());

        let current = [now + 30, now - 30]
            .iter()
            .map(|t| format_code(totp_code(&seed, *t).unwrap()))
            .find(|c| *c != enroll_code)
            .unwrap();
        handler.reset_own_mfa(&user_id, &current).await.unwrap();
        assert_eq!(get_mfa_columns(&handler, "bob").await, (None, None));

        let err = handler.reset_own_mfa(&user_id, &current).await.unwrap_err();
        assert!(err.to_string().contains("not enrolled"));
    }

    #[tokio::test]
    async fn test_reset_user_mfa() {
        let (setup, handler) = setup_handler().await;
        let (user_id, _, _) = enroll_user(&handler, &setup, "bob").await;
        assert!(get_mfa_columns(&handler, "bob").await.0.is_some());

        handler.reset_user_mfa(&user_id).await.unwrap();
        assert_eq!(get_mfa_columns(&handler, "bob").await, (None, None));
        handler.reset_user_mfa(&user_id).await.unwrap();
        let err = handler
            .reset_user_mfa(&UserId::new("nobody"))
            .await
            .unwrap_err();
        assert!(matches!(err, DomainError::EntityNotFound(_)));
    }

    #[tokio::test]
    async fn test_verify_user_totp() {
        let (setup, handler) = setup_handler().await;
        let (user_id, seed, enroll_code) = enroll_user(&handler, &setup, "bob").await;
        insert_user_no_password(&handler, "john").await;
        let now = chrono::Utc::now().timestamp() as u64;

        let err = handler
            .verify_user_totp(&user_id, &enroll_code)
            .await
            .unwrap_err();
        assert!(err.to_string().contains(TOTP_CODE_ALREADY_USED));

        let next_code = [now + 30, now - 30]
            .iter()
            .map(|t| format_code(totp_code(&seed, *t).unwrap()))
            .find(|c| *c != enroll_code)
            .unwrap();
        handler
            .verify_user_totp(&user_id, &next_code)
            .await
            .unwrap();
        let err = handler
            .verify_user_totp(&user_id, &next_code)
            .await
            .unwrap_err();
        assert!(err.to_string().contains(TOTP_CODE_ALREADY_USED));

        let err = handler
            .verify_user_totp(&user_id, &wrong_code(&seed, now))
            .await
            .unwrap_err();
        assert!(matches!(err, DomainError::AuthenticationError(_)));
        let err = handler
            .verify_user_totp(&UserId::new("john"), &enroll_code)
            .await
            .unwrap_err();
        assert!(matches!(err, DomainError::AuthenticationError(_)));

        handler
            .write_mfa_columns(
                &user_id,
                Some(format!(
                    "{SEALED_PREFIX}{}",
                    "A".repeat(SEALED_BLOB_LEN - SEALED_PREFIX.len())
                )),
                Some(MFA_TYPE_TOTP.to_owned()),
            )
            .await
            .unwrap();
        let err = handler
            .verify_user_totp(&user_id, &next_code)
            .await
            .unwrap_err();
        assert!(err.to_string().contains("re-enrollment"));
    }
}
