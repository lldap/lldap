use crate::tcp_backend_handler::TcpBackendHandler;
use async_trait::async_trait;
use chrono::NaiveDateTime;
use lldap_domain::types::UserId;
use lldap_domain_model::{
    error::*,
    model::{self, JwtRefreshStorageColumn, JwtStorageColumn, PasswordResetTokensColumn},
};
use lldap_sql_backend_handler::SqlBackendHandler;
use sea_orm::{
    ActiveModelTrait, ColumnTrait, EntityTrait, IntoActiveModel, QueryFilter, QuerySelect,
    sea_query::{Cond, Expr},
};
use std::collections::HashSet;
use tracing::{debug, instrument};

fn gen_random_string(len: usize) -> String {
    use rand::{Rng, SeedableRng, distributions::Alphanumeric, rngs::SmallRng};
    let mut rng = SmallRng::from_entropy();
    std::iter::repeat(())
        .map(|()| rng.sample(Alphanumeric))
        .map(char::from)
        .take(len)
        .collect()
}

#[async_trait]
impl TcpBackendHandler for SqlBackendHandler {
    #[instrument(skip_all, level = "debug")]
    async fn get_jwt_blacklist(&self) -> anyhow::Result<HashSet<u64>> {
        Ok(model::JwtStorage::find()
            .select_only()
            .column(JwtStorageColumn::JwtHash)
            .filter(JwtStorageColumn::Blacklisted.eq(true))
            .into_tuple::<(i64,)>()
            .all(self.pool())
            .await?
            .into_iter()
            .map(|m| m.0 as u64)
            .collect::<HashSet<u64>>())
    }

    #[instrument(skip_all, level = "debug")]
    async fn create_refresh_token(&self, user: &UserId) -> Result<(String, chrono::Duration)> {
        debug!(?user);
        // TODO: Initialize the rng only once. Maybe Arc<Cell>?
        let refresh_token = gen_random_string(100);
        let refresh_token_hash = {
            use std::collections::hash_map::DefaultHasher;
            use std::hash::{Hash, Hasher};
            let mut s = DefaultHasher::new();
            refresh_token.hash(&mut s);
            s.finish()
        };
        let duration = chrono::Duration::days(30);
        let new_token = model::jwt_refresh_storage::Model {
            refresh_token_hash: refresh_token_hash as i64,
            user_id: user.clone(),
            expiry_date: chrono::Utc::now().naive_utc() + duration,
        }
        .into_active_model();
        new_token.insert(self.pool()).await?;
        Ok((refresh_token, duration))
    }

    #[instrument(skip_all, level = "debug")]
    async fn register_jwt(
        &self,
        user: &UserId,
        jwt_hash: u64,
        expiry_date: NaiveDateTime,
    ) -> Result<()> {
        debug!(?user, ?jwt_hash);
        let new_token = model::jwt_storage::Model {
            jwt_hash: jwt_hash as i64,
            user_id: user.clone(),
            blacklisted: false,
            expiry_date,
        }
        .into_active_model();
        new_token.insert(self.pool()).await?;
        Ok(())
    }

    #[instrument(skip_all, level = "debug")]
    async fn check_token(&self, refresh_token_hash: u64, user: &UserId) -> Result<bool> {
        debug!(?user);
        Ok(
            model::JwtRefreshStorage::find_by_id(refresh_token_hash as i64)
                .filter(JwtRefreshStorageColumn::UserId.eq(user))
                .one(self.pool())
                .await?
                .is_some(),
        )
    }

    #[instrument(skip_all, level = "debug")]
    async fn blacklist_jwts(&self, user: &UserId) -> Result<HashSet<u64>> {
        debug!(?user);
        let valid_tokens = model::JwtStorage::find()
            .select_only()
            .column(JwtStorageColumn::JwtHash)
            .filter(
                Cond::all()
                    .add(JwtStorageColumn::UserId.eq(user))
                    .add(JwtStorageColumn::Blacklisted.eq(false)),
            )
            .into_tuple::<(i64,)>()
            .all(self.pool())
            .await?
            .into_iter()
            .map(|t| t.0 as u64)
            .collect::<HashSet<u64>>();
        model::JwtStorage::update_many()
            .col_expr(JwtStorageColumn::Blacklisted, Expr::value(true))
            .filter(JwtStorageColumn::UserId.eq(user))
            .exec(self.pool())
            .await?;
        Ok(valid_tokens)
    }

    #[instrument(skip_all, level = "debug")]
    async fn delete_refresh_token(&self, refresh_token_hash: u64) -> Result<()> {
        model::JwtRefreshStorage::delete_by_id(refresh_token_hash as i64)
            .exec(self.pool())
            .await?;
        Ok(())
    }

    #[instrument(skip_all, level = "debug")]
    async fn start_password_reset(&self, user: &UserId) -> Result<Option<String>> {
        debug!(?user);
        if model::User::find_by_id(user.clone())
            .one(self.pool())
            .await?
            .is_none()
        {
            debug!("User not found");
            return Ok(None);
        }

        let token = gen_random_string(100);
        let duration = chrono::Duration::minutes(10);

        let new_token = model::password_reset_tokens::Model {
            token: token.clone(),
            user_id: user.clone(),
            expiry_date: chrono::Utc::now().naive_utc() + duration,
        }
        .into_active_model();
        new_token.insert(self.pool()).await?;
        Ok(Some(token))
    }

    #[instrument(skip_all, level = "debug", ret)]
    async fn get_user_id_for_password_reset_token(&self, token: &str) -> Result<UserId> {
        Ok(model::PasswordResetTokens::find_by_id(token.to_owned())
            .filter(PasswordResetTokensColumn::ExpiryDate.gt(chrono::Utc::now().naive_utc()))
            .one(self.pool())
            .await?
            .ok_or_else(|| DomainError::EntityNotFound("Invalid reset token".to_owned()))?
            .user_id)
    }

    #[instrument(skip_all, level = "debug")]
    async fn delete_password_reset_token(&self, token: &str) -> Result<()> {
        let result = model::PasswordResetTokens::delete_by_id(token.to_owned())
            .exec(self.pool())
            .await?;
        if result.rows_affected == 0 {
            return Err(DomainError::EntityNotFound(format!(
                "No such password reset token: '{}'",
                token
            )));
        }
        Ok(())
    }
}
