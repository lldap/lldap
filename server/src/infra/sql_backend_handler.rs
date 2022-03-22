use super::{jwt_sql_tables::*, tcp_backend_handler::*};
use crate::domain::{error::*, handler::UserId, sql_backend_handler::SqlBackendHandler};
use async_trait::async_trait;
use futures_util::StreamExt;
use sea_query::{Expr, Iden, Query, SimpleExpr};
use sea_query_binder::SqlxBinder;
use sqlx::{query_as_with, query_with, Row};
use std::collections::HashSet;

fn gen_random_string(len: usize) -> String {
    use rand::{distributions::Alphanumeric, rngs::SmallRng, Rng, SeedableRng};
    let mut rng = SmallRng::from_entropy();
    std::iter::repeat(())
        .map(|()| rng.sample(Alphanumeric))
        .map(char::from)
        .take(len)
        .collect()
}

#[async_trait]
impl TcpBackendHandler for SqlBackendHandler {
    async fn get_jwt_blacklist(&self) -> anyhow::Result<HashSet<u64>> {
        let (query, values) = Query::select()
            .column(JwtStorage::JwtHash)
            .from(JwtStorage::Table)
            .build_sqlx(DbQueryBuilder {});

        query_with(&query, values)
            .map(|row: DbRow| row.get::<i64, _>(&*JwtStorage::JwtHash.to_string()) as u64)
            .fetch(&self.sql_pool)
            .collect::<Vec<sqlx::Result<u64>>>()
            .await
            .into_iter()
            .collect::<sqlx::Result<HashSet<u64>>>()
            .map_err(|e| anyhow::anyhow!(e))
    }

    async fn create_refresh_token(&self, user: &UserId) -> Result<(String, chrono::Duration)> {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};
        // TODO: Initialize the rng only once. Maybe Arc<Cell>?
        let refresh_token = gen_random_string(100);
        let refresh_token_hash = {
            let mut s = DefaultHasher::new();
            refresh_token.hash(&mut s);
            s.finish()
        };
        let duration = chrono::Duration::days(30);
        let (query, values) = Query::insert()
            .into_table(JwtRefreshStorage::Table)
            .columns(vec![
                JwtRefreshStorage::RefreshTokenHash,
                JwtRefreshStorage::UserId,
                JwtRefreshStorage::ExpiryDate,
            ])
            .values_panic(vec![
                (refresh_token_hash as i64).into(),
                user.into(),
                (chrono::Utc::now() + duration).naive_utc().into(),
            ])
            .build_sqlx(DbQueryBuilder {});
        query_with(&query, values).execute(&self.sql_pool).await?;
        Ok((refresh_token, duration))
    }

    async fn check_token(&self, refresh_token_hash: u64, user: &UserId) -> Result<bool> {
        let (query, values) = Query::select()
            .expr(SimpleExpr::Value(1.into()))
            .from(JwtRefreshStorage::Table)
            .and_where(Expr::col(JwtRefreshStorage::RefreshTokenHash).eq(refresh_token_hash as i64))
            .and_where(Expr::col(JwtRefreshStorage::UserId).eq(user))
            .build_sqlx(DbQueryBuilder {});
        Ok(query_with(&query, values)
            .fetch_optional(&self.sql_pool)
            .await?
            .is_some())
    }
    async fn blacklist_jwts(&self, user: &UserId) -> Result<HashSet<u64>> {
        use sqlx::Result;
        let (query, values) = Query::select()
            .column(JwtStorage::JwtHash)
            .from(JwtStorage::Table)
            .and_where(Expr::col(JwtStorage::UserId).eq(user))
            .and_where(Expr::col(JwtStorage::Blacklisted).eq(true))
            .build_sqlx(DbQueryBuilder {});
        let result = query_with(&query, values)
            .map(|row: DbRow| row.get::<i64, _>(&*JwtStorage::JwtHash.to_string()) as u64)
            .fetch(&self.sql_pool)
            .collect::<Vec<sqlx::Result<u64>>>()
            .await
            .into_iter()
            .collect::<Result<HashSet<u64>>>();
        let (query, values) = Query::update()
            .table(JwtStorage::Table)
            .values(vec![(JwtStorage::Blacklisted, true.into())])
            .and_where(Expr::col(JwtStorage::UserId).eq(user))
            .build_sqlx(DbQueryBuilder {});
        query_with(&query, values).execute(&self.sql_pool).await?;
        Ok(result?)
    }
    async fn delete_refresh_token(&self, refresh_token_hash: u64) -> Result<()> {
        let (query, values) = Query::delete()
            .from_table(JwtRefreshStorage::Table)
            .and_where(Expr::col(JwtRefreshStorage::RefreshTokenHash).eq(refresh_token_hash))
            .build_sqlx(DbQueryBuilder {});
        query_with(&query, values).execute(&self.sql_pool).await?;
        Ok(())
    }

    async fn start_password_reset(&self, user: &UserId) -> Result<Option<String>> {
        let (query, values) = Query::select()
            .column(Users::UserId)
            .from(Users::Table)
            .and_where(Expr::col(Users::UserId).eq(user))
            .build_sqlx(DbQueryBuilder {});

        // Check that the user exists.
        if query_with(&query, values)
            .fetch_one(&self.sql_pool)
            .await
            .is_err()
        {
            return Ok(None);
        }

        let token = gen_random_string(100);
        let duration = chrono::Duration::minutes(10);

        let (query, values) = Query::insert()
            .into_table(PasswordResetTokens::Table)
            .columns(vec![
                PasswordResetTokens::Token,
                PasswordResetTokens::UserId,
                PasswordResetTokens::ExpiryDate,
            ])
            .values_panic(vec![
                token.clone().into(),
                user.into(),
                (chrono::Utc::now() + duration).naive_utc().into(),
            ])
            .build_sqlx(DbQueryBuilder {});
        query_with(&query, values).execute(&self.sql_pool).await?;
        Ok(Some(token))
    }

    async fn get_user_id_for_password_reset_token(&self, token: &str) -> Result<UserId> {
        let (query, values) = Query::select()
            .column(PasswordResetTokens::UserId)
            .from(PasswordResetTokens::Table)
            .and_where(Expr::col(PasswordResetTokens::Token).eq(token))
            .and_where(
                Expr::col(PasswordResetTokens::ExpiryDate).gt(chrono::Utc::now().naive_utc()),
            )
            .build_sqlx(DbQueryBuilder {});

        let (user_id,) = query_as_with(&query, values)
            .fetch_one(&self.sql_pool)
            .await?;
        Ok(user_id)
    }

    async fn delete_password_reset_token(&self, token: &str) -> Result<()> {
        let (query, values) = Query::delete()
            .from_table(PasswordResetTokens::Table)
            .and_where(Expr::col(PasswordResetTokens::Token).eq(token))
            .build_sqlx(DbQueryBuilder {});
        query_with(&query, values).execute(&self.sql_pool).await?;
        Ok(())
    }
}
