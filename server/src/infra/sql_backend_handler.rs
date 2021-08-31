use super::{jwt_sql_tables::*, tcp_backend_handler::*};
use crate::domain::{error::*, sql_backend_handler::SqlBackendHandler};
use async_trait::async_trait;
use futures_util::StreamExt;
use sea_query::{Expr, Iden, Query, SimpleExpr};
use sqlx::Row;
use std::collections::HashSet;

#[async_trait]
impl TcpBackendHandler for SqlBackendHandler {
    async fn get_jwt_blacklist(&self) -> anyhow::Result<HashSet<u64>> {
        use sqlx::Result;
        let query = Query::select()
            .column(JwtStorage::JwtHash)
            .from(JwtStorage::Table)
            .to_string(DbQueryBuilder {});

        sqlx::query(&query)
            .map(|row: DbRow| row.get::<i64, _>(&*JwtStorage::JwtHash.to_string()) as u64)
            .fetch(&self.sql_pool)
            .collect::<Vec<sqlx::Result<u64>>>()
            .await
            .into_iter()
            .collect::<Result<HashSet<u64>>>()
            .map_err(|e| anyhow::anyhow!(e))
    }

    async fn create_refresh_token(&self, user: &str) -> Result<(String, chrono::Duration)> {
        use rand::{distributions::Alphanumeric, rngs::SmallRng, Rng, SeedableRng};
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};
        // TODO: Initialize the rng only once. Maybe Arc<Cell>?
        let mut rng = SmallRng::from_entropy();
        let refresh_token: String = std::iter::repeat(())
            .map(|()| rng.sample(Alphanumeric))
            .map(char::from)
            .take(100)
            .collect();
        let refresh_token_hash = {
            let mut s = DefaultHasher::new();
            refresh_token.hash(&mut s);
            s.finish()
        };
        let duration = chrono::Duration::days(30);
        let query = Query::insert()
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
            .to_string(DbQueryBuilder {});
        sqlx::query(&query).execute(&self.sql_pool).await?;
        Ok((refresh_token, duration))
    }

    async fn check_token(&self, refresh_token_hash: u64, user: &str) -> Result<bool> {
        let query = Query::select()
            .expr(SimpleExpr::Value(1.into()))
            .from(JwtRefreshStorage::Table)
            .and_where(Expr::col(JwtRefreshStorage::RefreshTokenHash).eq(refresh_token_hash as i64))
            .and_where(Expr::col(JwtRefreshStorage::UserId).eq(user))
            .to_string(DbQueryBuilder {});
        Ok(sqlx::query(&query)
            .fetch_optional(&self.sql_pool)
            .await?
            .is_some())
    }
    async fn blacklist_jwts(&self, user: &str) -> DomainResult<HashSet<u64>> {
        use sqlx::Result;
        let query = Query::select()
            .column(JwtStorage::JwtHash)
            .from(JwtStorage::Table)
            .and_where(Expr::col(JwtStorage::UserId).eq(user))
            .and_where(Expr::col(JwtStorage::Blacklisted).eq(true))
            .to_string(DbQueryBuilder {});
        let result = sqlx::query(&query)
            .map(|row: DbRow| row.get::<i64, _>(&*JwtStorage::JwtHash.to_string()) as u64)
            .fetch(&self.sql_pool)
            .collect::<Vec<sqlx::Result<u64>>>()
            .await
            .into_iter()
            .collect::<Result<HashSet<u64>>>();
        let query = Query::update()
            .table(JwtStorage::Table)
            .values(vec![(JwtStorage::Blacklisted, true.into())])
            .and_where(Expr::col(JwtStorage::UserId).eq(user))
            .to_string(DbQueryBuilder {});
        sqlx::query(&query).execute(&self.sql_pool).await?;
        Ok(result?)
    }
    async fn delete_refresh_token(&self, refresh_token_hash: u64) -> DomainResult<()> {
        let query = Query::delete()
            .from_table(JwtRefreshStorage::Table)
            .and_where(Expr::col(JwtRefreshStorage::RefreshTokenHash).eq(refresh_token_hash))
            .to_string(DbQueryBuilder {});
        sqlx::query(&query).execute(&self.sql_pool).await?;
        Ok(())
    }
}
