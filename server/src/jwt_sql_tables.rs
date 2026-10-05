use sea_orm::{
    ConnectionTrait, DeriveIden, TransactionTrait,
    sea_query::{ColumnDef, Expr, ForeignKey, ForeignKeyAction, Query, Table},
};

pub use lldap_sql_backend_handler::{sql_migrations::Users, sql_tables::DbConnection};

/// Contains the refresh tokens for a given user.
#[derive(DeriveIden)]
pub enum JwtRefreshStorage {
    Table,
    RefreshTokenHash,
    UserId,
    ExpiryDate,
}

/// Contains the blacklisted JWT that haven't expired yet.
#[derive(DeriveIden)]
pub enum JwtStorage {
    Table,
    JwtHash,
    UserId,
    ExpiryDate,
    Blacklisted,
}

/// Contains the temporary tokens to reset the password, sent by email.
#[derive(DeriveIden)]
pub enum PasswordResetTokens {
    Table,
    Token,
    UserId,
    ExpiryDate,
}

/// This needs to be initialized after the domain tables are.
pub async fn init_table(pool: &DbConnection) -> std::result::Result<(), sea_orm::DbErr> {
    let builder = pool.get_database_backend();

    pool.execute(
        builder.build(
            Table::create()
                .table(JwtRefreshStorage::Table)
                .if_not_exists()
                .col(
                    ColumnDef::new(JwtRefreshStorage::RefreshTokenHash)
                        .big_integer()
                        .not_null()
                        .primary_key(),
                )
                .col(
                    ColumnDef::new(JwtRefreshStorage::UserId)
                        .string_len(255)
                        .not_null(),
                )
                .col(
                    ColumnDef::new(JwtRefreshStorage::ExpiryDate)
                        .date_time()
                        .not_null(),
                )
                .foreign_key(
                    ForeignKey::create()
                        .name("JwtRefreshStorageUserForeignKey")
                        .from(JwtRefreshStorage::Table, JwtRefreshStorage::UserId)
                        .to(Users::Table, Users::UserId)
                        .on_delete(ForeignKeyAction::Cascade)
                        .on_update(ForeignKeyAction::Cascade),
                ),
        ),
    )
    .await?;

    pool.execute(
        builder.build(
            Table::create()
                .table(JwtStorage::Table)
                .if_not_exists()
                .col(
                    ColumnDef::new(JwtStorage::JwtHash)
                        .big_integer()
                        .not_null()
                        .primary_key(),
                )
                .col(
                    ColumnDef::new(JwtStorage::UserId)
                        .string_len(255)
                        .not_null(),
                )
                .col(
                    ColumnDef::new(JwtStorage::ExpiryDate)
                        .date_time()
                        .not_null(),
                )
                .col(
                    ColumnDef::new(JwtStorage::Blacklisted)
                        .boolean()
                        .default(false)
                        .not_null(),
                )
                .foreign_key(
                    ForeignKey::create()
                        .name("JwtStorageUserForeignKey")
                        .from(JwtStorage::Table, JwtStorage::UserId)
                        .to(Users::Table, Users::UserId)
                        .on_delete(ForeignKeyAction::Cascade)
                        .on_update(ForeignKeyAction::Cascade),
                ),
        ),
    )
    .await?;

    pool.execute(
        builder.build(
            Table::create()
                .table(PasswordResetTokens::Table)
                .if_not_exists()
                .col(
                    ColumnDef::new(PasswordResetTokens::Token)
                        .string_len(255)
                        .not_null()
                        .primary_key(),
                )
                .col(
                    ColumnDef::new(PasswordResetTokens::UserId)
                        .string_len(255)
                        .not_null(),
                )
                .col(
                    ColumnDef::new(PasswordResetTokens::ExpiryDate)
                        .date_time()
                        .not_null(),
                )
                .foreign_key(
                    ForeignKey::create()
                        .name("PasswordResetTokensUserForeignKey")
                        .from(PasswordResetTokens::Table, PasswordResetTokens::UserId)
                        .to(Users::Table, Users::UserId)
                        .on_delete(ForeignKeyAction::Cascade)
                        .on_update(ForeignKeyAction::Cascade),
                ),
        ),
    )
    .await?;

    Ok(())
}

/// Invalidate every session: blacklist all unexpired JWTs and delete all
/// refresh tokens, in one transaction.
///
/// Run once when the schema is migrated across the opaque-ke 0.7 -> 4.0
/// upgrade, so no session issued before the upgrade can outlive it: a
/// password reset performed through a pre-upgrade session could otherwise
/// race the lazy password upgrade. Expired JWTs are left alone; they fail
/// the expiry check anyway, and blacklisting them would only bloat the
/// in-memory blacklist loaded at startup until the hourly cleaner runs.
pub async fn invalidate_all_sessions(
    pool: &DbConnection,
) -> std::result::Result<(), sea_orm::DbErr> {
    let now = chrono::Utc::now().naive_utc();
    let transaction = pool.begin().await?;
    let builder = transaction.get_database_backend();
    transaction
        .execute(
            builder.build(
                Query::update()
                    .table(JwtStorage::Table)
                    .value(JwtStorage::Blacklisted, true)
                    .and_where(Expr::col(JwtStorage::Blacklisted).eq(false))
                    .and_where(Expr::col(JwtStorage::ExpiryDate).gt(now)),
            ),
        )
        .await?;
    transaction
        .execute(builder.build(Query::delete().from_table(JwtRefreshStorage::Table)))
        .await?;
    transaction.commit().await
}

#[cfg(test)]
mod tests {
    use super::*;
    use lldap_sql_backend_handler::sql_tables;
    use sea_orm::{Database, DbBackend, FromQueryResult, Statement};

    async fn get_in_memory_db() -> DbConnection {
        let mut sql_opt = sea_orm::ConnectOptions::new("sqlite::memory:".to_owned());
        sql_opt.max_connections(1).sqlx_logging(false);
        Database::connect(sql_opt).await.unwrap()
    }

    fn raw_statement(sql: &str) -> Statement {
        Statement::from_string(DbBackend::Sqlite, sql.to_owned())
    }

    #[derive(FromQueryResult, Debug, PartialEq, Eq)]
    struct JwtRow {
        jwt_hash: i64,
        blacklisted: bool,
    }

    #[derive(FromQueryResult, Debug, PartialEq, Eq)]
    struct Count {
        count: i64,
    }

    #[tokio::test]
    async fn invalidate_all_sessions_blacklists_live_jwts_and_drops_refresh_tokens() {
        let pool = get_in_memory_db().await;
        sql_tables::init_table(&pool).await.unwrap();
        init_table(&pool).await.unwrap();
        for stmt in [
            r#"INSERT INTO users (user_id, email, lowercase_email, display_name, creation_date, uuid)
               VALUES ("alice", "a@x", "a@x", "Alice", "1970-01-01 00:00:00", "u1"),
                      ("bob", "b@x", "b@x", "Bob", "1970-01-01 00:00:00", "u2")"#,
            r#"INSERT INTO jwt_storage (jwt_hash, user_id, expiry_date, blacklisted)
               VALUES (1, "alice", "2999-01-01 00:00:00", 0),
                      (2, "bob", "2999-01-01 00:00:00", 0),
                      (3, "alice", "2000-01-01 00:00:00", 0),
                      (4, "bob", "2999-01-01 00:00:00", 1)"#,
            r#"INSERT INTO jwt_refresh_storage (refresh_token_hash, user_id, expiry_date)
               VALUES (10, "alice", "2999-01-01 00:00:00"),
                      (11, "bob", "2999-01-01 00:00:00")"#,
        ] {
            pool.execute(raw_statement(stmt)).await.unwrap();
        }

        invalidate_all_sessions(&pool).await.unwrap();

        let rows = JwtRow::find_by_statement(raw_statement(
            "SELECT jwt_hash, blacklisted FROM jwt_storage ORDER BY jwt_hash",
        ))
        .all(&pool)
        .await
        .unwrap();
        assert_eq!(
            rows,
            vec![
                JwtRow {
                    jwt_hash: 1,
                    blacklisted: true
                },
                JwtRow {
                    jwt_hash: 2,
                    blacklisted: true
                },
                // Already expired: left alone.
                JwtRow {
                    jwt_hash: 3,
                    blacklisted: false
                },
                JwtRow {
                    jwt_hash: 4,
                    blacklisted: true
                },
            ]
        );
        let refresh = Count::find_by_statement(raw_statement(
            "SELECT COUNT(*) AS count FROM jwt_refresh_storage",
        ))
        .one(&pool)
        .await
        .unwrap()
        .unwrap();
        assert_eq!(refresh.count, 0, "every refresh token must be gone");
    }
}
