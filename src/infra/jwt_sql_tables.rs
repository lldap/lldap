use sea_query::*;

pub use crate::domain::sql_tables::*;

/// Contains the refresh tokens for a given user.
#[derive(Iden)]
pub enum JwtRefreshStorage {
    Table,
    RefreshTokenHash,
    UserId,
    ExpiryDate,
}

/// Contains the blacklisted JWT that haven't expired yet.
#[derive(Iden)]
pub enum JwtBlacklist {
    Table,
    JwtHash,
    UserId,
    ExpiryDate,
}

/// This needs to be initialized after the domain tables are.
pub async fn init_table(pool: &Pool) -> sqlx::Result<()> {
    sqlx::query(
        &Table::create()
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
                    .table(JwtRefreshStorage::Table, Users::Table)
                    .col(JwtRefreshStorage::UserId, Users::UserId)
                    .on_delete(ForeignKeyAction::Cascade)
                    .on_update(ForeignKeyAction::Cascade),
            )
            .to_string(DbQueryBuilder {}),
    )
    .execute(pool)
    .await?;

    sqlx::query(
        &Table::create()
            .table(JwtBlacklist::Table)
            .if_not_exists()
            .col(
                ColumnDef::new(JwtBlacklist::JwtHash)
                    .big_integer()
                    .not_null()
                    .primary_key(),
            )
            .col(
                ColumnDef::new(JwtBlacklist::UserId)
                    .string_len(255)
                    .not_null(),
            )
            .col(
                ColumnDef::new(JwtBlacklist::ExpiryDate)
                    .date_time()
                    .not_null(),
            )
            .foreign_key(
                ForeignKey::create()
                    .name("JwtBlacklistUserForeignKey")
                    .table(JwtBlacklist::Table, Users::Table)
                    .col(JwtBlacklist::UserId, Users::UserId)
                    .on_delete(ForeignKeyAction::Cascade)
                    .on_update(ForeignKeyAction::Cascade),
            )
            .to_string(DbQueryBuilder {}),
    )
    .execute(pool)
    .await?;

    Ok(())
}
