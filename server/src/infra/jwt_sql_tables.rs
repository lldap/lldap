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
pub enum JwtStorage {
    Table,
    JwtHash,
    UserId,
    ExpiryDate,
    Blacklisted,
}

/// Contains the temporary tokens to reset the password, sent by email.
#[derive(Iden)]
pub enum PasswordResetTokens {
    Table,
    Token,
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
                    .table(JwtStorage::Table, Users::Table)
                    .col(JwtStorage::UserId, Users::UserId)
                    .on_delete(ForeignKeyAction::Cascade)
                    .on_update(ForeignKeyAction::Cascade),
            )
            .to_string(DbQueryBuilder {}),
    )
    .execute(pool)
    .await?;

    sqlx::query(
        &Table::create()
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
                    .table(PasswordResetTokens::Table, Users::Table)
                    .col(PasswordResetTokens::UserId, Users::UserId)
                    .on_delete(ForeignKeyAction::Cascade)
                    .on_update(ForeignKeyAction::Cascade),
            )
            .to_string(DbQueryBuilder {}),
    )
    .execute(pool)
    .await?;

    Ok(())
}
