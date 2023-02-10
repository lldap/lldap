use sea_orm::{
    sea_query::{self, ColumnDef, ForeignKey, ForeignKeyAction, Iden, Table},
    ConnectionTrait,
};

pub use crate::domain::{sql_migrations::Users, sql_tables::DbConnection};

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
