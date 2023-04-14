use crate::domain::{
    sql_tables::{DbConnection, SchemaVersion},
    types::{GroupId, UserId, Uuid},
};
use anyhow::Context;
use itertools::Itertools;
use sea_orm::{
    sea_query::{
        self, all, ColumnDef, Expr, ForeignKey, ForeignKeyAction, Func, Index, Query, Table, Value,
    },
    ConnectionTrait, FromQueryResult, Iden, Order, Statement, TransactionTrait,
};
use serde::{Deserialize, Serialize};
use tracing::{info, instrument, warn};

#[derive(Iden, PartialEq, Eq, Debug, Serialize, Deserialize, Clone, Copy)]
pub enum Users {
    Table,
    UserId,
    Email,
    DisplayName,
    FirstName,
    LastName,
    Avatar,
    CreationDate,
    PasswordHash,
    TotpSecret,
    MfaType,
    Uuid,
}

#[derive(Iden, PartialEq, Eq, Debug, Serialize, Deserialize, Clone, Copy)]
pub enum Groups {
    Table,
    GroupId,
    DisplayName,
    CreationDate,
    Uuid,
}

#[derive(Iden, Clone, Copy)]
pub enum Memberships {
    Table,
    UserId,
    GroupId,
}

// Metadata about the SQL DB.
#[derive(Iden)]
pub enum Metadata {
    Table,
    // Which version of the schema we're at.
    Version,
}

#[derive(FromQueryResult, PartialEq, Eq, Debug)]
pub struct JustSchemaVersion {
    pub version: SchemaVersion,
}

#[instrument(skip_all, level = "debug", ret)]
pub async fn get_schema_version(pool: &DbConnection) -> Option<SchemaVersion> {
    JustSchemaVersion::find_by_statement(
        pool.get_database_backend().build(
            Query::select()
                .from(Metadata::Table)
                .column(Metadata::Version),
        ),
    )
    .one(pool)
    .await
    .ok()
    .flatten()
    .map(|j| j.version)
}

pub async fn upgrade_to_v1(pool: &DbConnection) -> std::result::Result<(), sea_orm::DbErr> {
    let builder = pool.get_database_backend();
    // SQLite needs this pragma to be turned on. Other DB might not understand this, so ignore the
    // error.
    let _ = pool
        .execute(Statement::from_string(
            builder,
            "PRAGMA foreign_keys = ON".to_owned(),
        ))
        .await;

    pool.execute(
        builder.build(
            Table::create()
                .table(Users::Table)
                .if_not_exists()
                .col(
                    ColumnDef::new(Users::UserId)
                        .string_len(255)
                        .not_null()
                        .primary_key(),
                )
                .col(ColumnDef::new(Users::Email).string_len(255).not_null())
                .col(
                    ColumnDef::new(Users::DisplayName)
                        .string_len(255)
                        .not_null(),
                )
                .col(ColumnDef::new(Users::FirstName).string_len(255))
                .col(ColumnDef::new(Users::LastName).string_len(255))
                .col(ColumnDef::new(Users::Avatar).binary())
                .col(ColumnDef::new(Users::CreationDate).date_time().not_null())
                .col(ColumnDef::new(Users::PasswordHash).binary())
                .col(ColumnDef::new(Users::TotpSecret).string_len(64))
                .col(ColumnDef::new(Users::MfaType).string_len(64))
                .col(ColumnDef::new(Users::Uuid).string_len(36).not_null()),
        ),
    )
    .await?;

    pool.execute(
        builder.build(
            Table::create()
                .table(Groups::Table)
                .if_not_exists()
                .col(
                    ColumnDef::new(Groups::GroupId)
                        .integer()
                        .auto_increment()
                        .not_null()
                        .primary_key(),
                )
                .col(
                    ColumnDef::new(Groups::DisplayName)
                        .string_len(255)
                        .unique_key()
                        .not_null(),
                )
                .col(ColumnDef::new(Users::CreationDate).date_time().not_null())
                .col(ColumnDef::new(Users::Uuid).string_len(36).not_null()),
        ),
    )
    .await?;

    // If the creation_date column doesn't exist, add it.
    if pool
        .execute(
            builder.build(
                Table::alter().table(Groups::Table).add_column(
                    ColumnDef::new(Groups::CreationDate)
                        .date_time()
                        .not_null()
                        .default(chrono::Utc::now().naive_utc()),
                ),
            ),
        )
        .await
        .is_ok()
    {
        warn!("`creation_date` column not found in `groups`, creating it");
    }

    // If the uuid column doesn't exist, add it.
    if pool
        .execute(
            builder.build(
                Table::alter().table(Groups::Table).add_column(
                    ColumnDef::new(Groups::Uuid)
                        .string_len(36)
                        .not_null()
                        .default(""),
                ),
            ),
        )
        .await
        .is_ok()
    {
        warn!("`uuid` column not found in `groups`, creating it");
        #[derive(FromQueryResult)]
        struct ShortGroupDetails {
            group_id: GroupId,
            display_name: String,
            creation_date: chrono::NaiveDateTime,
        }
        for result in ShortGroupDetails::find_by_statement(
            builder.build(
                Query::select()
                    .from(Groups::Table)
                    .column(Groups::GroupId)
                    .column(Groups::DisplayName)
                    .column(Groups::CreationDate),
            ),
        )
        .all(pool)
        .await?
        {
            pool.execute(
                builder.build(
                    Query::update()
                        .table(Groups::Table)
                        .value(
                            Groups::Uuid,
                            Value::from(Uuid::from_name_and_date(
                                &result.display_name,
                                &result.creation_date,
                            )),
                        )
                        .and_where(Expr::col(Groups::GroupId).eq(result.group_id)),
                ),
            )
            .await?;
        }
    }

    if pool
        .execute(
            builder.build(
                Table::alter().table(Users::Table).add_column(
                    ColumnDef::new(Users::Uuid)
                        .string_len(36)
                        .not_null()
                        .default(""),
                ),
            ),
        )
        .await
        .is_ok()
    {
        warn!("`uuid` column not found in `users`, creating it");
        #[derive(FromQueryResult)]
        struct ShortUserDetails {
            user_id: UserId,
            creation_date: chrono::NaiveDateTime,
        }
        for result in ShortUserDetails::find_by_statement(
            builder.build(
                Query::select()
                    .from(Users::Table)
                    .column(Users::UserId)
                    .column(Users::CreationDate),
            ),
        )
        .all(pool)
        .await?
        {
            pool.execute(
                builder.build(
                    Query::update()
                        .table(Users::Table)
                        .value(
                            Users::Uuid,
                            Value::from(Uuid::from_name_and_date(
                                result.user_id.as_str(),
                                &result.creation_date,
                            )),
                        )
                        .and_where(Expr::col(Users::UserId).eq(result.user_id)),
                ),
            )
            .await?;
        }
    }

    pool.execute(
        builder.build(
            Table::create()
                .table(Memberships::Table)
                .if_not_exists()
                .col(
                    ColumnDef::new(Memberships::UserId)
                        .string_len(255)
                        .not_null(),
                )
                .col(ColumnDef::new(Memberships::GroupId).integer().not_null())
                .foreign_key(
                    ForeignKey::create()
                        .name("MembershipUserForeignKey")
                        .from(Memberships::Table, Memberships::UserId)
                        .to(Users::Table, Users::UserId)
                        .on_delete(ForeignKeyAction::Cascade)
                        .on_update(ForeignKeyAction::Cascade),
                )
                .foreign_key(
                    ForeignKey::create()
                        .name("MembershipGroupForeignKey")
                        .from(Memberships::Table, Memberships::GroupId)
                        .to(Groups::Table, Groups::GroupId)
                        .on_delete(ForeignKeyAction::Cascade)
                        .on_update(ForeignKeyAction::Cascade),
                ),
        ),
    )
    .await?;

    if pool
        .query_one(
            builder.build(
                Query::select()
                    .from(Groups::Table)
                    .column(Groups::DisplayName)
                    .cond_where(Expr::col(Groups::DisplayName).eq("lldap_readonly")),
            ),
        )
        .await
        .is_ok()
    {
        pool.execute(
            builder.build(
                Query::update()
                    .table(Groups::Table)
                    .values(vec![(Groups::DisplayName, "lldap_password_manager".into())])
                    .cond_where(Expr::col(Groups::DisplayName).eq("lldap_readonly")),
            ),
        )
        .await?;
    }

    pool.execute(
        builder.build(
            Table::create()
                .table(Metadata::Table)
                .if_not_exists()
                .col(ColumnDef::new(Metadata::Version).small_integer()),
        ),
    )
    .await?;

    pool.execute(
        builder.build(
            Query::insert()
                .into_table(Metadata::Table)
                .columns(vec![Metadata::Version])
                .values_panic(vec![SchemaVersion(1).into()]),
        ),
    )
    .await?;

    assert_eq!(get_schema_version(pool).await.unwrap().0, 1);

    Ok(())
}

async fn replace_column<I: Iden + Copy + 'static, const N: usize>(
    pool: &DbConnection,
    table_name: I,
    column_name: I,
    mut new_column: ColumnDef,
    update_values: [Statement; N],
) -> anyhow::Result<()> {
    // Update the definition of a column (in a compatible way). Due to Sqlite, this is more complicated:
    //  - rename the column to a temporary name
    //  - create the column with the new definition
    //  - copy the data from the temp column to the new one
    //  - update the new one if there are changes needed
    //  - drop the old one
    let builder = pool.get_database_backend();
    pool.transaction::<_, (), sea_orm::DbErr>(move |transaction| {
        Box::pin(async move {
            #[derive(Iden)]
            enum TempTable {
                TempName,
            }
            transaction
                .execute(
                    builder.build(
                        Table::alter()
                            .table(table_name)
                            .rename_column(column_name, TempTable::TempName),
                    ),
                )
                .await?;
            transaction
                .execute(
                    builder.build(Table::alter().table(table_name).add_column(&mut new_column)),
                )
                .await?;
            transaction
                .execute(
                    builder.build(
                        Query::update()
                            .table(table_name)
                            .value(column_name, Expr::col((table_name, TempTable::TempName))),
                    ),
                )
                .await?;
            for statement in update_values {
                transaction.execute(statement).await?;
            }
            transaction
                .execute(
                    builder.build(
                        Table::alter()
                            .table(table_name)
                            .drop_column(TempTable::TempName),
                    ),
                )
                .await?;
            Ok(())
        })
    })
    .await?;
    Ok(())
}

async fn migrate_to_v2(pool: &DbConnection) -> anyhow::Result<()> {
    let builder = pool.get_database_backend();
    // Allow nulls in DisplayName, and change empty string to null.
    replace_column(
        pool,
        Users::Table,
        Users::DisplayName,
        ColumnDef::new(Users::DisplayName)
            .string_len(255)
            .to_owned(),
        [builder.build(
            Query::update()
                .table(Users::Table)
                .value(Users::DisplayName, Option::<String>::None)
                .cond_where(Expr::col(Users::DisplayName).eq("")),
        )],
    )
    .await?;
    Ok(())
}

async fn migrate_to_v3(pool: &DbConnection) -> anyhow::Result<()> {
    let builder = pool.get_database_backend();
    // Allow nulls in First and LastName. Users who created their DB in 0.4.1 have the not null constraint.
    replace_column(
        pool,
        Users::Table,
        Users::FirstName,
        ColumnDef::new(Users::FirstName).string_len(255).to_owned(),
        [builder.build(
            Query::update()
                .table(Users::Table)
                .value(Users::FirstName, Option::<String>::None)
                .cond_where(Expr::col(Users::FirstName).eq("")),
        )],
    )
    .await?;
    replace_column(
        pool,
        Users::Table,
        Users::LastName,
        ColumnDef::new(Users::LastName).string_len(255).to_owned(),
        [builder.build(
            Query::update()
                .table(Users::Table)
                .value(Users::LastName, Option::<String>::None)
                .cond_where(Expr::col(Users::LastName).eq("")),
        )],
    )
    .await?;
    // Change Avatar from binary to blob(long), because for MySQL this is 64kb.
    replace_column(
        pool,
        Users::Table,
        Users::Avatar,
        ColumnDef::new(Users::Avatar)
            .blob(sea_query::BlobSize::Long)
            .to_owned(),
        [],
    )
    .await?;
    Ok(())
}

async fn migrate_to_v4(pool: &DbConnection) -> anyhow::Result<()> {
    let builder = pool.get_database_backend();
    // Make emails and UUIDs unique.
    if let Err(e) = pool
        .execute(
            builder.build(
                Index::create()
                    .if_not_exists()
                    .name("unique-user-email")
                    .table(Users::Table)
                    .col(Users::Email)
                    .unique(),
            ),
        )
        .await
        .context(
            r#"while enforcing unicity on emails (2 users have the same email).

See https://github.com/lldap/lldap/blob/main/docs/migration_guides/v0.5.md for details.

"#,
        )
    {
        warn!("Found several users with the same email:");
        for (email, users) in &pool
            .query_all(
                builder.build(
                    Query::select()
                        .from(Users::Table)
                        .columns([Users::Email, Users::UserId])
                        .order_by_columns([(Users::Email, Order::Asc), (Users::UserId, Order::Asc)])
                        .and_where(
                            Expr::col(Users::Email).in_subquery(
                                Query::select()
                                    .from(Users::Table)
                                    .column(Users::Email)
                                    .group_by_col(Users::Email)
                                    .cond_having(all![Expr::gt(
                                        Expr::expr(Func::count(Expr::col(Users::Email))),
                                        1
                                    )])
                                    .take(),
                            ),
                        ),
                ),
            )
            .await
            .expect("Could not check duplicate users")
            .into_iter()
            .map(|row| {
                (
                    row.try_get::<UserId>("", &Users::UserId.to_string())
                        .unwrap(),
                    row.try_get::<String>("", &Users::Email.to_string())
                        .unwrap(),
                )
            })
            .group_by(|(_user, email)| email.to_owned())
        {
            warn!("Email: {email}");
            for (user, _email) in users {
                warn!("    User: {}", user.as_str());
            }
        }
        return Err(e);
    }
    pool.execute(
        builder.build(
            Index::create()
                .if_not_exists()
                .name("unique-user-uuid")
                .table(Users::Table)
                .col(Users::Uuid)
                .unique(),
        ),
    )
    .await
    .context("while enforcing unicity on user UUIDs (2 users have the same UUID)")?;
    pool.execute(
        builder.build(
            Index::create()
                .if_not_exists()
                .name("unique-group-uuid")
                .table(Groups::Table)
                .col(Groups::Uuid)
                .unique(),
        ),
    )
    .await
    .context("while enforcing unicity on group UUIDs (2 groups have the same UUID)")?;
    Ok(())
}

// This is needed to make an array of async functions.
macro_rules! to_sync {
    ($l:ident) => {
        |pool| -> std::pin::Pin<Box<dyn std::future::Future<Output = anyhow::Result<()>>>> {
            Box::pin($l(pool))
        }
    };
}

pub async fn migrate_from_version(
    pool: &DbConnection,
    version: SchemaVersion,
    last_version: SchemaVersion,
) -> anyhow::Result<()> {
    match version.cmp(&last_version) {
        std::cmp::Ordering::Less => (),
        std::cmp::Ordering::Equal => return Ok(()),
        std::cmp::Ordering::Greater => anyhow::bail!("DB version downgrading is not supported"),
    }
    let migrations = [
        to_sync!(migrate_to_v2),
        to_sync!(migrate_to_v3),
        to_sync!(migrate_to_v4),
    ];
    for migration in 2..=4 {
        if version < SchemaVersion(migration) && SchemaVersion(migration) <= last_version {
            info!("Upgrading DB schema from {} to {}", version.0, migration);
            migrations[(migration - 2) as usize](pool).await?;
        }
    }
    let builder = pool.get_database_backend();
    pool.execute(
        builder.build(
            Query::update()
                .table(Metadata::Table)
                .value(Metadata::Version, Value::from(last_version)),
        ),
    )
    .await?;
    Ok(())
}
