use crate::domain::{
    sql_tables::{DbConnection, SchemaVersion, LAST_SCHEMA_VERSION},
    types::{AttributeType, GroupId, JpegPhoto, Serialized, UserId, Uuid},
};
use itertools::Itertools;
use sea_orm::{
    sea_query::{
        self, all, ColumnDef, Expr, ForeignKey, ForeignKeyAction, Func, Index, Query, Table, Value,
    },
    ConnectionTrait, DatabaseTransaction, DbErr, DeriveIden, FromQueryResult, Iden, Order,
    Statement, TransactionTrait,
};
use serde::{Deserialize, Serialize};
use tracing::{error, info, instrument, warn};

#[derive(DeriveIden, PartialEq, Eq, Debug, Serialize, Deserialize, Clone, Copy)]
pub enum Users {
    Table,
    UserId,
    Email,
    LowercaseEmail,
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

#[derive(DeriveIden, PartialEq, Eq, Debug, Serialize, Deserialize, Clone, Copy)]
pub enum Groups {
    Table,
    GroupId,
    DisplayName,
    LowercaseDisplayName,
    CreationDate,
    Uuid,
}

#[derive(DeriveIden, Clone, Copy)]
pub enum Memberships {
    Table,
    UserId,
    GroupId,
}

#[derive(DeriveIden, PartialEq, Eq, Debug, Serialize, Deserialize, Clone, Copy)]
pub enum UserAttributeSchema {
    Table,
    UserAttributeSchemaName,
    UserAttributeSchemaType,
    UserAttributeSchemaIsList,
    UserAttributeSchemaIsUserVisible,
    UserAttributeSchemaIsUserEditable,
    UserAttributeSchemaIsHardcoded,
}

#[derive(DeriveIden, PartialEq, Eq, Debug, Serialize, Deserialize, Clone, Copy)]
pub enum UserAttributes {
    Table,
    UserAttributeUserId,
    UserAttributeName,
    UserAttributeValue,
}

#[derive(DeriveIden, PartialEq, Eq, Debug, Serialize, Deserialize, Clone, Copy)]
pub enum GroupAttributeSchema {
    Table,
    GroupAttributeSchemaName,
    GroupAttributeSchemaType,
    GroupAttributeSchemaIsList,
    GroupAttributeSchemaIsGroupVisible,
    GroupAttributeSchemaIsGroupEditable,
    GroupAttributeSchemaIsHardcoded,
}

#[derive(DeriveIden, PartialEq, Eq, Debug, Serialize, Deserialize, Clone, Copy)]
pub enum GroupAttributes {
    Table,
    GroupAttributeGroupId,
    GroupAttributeName,
    GroupAttributeValue,
}

// Metadata about the SQL DB.
#[derive(DeriveIden)]
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
    transaction: DatabaseTransaction,
    table_name: I,
    column_name: I,
    mut new_column: ColumnDef,
    update_values: [Statement; N],
) -> Result<DatabaseTransaction, DbErr> {
    // Update the definition of a column (in a compatible way). Due to Sqlite, this is more complicated:
    //  - rename the column to a temporary name
    //  - create the column with the new definition
    //  - copy the data from the temp column to the new one
    //  - update the new one if there are changes needed
    //  - drop the old one
    let builder = transaction.get_database_backend();
    #[derive(DeriveIden)]
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
        .execute(builder.build(Table::alter().table(table_name).add_column(&mut new_column)))
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
    Ok(transaction)
}

async fn migrate_to_v2(transaction: DatabaseTransaction) -> Result<DatabaseTransaction, DbErr> {
    let builder = transaction.get_database_backend();
    // Allow nulls in DisplayName, and change empty string to null.
    let transaction = replace_column(
        transaction,
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
    Ok(transaction)
}

async fn migrate_to_v3(transaction: DatabaseTransaction) -> Result<DatabaseTransaction, DbErr> {
    let builder = transaction.get_database_backend();
    // Allow nulls in First and LastName. Users who created their DB in 0.4.1 have the not null constraint.
    let transaction = replace_column(
        transaction,
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
    let transaction = replace_column(
        transaction,
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
    let transaction = replace_column(
        transaction,
        Users::Table,
        Users::Avatar,
        ColumnDef::new(Users::Avatar)
            .blob(sea_query::BlobSize::Long)
            .to_owned(),
        [],
    )
    .await?;
    Ok(transaction)
}

async fn migrate_to_v4(transaction: DatabaseTransaction) -> Result<DatabaseTransaction, DbErr> {
    let builder = transaction.get_database_backend();
    // Make emails and UUIDs unique.
    if let Err(e) = transaction
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
    {
        error!(
            r#"Found several users with the same email.

See https://github.com/lldap/lldap/blob/main/docs/migration_guides/v0.5.md for details.

Conflicting emails:
"#,
        );
        for (email, users) in &transaction
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
    transaction
        .execute(
            builder.build(
                Index::create()
                    .if_not_exists()
                    .name("unique-user-uuid")
                    .table(Users::Table)
                    .col(Users::Uuid)
                    .unique(),
            ),
        )
        .await?;
    transaction
        .execute(
            builder.build(
                Index::create()
                    .if_not_exists()
                    .name("unique-group-uuid")
                    .table(Groups::Table)
                    .col(Groups::Uuid)
                    .unique(),
            ),
        )
        .await?;
    Ok(transaction)
}

async fn migrate_to_v5(transaction: DatabaseTransaction) -> Result<DatabaseTransaction, DbErr> {
    let builder = transaction.get_database_backend();
    transaction
        .execute(
            builder.build(
                Table::create()
                    .table(UserAttributeSchema::Table)
                    .col(
                        ColumnDef::new(UserAttributeSchema::UserAttributeSchemaName)
                            .string_len(64)
                            .not_null()
                            .primary_key(),
                    )
                    .col(
                        ColumnDef::new(UserAttributeSchema::UserAttributeSchemaType)
                            .string_len(64)
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(UserAttributeSchema::UserAttributeSchemaIsList)
                            .boolean()
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(UserAttributeSchema::UserAttributeSchemaIsUserVisible)
                            .boolean()
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(UserAttributeSchema::UserAttributeSchemaIsUserEditable)
                            .boolean()
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(UserAttributeSchema::UserAttributeSchemaIsHardcoded)
                            .boolean()
                            .not_null(),
                    ),
            ),
        )
        .await?;

    transaction
        .execute(
            builder.build(
                Table::create()
                    .table(GroupAttributeSchema::Table)
                    .col(
                        ColumnDef::new(GroupAttributeSchema::GroupAttributeSchemaName)
                            .string_len(64)
                            .not_null()
                            .primary_key(),
                    )
                    .col(
                        ColumnDef::new(GroupAttributeSchema::GroupAttributeSchemaType)
                            .string_len(64)
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(GroupAttributeSchema::GroupAttributeSchemaIsList)
                            .boolean()
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(GroupAttributeSchema::GroupAttributeSchemaIsGroupVisible)
                            .boolean()
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(GroupAttributeSchema::GroupAttributeSchemaIsGroupEditable)
                            .boolean()
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(GroupAttributeSchema::GroupAttributeSchemaIsHardcoded)
                            .boolean()
                            .not_null(),
                    ),
            ),
        )
        .await?;

    transaction
        .execute(
            builder.build(
                Table::create()
                    .table(UserAttributes::Table)
                    .col(
                        ColumnDef::new(UserAttributes::UserAttributeUserId)
                            .string_len(255)
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(UserAttributes::UserAttributeName)
                            .string_len(64)
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(UserAttributes::UserAttributeValue)
                            .blob(sea_query::BlobSize::Long)
                            .not_null(),
                    )
                    .foreign_key(
                        ForeignKey::create()
                            .name("UserAttributeUserIdForeignKey")
                            .from(UserAttributes::Table, UserAttributes::UserAttributeUserId)
                            .to(Users::Table, Users::UserId)
                            .on_delete(ForeignKeyAction::Cascade)
                            .on_update(ForeignKeyAction::Cascade),
                    )
                    .foreign_key(
                        ForeignKey::create()
                            .name("UserAttributeNameForeignKey")
                            .from(UserAttributes::Table, UserAttributes::UserAttributeName)
                            .to(
                                UserAttributeSchema::Table,
                                UserAttributeSchema::UserAttributeSchemaName,
                            )
                            .on_delete(ForeignKeyAction::Cascade)
                            .on_update(ForeignKeyAction::Cascade),
                    )
                    .primary_key(
                        Index::create()
                            .col(UserAttributes::UserAttributeUserId)
                            .col(UserAttributes::UserAttributeName),
                    ),
            ),
        )
        .await?;

    transaction
        .execute(
            builder.build(
                Table::create()
                    .table(GroupAttributes::Table)
                    .col(
                        ColumnDef::new(GroupAttributes::GroupAttributeGroupId)
                            .integer()
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(GroupAttributes::GroupAttributeName)
                            .string_len(64)
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(GroupAttributes::GroupAttributeValue)
                            .blob(sea_query::BlobSize::Long)
                            .not_null(),
                    )
                    .foreign_key(
                        ForeignKey::create()
                            .name("GroupAttributeGroupIdForeignKey")
                            .from(
                                GroupAttributes::Table,
                                GroupAttributes::GroupAttributeGroupId,
                            )
                            .to(Groups::Table, Groups::GroupId)
                            .on_delete(ForeignKeyAction::Cascade)
                            .on_update(ForeignKeyAction::Cascade),
                    )
                    .foreign_key(
                        ForeignKey::create()
                            .name("GroupAttributeNameForeignKey")
                            .from(GroupAttributes::Table, GroupAttributes::GroupAttributeName)
                            .to(
                                GroupAttributeSchema::Table,
                                GroupAttributeSchema::GroupAttributeSchemaName,
                            )
                            .on_delete(ForeignKeyAction::Cascade)
                            .on_update(ForeignKeyAction::Cascade),
                    )
                    .primary_key(
                        Index::create()
                            .col(GroupAttributes::GroupAttributeGroupId)
                            .col(GroupAttributes::GroupAttributeName),
                    ),
            ),
        )
        .await?;

    transaction
        .execute(
            builder.build(
                Query::insert()
                    .into_table(UserAttributeSchema::Table)
                    .columns([
                        UserAttributeSchema::UserAttributeSchemaName,
                        UserAttributeSchema::UserAttributeSchemaType,
                        UserAttributeSchema::UserAttributeSchemaIsList,
                        UserAttributeSchema::UserAttributeSchemaIsUserVisible,
                        UserAttributeSchema::UserAttributeSchemaIsUserEditable,
                        UserAttributeSchema::UserAttributeSchemaIsHardcoded,
                    ])
                    .values_panic([
                        "first_name".into(),
                        AttributeType::String.into(),
                        false.into(),
                        true.into(),
                        true.into(),
                        true.into(),
                    ])
                    .values_panic([
                        "last_name".into(),
                        AttributeType::String.into(),
                        false.into(),
                        true.into(),
                        true.into(),
                        true.into(),
                    ])
                    .values_panic([
                        "avatar".into(),
                        AttributeType::JpegPhoto.into(),
                        false.into(),
                        true.into(),
                        true.into(),
                        true.into(),
                    ]),
            ),
        )
        .await?;

    {
        let mut user_statement = Query::insert()
            .into_table(UserAttributes::Table)
            .columns([
                UserAttributes::UserAttributeUserId,
                UserAttributes::UserAttributeName,
                UserAttributes::UserAttributeValue,
            ])
            .to_owned();
        #[derive(FromQueryResult)]
        struct FullUserDetails {
            user_id: UserId,
            first_name: Option<String>,
            last_name: Option<String>,
            avatar: Option<JpegPhoto>,
        }
        let mut any_user = false;
        for user in FullUserDetails::find_by_statement(builder.build(
            Query::select().from(Users::Table).columns([
                Users::UserId,
                Users::FirstName,
                Users::LastName,
                Users::Avatar,
            ]),
        ))
        .all(&transaction)
        .await?
        {
            if let Some(name) = &user.first_name {
                any_user = true;
                user_statement.values_panic([
                    user.user_id.clone().into(),
                    "first_name".into(),
                    Serialized::from(name).into(),
                ]);
            }
            if let Some(name) = &user.last_name {
                any_user = true;
                user_statement.values_panic([
                    user.user_id.clone().into(),
                    "last_name".into(),
                    Serialized::from(name).into(),
                ]);
            }
            if let Some(avatar) = &user.avatar {
                any_user = true;
                user_statement.values_panic([
                    user.user_id.clone().into(),
                    "avatar".into(),
                    Serialized::from(avatar).into(),
                ]);
            }
        }

        if any_user {
            transaction.execute(builder.build(&user_statement)).await?;
        }
    }

    for column in [Users::FirstName, Users::LastName, Users::Avatar] {
        transaction
            .execute(builder.build(Table::alter().table(Users::Table).drop_column(column)))
            .await?;
    }

    Ok(transaction)
}

async fn migrate_to_v6(transaction: DatabaseTransaction) -> Result<DatabaseTransaction, DbErr> {
    let builder = transaction.get_database_backend();
    transaction
        .execute(
            builder.build(
                Table::alter().table(Groups::Table).add_column(
                    ColumnDef::new(Groups::LowercaseDisplayName)
                        .string_len(255)
                        .not_null()
                        .default("UNSET"),
                ),
            ),
        )
        .await?;
    transaction
        .execute(
            builder.build(
                Table::alter().table(Users::Table).add_column(
                    ColumnDef::new(Users::LowercaseEmail)
                        .string_len(255)
                        .not_null()
                        .default("UNSET"),
                ),
            ),
        )
        .await?;

    transaction
        .execute(builder.build(Query::update().table(Groups::Table).value(
            Groups::LowercaseDisplayName,
            Func::lower(Expr::col(Groups::DisplayName)),
        )))
        .await?;

    transaction
        .execute(
            builder.build(
                Query::update()
                    .table(Users::Table)
                    .value(Users::LowercaseEmail, Func::lower(Expr::col(Users::Email))),
            ),
        )
        .await?;

    Ok(transaction)
}

// This is needed to make an array of async functions.
macro_rules! to_sync {
    ($l:ident) => {
        move |transaction| -> std::pin::Pin<
            Box<dyn std::future::Future<Output = Result<DatabaseTransaction, DbErr>>>,
        > { Box::pin($l(transaction)) }
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
    info!("Upgrading DB schema from version {}", version.0);
    let migrations = [
        to_sync!(migrate_to_v2),
        to_sync!(migrate_to_v3),
        to_sync!(migrate_to_v4),
        to_sync!(migrate_to_v5),
        to_sync!(migrate_to_v6),
    ];
    assert_eq!(migrations.len(), (LAST_SCHEMA_VERSION.0 - 1) as usize);
    for migration in 2..=last_version.0 {
        if version < SchemaVersion(migration) && SchemaVersion(migration) <= last_version {
            info!("Upgrading DB schema to version {}", migration);
            let transaction = pool.begin().await?;
            let transaction = migrations[(migration - 2) as usize](transaction).await?;
            let builder = transaction.get_database_backend();
            transaction
                .execute(
                    builder.build(
                        Query::update()
                            .table(Metadata::Table)
                            .value(Metadata::Version, Value::from(migration)),
                    ),
                )
                .await?;
            transaction.commit().await?;
        }
    }
    Ok(())
}
