use super::{
    handler::{GroupId, UserId, Uuid},
    sql_tables::{
        DbQueryBuilder, DbRow, Groups, Memberships, Metadata, Pool, SchemaVersion, Users,
    },
};
use sea_query::*;
use sea_query_binder::SqlxBinder;
use sqlx::Row;
use tracing::{debug, warn};

pub async fn create_group(group_name: &str, pool: &Pool) -> sqlx::Result<()> {
    let now = chrono::Utc::now();
    let (query, values) = Query::insert()
        .into_table(Groups::Table)
        .columns(vec![
            Groups::DisplayName,
            Groups::CreationDate,
            Groups::Uuid,
        ])
        .values_panic(vec![
            group_name.into(),
            now.naive_utc().into(),
            Uuid::from_name_and_date(group_name, &now).into(),
        ])
        .build_sqlx(DbQueryBuilder {});
    debug!(%query);
    sqlx::query_with(query.as_str(), values)
        .execute(pool)
        .await
        .map(|_| ())
}

pub async fn get_schema_version(pool: &Pool) -> Option<SchemaVersion> {
    sqlx::query(
        &Query::select()
            .from(Metadata::Table)
            .column(Metadata::Version)
            .to_string(DbQueryBuilder {}),
    )
    .map(|row: DbRow| row.get::<SchemaVersion, _>(&*Metadata::Version.to_string()))
    .fetch_one(pool)
    .await
    .ok()
}

pub async fn upgrade_to_v1(pool: &Pool) -> sqlx::Result<()> {
    // SQLite needs this pragma to be turned on. Other DB might not understand this, so ignore the
    // error.
    let _ = sqlx::query("PRAGMA foreign_keys = ON").execute(pool).await;
    sqlx::query(
        &Table::create()
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
            .col(ColumnDef::new(Users::FirstName).string_len(255).not_null())
            .col(ColumnDef::new(Users::LastName).string_len(255).not_null())
            .col(ColumnDef::new(Users::Avatar).binary())
            .col(ColumnDef::new(Users::CreationDate).date_time().not_null())
            .col(ColumnDef::new(Users::PasswordHash).binary())
            .col(ColumnDef::new(Users::TotpSecret).string_len(64))
            .col(ColumnDef::new(Users::MfaType).string_len(64))
            .col(ColumnDef::new(Users::Uuid).string_len(36).not_null())
            .to_string(DbQueryBuilder {}),
    )
    .execute(pool)
    .await?;

    sqlx::query(
        &Table::create()
            .table(Groups::Table)
            .if_not_exists()
            .col(
                ColumnDef::new(Groups::GroupId)
                    .integer()
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
            .col(ColumnDef::new(Users::Uuid).string_len(36).not_null())
            .to_string(DbQueryBuilder {}),
    )
    .execute(pool)
    .await?;

    // If the creation_date column doesn't exist, add it.
    if sqlx::query(
        &Table::alter()
            .table(Groups::Table)
            .add_column(
                ColumnDef::new(Groups::CreationDate)
                    .date_time()
                    .not_null()
                    .default(chrono::Utc::now().naive_utc()),
            )
            .to_string(DbQueryBuilder {}),
    )
    .execute(pool)
    .await
    .is_ok()
    {
        warn!("`creation_date` column not found in `groups`, creating it");
    }

    // If the uuid column doesn't exist, add it.
    if sqlx::query(
        &Table::alter()
            .table(Groups::Table)
            .add_column(
                ColumnDef::new(Groups::Uuid)
                    .string_len(36)
                    .not_null()
                    .default(""),
            )
            .to_string(DbQueryBuilder {}),
    )
    .execute(pool)
    .await
    .is_ok()
    {
        warn!("`uuid` column not found in `groups`, creating it");
        for row in sqlx::query(
            &Query::select()
                .from(Groups::Table)
                .column(Groups::GroupId)
                .column(Groups::DisplayName)
                .column(Groups::CreationDate)
                .to_string(DbQueryBuilder {}),
        )
        .fetch_all(pool)
        .await?
        {
            sqlx::query(
                &Query::update()
                    .table(Groups::Table)
                    .value(
                        Groups::Uuid,
                        Uuid::from_name_and_date(
                            &row.get::<String, _>(&*Groups::DisplayName.to_string()),
                            &row.get::<chrono::DateTime<chrono::Utc>, _>(
                                &*Groups::CreationDate.to_string(),
                            ),
                        )
                        .into(),
                    )
                    .and_where(
                        Expr::col(Groups::GroupId)
                            .eq(row.get::<GroupId, _>(&*Groups::GroupId.to_string())),
                    )
                    .to_string(DbQueryBuilder {}),
            )
            .execute(pool)
            .await?;
        }
    }

    if sqlx::query(
        &Table::alter()
            .table(Users::Table)
            .add_column(
                ColumnDef::new(Users::Uuid)
                    .string_len(36)
                    .not_null()
                    .default(""),
            )
            .to_string(DbQueryBuilder {}),
    )
    .execute(pool)
    .await
    .is_ok()
    {
        warn!("`uuid` column not found in `users`, creating it");
        for row in sqlx::query(
            &Query::select()
                .from(Users::Table)
                .column(Users::UserId)
                .column(Users::CreationDate)
                .to_string(DbQueryBuilder {}),
        )
        .fetch_all(pool)
        .await?
        {
            let user_id = row.get::<UserId, _>(&*Users::UserId.to_string());
            sqlx::query(
                &Query::update()
                    .table(Users::Table)
                    .value(
                        Users::Uuid,
                        Uuid::from_name_and_date(
                            user_id.as_str(),
                            &row.get::<chrono::DateTime<chrono::Utc>, _>(
                                &*Users::CreationDate.to_string(),
                            ),
                        )
                        .into(),
                    )
                    .and_where(Expr::col(Users::UserId).eq(user_id))
                    .to_string(DbQueryBuilder {}),
            )
            .execute(pool)
            .await?;
        }
    }

    sqlx::query(
        &Table::create()
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
            )
            .to_string(DbQueryBuilder {}),
    )
    .execute(pool)
    .await?;

    if sqlx::query(
        &Query::select()
            .from(Groups::Table)
            .column(Groups::DisplayName)
            .cond_where(Expr::col(Groups::DisplayName).eq("lldap_readonly"))
            .to_string(DbQueryBuilder {}),
    )
    .fetch_one(pool)
    .await
    .is_ok()
    {
        sqlx::query(
            &Query::update()
                .table(Groups::Table)
                .values(vec![(Groups::DisplayName, "lldap_password_manager".into())])
                .cond_where(Expr::col(Groups::DisplayName).eq("lldap_readonly"))
                .to_string(DbQueryBuilder {}),
        )
        .execute(pool)
        .await?;
        create_group("lldap_strict_readonly", pool).await?
    }

    sqlx::query(
        &Table::create()
            .table(Metadata::Table)
            .if_not_exists()
            .col(ColumnDef::new(Metadata::Version).tiny_integer().not_null())
            .to_string(DbQueryBuilder {}),
    )
    .execute(pool)
    .await?;

    sqlx::query(
        &Query::insert()
            .into_table(Metadata::Table)
            .columns(vec![Metadata::Version])
            .values_panic(vec![SchemaVersion(1).into()])
            .to_string(DbQueryBuilder {}),
    )
    .execute(pool)
    .await?;

    Ok(())
}

pub async fn migrate_from_version(_pool: &Pool, version: SchemaVersion) -> anyhow::Result<()> {
    if version.0 > 1 {
        anyhow::bail!("DB version downgrading is not supported");
    }
    Ok(())
}
