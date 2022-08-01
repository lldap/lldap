use super::handler::{GroupId, UserId, Uuid};
use sea_query::*;
use sea_query_binder::SqlxBinder;
use sqlx::Row;
use tracing::{debug, warn};

pub type Pool = sqlx::sqlite::SqlitePool;
pub type PoolOptions = sqlx::sqlite::SqlitePoolOptions;
pub type DbRow = sqlx::sqlite::SqliteRow;
pub type DbQueryBuilder = SqliteQueryBuilder;

impl From<GroupId> for Value {
    fn from(group_id: GroupId) -> Self {
        group_id.0.into()
    }
}

impl From<UserId> for sea_query::Value {
    fn from(user_id: UserId) -> Self {
        user_id.into_string().into()
    }
}

impl From<&UserId> for sea_query::Value {
    fn from(user_id: &UserId) -> Self {
        user_id.as_str().into()
    }
}

impl From<Uuid> for sea_query::Value {
    fn from(uuid: Uuid) -> Self {
        uuid.as_str().into()
    }
}

impl From<&Uuid> for sea_query::Value {
    fn from(uuid: &Uuid) -> Self {
        uuid.as_str().into()
    }
}

#[derive(Iden)]
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

#[derive(Iden)]
pub enum Groups {
    Table,
    GroupId,
    DisplayName,
    CreationDate,
    Uuid,
}

#[derive(Iden)]
pub enum Memberships {
    Table,
    UserId,
    GroupId,
}

async fn column_exists(pool: &Pool, table_name: &str, column_name: &str) -> sqlx::Result<bool> {
    // Sqlite specific
    let query = format!(
        "SELECT COUNT(*) AS col_count FROM pragma_table_info('{}') WHERE name = '{}'",
        table_name, column_name
    );
    match sqlx::query(&query).fetch_one(pool).await {
        Err(_) => Ok(false),
        Ok(row) => Ok(row.get::<i32, _>("col_count") > 0),
    }
}

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

pub async fn init_table(pool: &Pool) -> sqlx::Result<()> {
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
    if !column_exists(
        pool,
        &*Groups::Table.to_string(),
        &*Groups::CreationDate.to_string(),
    )
    .await?
    {
        warn!("`creation_date` column not found in `groups`, creating it");
        sqlx::query(
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
        .await?;
    }

    // If the uuid column doesn't exist, add it.
    if !column_exists(
        pool,
        &*Groups::Table.to_string(),
        &*Groups::Uuid.to_string(),
    )
    .await?
    {
        warn!("`uuid` column not found in `groups`, creating it");
        sqlx::query(
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
        .await?;
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

    if !column_exists(pool, &*Users::Table.to_string(), &*Users::Uuid.to_string()).await? {
        warn!("`uuid` column not found in `users`, creating it");
        sqlx::query(
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
        .await?;
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

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::prelude::*;
    use sqlx::{Column, Row};

    #[tokio::test]
    async fn test_init_table() {
        let sql_pool = PoolOptions::new().connect("sqlite::memory:").await.unwrap();
        init_table(&sql_pool).await.unwrap();
        sqlx::query(r#"INSERT INTO users
      (user_id, email, display_name, first_name, last_name, creation_date, password_hash, uuid)
      VALUES ("bôb", "böb@bob.bob", "Bob Bobbersön", "Bob", "Bobberson", "1970-01-01 00:00:00", "bob00", "abc")"#).execute(&sql_pool).await.unwrap();
        let row =
            sqlx::query(r#"SELECT display_name, creation_date FROM users WHERE user_id = "bôb""#)
                .fetch_one(&sql_pool)
                .await
                .unwrap();
        assert_eq!(row.column(0).name(), "display_name");
        assert_eq!(row.get::<String, _>("display_name"), "Bob Bobbersön");
        assert_eq!(
            row.get::<DateTime<Utc>, _>("creation_date"),
            Utc.timestamp(0, 0),
        );
    }

    #[tokio::test]
    async fn test_already_init_table() {
        let sql_pool = PoolOptions::new().connect("sqlite::memory:").await.unwrap();
        init_table(&sql_pool).await.unwrap();
        init_table(&sql_pool).await.unwrap();
    }

    #[tokio::test]
    async fn test_migrate_tables() {
        // Test that we add the column creation_date to groups and uuid to users and groups.
        let sql_pool = PoolOptions::new().connect("sqlite::memory:").await.unwrap();
        sqlx::query(r#"CREATE TABLE users ( user_id TEXT , creation_date TEXT);"#)
            .execute(&sql_pool)
            .await
            .unwrap();
        sqlx::query(
            r#"INSERT INTO users (user_id, creation_date)
                       VALUES ("bôb", "1970-01-01 00:00:00")"#,
        )
        .execute(&sql_pool)
        .await
        .unwrap();
        sqlx::query(r#"CREATE TABLE groups ( group_id INTEGER PRIMARY KEY, display_name TEXT );"#)
            .execute(&sql_pool)
            .await
            .unwrap();
        sqlx::query(
            r#"INSERT INTO groups (display_name)
                      VALUES ("lldap_admin"), ("lldap_readonly")"#,
        )
        .execute(&sql_pool)
        .await
        .unwrap();
        init_table(&sql_pool).await.unwrap();
        sqlx::query(
            r#"INSERT INTO groups (display_name, creation_date, uuid)
                      VALUES ("test", "1970-01-01 00:00:00", "abc")"#,
        )
        .execute(&sql_pool)
        .await
        .unwrap();
        assert_eq!(
            sqlx::query(r#"SELECT uuid FROM users"#)
                .fetch_all(&sql_pool)
                .await
                .unwrap()
                .into_iter()
                .map(|row| row.get::<Uuid, _>("uuid"))
                .collect::<Vec<_>>(),
            vec![crate::uuid!("a02eaf13-48a7-30f6-a3d4-040ff7c52b04")]
        );
        assert_eq!(
            sqlx::query(r#"SELECT group_id, display_name FROM groups"#)
                .fetch_all(&sql_pool)
                .await
                .unwrap()
                .into_iter()
                .map(|row| (
                    row.get::<GroupId, _>("group_id"),
                    row.get::<String, _>("display_name")
                ))
                .collect::<Vec<_>>(),
            vec![
                (GroupId(1), "lldap_admin".to_string()),
                (GroupId(2), "lldap_password_manager".to_string()),
                (GroupId(3), "lldap_strict_readonly".to_string()),
                (GroupId(4), "test".to_string())
            ]
        );
    }
}
