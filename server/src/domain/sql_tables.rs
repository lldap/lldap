use super::{
    handler::{GroupId, UserId, Uuid},
    sql_migrations::{get_schema_version, migrate_from_version, upgrade_to_v1},
};
use sea_query::*;

pub use super::sql_migrations::create_group;

pub type Pool = sqlx::sqlite::SqlitePool;
pub type PoolOptions = sqlx::sqlite::SqlitePoolOptions;
pub type DbRow = sqlx::sqlite::SqliteRow;
pub type DbQueryBuilder = SqliteQueryBuilder;

#[derive(Copy, PartialEq, Eq, Debug, Clone, sqlx::FromRow, sqlx::Type)]
#[sqlx(transparent)]
pub struct SchemaVersion(pub u8);

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

impl From<SchemaVersion> for Value {
    fn from(version: SchemaVersion) -> Self {
        version.0.into()
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

// Metadata about the SQL DB.
#[derive(Iden)]
pub enum Metadata {
    Table,
    // Which version of the schema we're at.
    Version,
}

pub async fn init_table(pool: &Pool) -> anyhow::Result<()> {
    let version = {
        if let Some(version) = get_schema_version(pool).await {
            version
        } else {
            upgrade_to_v1(pool).await?;
            SchemaVersion(1)
        }
    };
    migrate_from_version(pool, version).await?;
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
        assert_eq!(
            sqlx::query(r#"SELECT version FROM metadata"#)
                .map(|row: DbRow| row.get::<SchemaVersion, _>("version"))
                .fetch_one(&sql_pool)
                .await
                .unwrap(),
            SchemaVersion(1)
        );
    }

    #[tokio::test]
    async fn test_too_high_version() {
        let sql_pool = PoolOptions::new().connect("sqlite::memory:").await.unwrap();
        sqlx::query(r#"CREATE TABLE metadata ( version INTEGER);"#)
            .execute(&sql_pool)
            .await
            .unwrap();
        sqlx::query(
            r#"INSERT INTO metadata (version)
                       VALUES (127)"#,
        )
        .execute(&sql_pool)
        .await
        .unwrap();
        assert!(init_table(&sql_pool).await.is_err());
    }
}
