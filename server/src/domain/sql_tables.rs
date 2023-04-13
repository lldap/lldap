use super::sql_migrations::{get_schema_version, migrate_from_version, upgrade_to_v1};
use sea_orm::Value;

pub type DbConnection = sea_orm::DatabaseConnection;

#[derive(Copy, PartialEq, Eq, Debug, Clone, PartialOrd, Ord)]
pub struct SchemaVersion(pub i16);

impl sea_orm::TryGetable for SchemaVersion {
    fn try_get_by<I: sea_orm::ColIdx>(
        res: &sea_orm::QueryResult,
        index: I,
    ) -> Result<Self, sea_orm::TryGetError> {
        Ok(SchemaVersion(i16::try_get_by(res, index)?))
    }
}

impl From<SchemaVersion> for Value {
    fn from(version: SchemaVersion) -> Self {
        version.0.into()
    }
}

const LAST_SCHEMA_VERSION: SchemaVersion = SchemaVersion(4);

pub async fn init_table(pool: &DbConnection) -> anyhow::Result<()> {
    let version = {
        if let Some(version) = get_schema_version(pool).await {
            version
        } else {
            upgrade_to_v1(pool).await?;
            SchemaVersion(1)
        }
    };
    migrate_from_version(pool, version, LAST_SCHEMA_VERSION).await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use crate::domain::{
        sql_migrations,
        types::{GroupId, Uuid},
    };

    use super::*;
    use chrono::prelude::*;
    use sea_orm::{ConnectionTrait, Database, DbBackend, FromQueryResult};

    async fn get_in_memory_db() -> DbConnection {
        let mut sql_opt = sea_orm::ConnectOptions::new("sqlite::memory:".to_owned());
        sql_opt.max_connections(1).sqlx_logging(false);
        Database::connect(sql_opt).await.unwrap()
    }

    fn raw_statement(sql: &str) -> sea_orm::Statement {
        sea_orm::Statement::from_string(DbBackend::Sqlite, sql.to_owned())
    }

    #[tokio::test]
    async fn test_init_table() {
        let sql_pool = get_in_memory_db().await;
        init_table(&sql_pool).await.unwrap();
        sql_pool.execute(raw_statement(
        r#"INSERT INTO users
      (user_id, email, display_name, first_name, last_name, creation_date, password_hash, uuid)
      VALUES ("bôb", "böb@bob.bob", "Bob Bobbersön", "Bob", "Bobberson", "1970-01-01 00:00:00", "bob00", "abc")"#)).await.unwrap();
        #[derive(FromQueryResult, PartialEq, Eq, Debug)]
        struct ShortUserDetails {
            display_name: String,
            creation_date: chrono::NaiveDateTime,
        }
        let result = ShortUserDetails::find_by_statement(raw_statement(
            r#"SELECT display_name, creation_date FROM users WHERE user_id = "bôb""#,
        ))
        .one(&sql_pool)
        .await
        .unwrap()
        .unwrap();
        assert_eq!(
            result,
            ShortUserDetails {
                display_name: "Bob Bobbersön".to_owned(),
                creation_date: Utc.timestamp_opt(0, 0).unwrap().naive_utc(),
            }
        );
    }

    #[tokio::test]
    async fn test_already_init_table() {
        crate::infra::logging::init_for_tests();
        let sql_pool = get_in_memory_db().await;
        init_table(&sql_pool).await.unwrap();
        init_table(&sql_pool).await.unwrap();
    }

    #[tokio::test]
    async fn test_migrate_tables() {
        // Test that we add the column creation_date to groups and uuid to users and groups.
        let sql_pool = get_in_memory_db().await;
        sql_pool
            .execute(raw_statement(
                r#"CREATE TABLE users ( user_id TEXT, display_name TEXT, first_name TEXT NOT NULL, last_name TEXT, avatar BLOB, creation_date TEXT, email TEXT);"#,
            ))
            .await
            .unwrap();
        sql_pool
            .execute(raw_statement(
                r#"INSERT INTO users (user_id, display_name, first_name, creation_date, email)
                       VALUES ("bôb", "", "", "1970-01-01 00:00:00", "bob@bob.com")"#,
            ))
            .await
            .unwrap();
        sql_pool
            .execute(raw_statement(
                r#"INSERT INTO users (user_id, display_name, first_name, creation_date, email)
                       VALUES ("john", "John Doe", "John", "1971-01-01 00:00:00", "bob2@bob.com")"#,
            ))
            .await
            .unwrap();
        sql_pool
            .execute(raw_statement(
                r#"CREATE TABLE groups ( group_id INTEGER PRIMARY KEY, display_name TEXT );"#,
            ))
            .await
            .unwrap();
        sql_pool
            .execute(raw_statement(
                r#"INSERT INTO groups (display_name)
                      VALUES ("lldap_admin"), ("lldap_readonly")"#,
            ))
            .await
            .unwrap();
        init_table(&sql_pool).await.unwrap();
        sql_pool
            .execute(raw_statement(
                r#"INSERT INTO groups (display_name, creation_date, uuid)
                      VALUES ("test", "1970-01-01 00:00:00", "abc")"#,
            ))
            .await
            .unwrap();
        #[derive(FromQueryResult, PartialEq, Eq, Debug)]
        struct SimpleUser {
            display_name: Option<String>,
            first_name: Option<String>,
            uuid: Uuid,
        }
        assert_eq!(
            SimpleUser::find_by_statement(raw_statement(
                r#"SELECT display_name, first_name, uuid FROM users ORDER BY display_name"#
            ))
            .all(&sql_pool)
            .await
            .unwrap(),
            vec![
                SimpleUser {
                    display_name: None,
                    first_name: None,
                    uuid: crate::uuid!("a02eaf13-48a7-30f6-a3d4-040ff7c52b04")
                },
                SimpleUser {
                    display_name: Some("John Doe".to_owned()),
                    first_name: Some("John".to_owned()),
                    uuid: crate::uuid!("986765a5-3f03-389e-b47b-536b2d6e1bec")
                }
            ]
        );
        #[derive(FromQueryResult, PartialEq, Eq, Debug)]
        struct ShortGroupDetails {
            group_id: GroupId,
            display_name: String,
        }
        assert_eq!(
            ShortGroupDetails::find_by_statement(raw_statement(
                r#"SELECT group_id, display_name, creation_date FROM groups"#
            ))
            .all(&sql_pool)
            .await
            .unwrap(),
            vec![
                ShortGroupDetails {
                    group_id: GroupId(1),
                    display_name: "lldap_admin".to_string()
                },
                ShortGroupDetails {
                    group_id: GroupId(2),
                    display_name: "lldap_password_manager".to_string()
                },
                ShortGroupDetails {
                    group_id: GroupId(3),
                    display_name: "test".to_string()
                }
            ]
        );
        assert_eq!(
            sql_migrations::JustSchemaVersion::find_by_statement(raw_statement(
                r#"SELECT version FROM metadata"#
            ))
            .one(&sql_pool)
            .await
            .unwrap()
            .unwrap(),
            sql_migrations::JustSchemaVersion {
                version: LAST_SCHEMA_VERSION
            }
        );
    }

    #[tokio::test]
    async fn test_migration_to_v4() {
        let sql_pool = get_in_memory_db().await;
        upgrade_to_v1(&sql_pool).await.unwrap();
        migrate_from_version(&sql_pool, SchemaVersion(1), SchemaVersion(3))
            .await
            .unwrap();
        sql_pool
            .execute(raw_statement(
                r#"INSERT INTO users (user_id, email, display_name, first_name, creation_date, uuid)
                       VALUES ("bob", "bob@bob.com", "", "", "1970-01-01 00:00:00", "a02eaf13-48a7-30f6-a3d4-040ff7c52b04")"#,
            ))
            .await
            .unwrap();
        sql_pool
            .execute(raw_statement(
                r#"INSERT INTO users (user_id, email, display_name, first_name, creation_date, uuid)
                       VALUES ("bob2", "bob@bob.com", "", "", "1970-01-01 00:00:00", "986765a5-3f03-389e-b47b-536b2d6e1bec")"#,
            ))
            .await
            .unwrap();
        migrate_from_version(&sql_pool, SchemaVersion(3), SchemaVersion(4))
            .await
            .expect_err("migration should fail");
        assert_eq!(
            sql_migrations::JustSchemaVersion::find_by_statement(raw_statement(
                r#"SELECT version FROM metadata"#
            ))
            .one(&sql_pool)
            .await
            .unwrap()
            .unwrap(),
            sql_migrations::JustSchemaVersion {
                version: SchemaVersion(3)
            }
        );
        sql_pool
            .execute(raw_statement(
                r#"UPDATE users SET email = "new@bob.com" WHERE user_id = "bob2""#,
            ))
            .await
            .unwrap();
        migrate_from_version(&sql_pool, SchemaVersion(3), SchemaVersion(4))
            .await
            .unwrap();
        assert_eq!(
            sql_migrations::JustSchemaVersion::find_by_statement(raw_statement(
                r#"SELECT version FROM metadata"#
            ))
            .one(&sql_pool)
            .await
            .unwrap()
            .unwrap(),
            sql_migrations::JustSchemaVersion {
                version: SchemaVersion(4)
            }
        );
    }

    #[tokio::test]
    async fn test_too_high_version() {
        let sql_pool = get_in_memory_db().await;
        sql_pool
            .execute(raw_statement(
                r#"CREATE TABLE metadata ( version INTEGER);"#,
            ))
            .await
            .unwrap();
        sql_pool
            .execute(raw_statement(
                r#"INSERT INTO metadata (version)
                       VALUES (127)"#,
            ))
            .await
            .unwrap();
        assert!(init_table(&sql_pool).await.is_err());
    }
}
