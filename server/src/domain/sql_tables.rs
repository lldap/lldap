use super::sql_migrations::{get_schema_version, migrate_from_version, upgrade_to_v1};
use sea_orm::Value;

pub type DbConnection = sea_orm::DatabaseConnection;

#[derive(Copy, PartialEq, Eq, Debug, Clone)]
pub struct SchemaVersion(pub i16);

impl sea_orm::TryGetable for SchemaVersion {
    fn try_get(
        res: &sea_orm::QueryResult,
        pre: &str,
        col: &str,
    ) -> Result<Self, sea_orm::TryGetError> {
        Ok(SchemaVersion(i16::try_get(res, pre, col)?))
    }
}

impl From<SchemaVersion> for Value {
    fn from(version: SchemaVersion) -> Self {
        version.0.into()
    }
}

pub async fn init_table(pool: &DbConnection) -> anyhow::Result<()> {
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
                r#"CREATE TABLE users ( user_id TEXT , creation_date TEXT);"#,
            ))
            .await
            .unwrap();
        sql_pool
            .execute(raw_statement(
                r#"INSERT INTO users (user_id, creation_date)
                       VALUES ("bôb", "1970-01-01 00:00:00")"#,
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
        struct JustUuid {
            uuid: Uuid,
        }
        assert_eq!(
            JustUuid::find_by_statement(raw_statement(r#"SELECT uuid FROM users"#))
                .all(&sql_pool)
                .await
                .unwrap(),
            vec![JustUuid {
                uuid: crate::uuid!("a02eaf13-48a7-30f6-a3d4-040ff7c52b04")
            }]
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
                version: SchemaVersion(1)
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
