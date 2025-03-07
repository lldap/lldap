#[cfg(test)]
mod tests {

    use crate::{
        migration::create_plugin_kv_table,
        store::{PluginKVScope, PluginKeyValueStore},
    };
    use lldap_key_value_store::api::store::KeyValueStore;
    use sea_orm::{Database, DatabaseConnection, DbErr, TransactionTrait};

    pub struct DbConn {
        pub fileid: &'static str,
        pub connection: DatabaseConnection,
    }

    impl Drop for DbConn {
        fn drop(&mut self) {
            let filename: String = "kvtests".to_owned() + self.fileid + ".db";
            let _ = std::fs::remove_file(filename);
        }
    }

    async fn prepare_dbconn(id: &'static str) -> Result<DatabaseConnection, DbErr> {
        let database_url: String = "sqlite://kvtests".to_owned() + id + ".db?mode=rwc";
        let sql_pool = {
            let mut sql_opt = sea_orm::ConnectOptions::new(database_url);
            sql_opt
                .max_connections(1)
                .sqlx_logging(true)
                .sqlx_logging_level(log::LevelFilter::Debug);
            Database::connect(sql_opt).await?
        };
        Ok(sql_pool)
    }

    async fn load_fixture(id: &'static str) -> DbConn {
        // Prepare the database connection
        let sql_conn = prepare_dbconn(id).await.unwrap();
        // Create the expected schema
        sql_conn
            .transaction(|transaction| {
                Box::pin(async move { create_plugin_kv_table(transaction).await })
            })
            .await
            .unwrap();
        DbConn {
            fileid: id,
            connection: sql_conn,
        }
    }

    #[tokio::test]
    async fn test_insert_and_fetch_string() {
        // Setup: Load a database and get a connection
        let db_conn = load_fixture("01").await;
        let scope = PluginKVScope("test".to_string());
        let store = PluginKeyValueStore::new(db_conn.connection.clone());
        let test_key: String = "test-key".to_string();
        // Verify: ensure nothing is stored under the key beforehand
        let pre_res = store.fetch::<String>(scope.key(test_key.clone())).await;
        assert!(pre_res.is_ok());
        assert!(pre_res.unwrap().is_none());
        // Exercise: Insert a value
        let store_res = store
            .store(scope.key(test_key.clone()), "value-test".to_string())
            .await;
        assert!(store_res.is_ok());
        // Exercise: Fetch the stored value
        let fetch_res = store.fetch(scope.key(test_key)).await;
        // Verify: ensure the expected value was stored
        assert_eq!(fetch_res.unwrap(), Some("value-test".to_string()));
    }

    #[tokio::test]
    async fn test_insert_and_fetch_i64() {
        // Setup: Load a database and get a connection
        let db_conn = load_fixture("02").await;
        let scope = PluginKVScope("test".to_string());
        let store = PluginKeyValueStore::new(db_conn.connection.clone());
        let test_key: String = "test-key".to_string();
        // Verify: ensure nothing is stored under the key beforehand
        let pre_res = store.fetch::<i64>(scope.key(test_key.clone())).await;
        assert!(pre_res.is_ok());
        assert!(pre_res.unwrap().is_none());
        // Exercise: Insert a value
        let store_res = store.store(scope.key(test_key.clone()), 42i64).await;
        assert!(store_res.is_ok());
        // Exercise: Fetch the stored value
        let fetch_res = store.fetch(scope.key(test_key)).await;
        // Verify: ensure the expected value was stored
        assert_eq!(fetch_res.unwrap(), Some(42i64));
    }

    #[tokio::test]
    async fn test_fetch_and_increment() {
        // Setup: Load a database and get a connection
        let db_conn = load_fixture("03").await;
        let scope = PluginKVScope("test".to_string());
        let store = PluginKeyValueStore::new(db_conn.connection.clone());
        let test_key: String = "test-key".to_string();
        // Verify: ensure nothing is stored under the key beforehand
        let pre_res = store.fetch::<i64>(scope.key(test_key.clone())).await;
        assert!(pre_res.is_ok());
        assert!(pre_res.unwrap().is_none());
        // Setup: Insert a value
        let store_res = store.store(scope.key(test_key.clone()), 42i64).await;
        assert!(store_res.is_ok());
        // Exercise: Fetch the stored value
        let fetch_res = store
            .fetch_and_increment(scope.key(test_key.clone()), 99)
            .await;
        // Verify: ensure the original value was returned
        assert_eq!(fetch_res.unwrap(), 42i64);
        // Exercise: Fetch the current stored value
        let inc_res = store.fetch::<i64>(scope.key(test_key)).await;
        assert!(inc_res.is_ok());
        // Verify: ensure the value was incremented on previous call
        assert_eq!(inc_res.unwrap(), Some(43i64));
    }

    #[tokio::test]
    async fn test_fetch_and_increment_default_value() {
        // Setup: Load a database and get a connection
        let db_conn = load_fixture("04").await;
        let scope = PluginKVScope("test".to_string());
        let store = PluginKeyValueStore::new(db_conn.connection.clone());
        let test_key: String = "test-key".to_string();
        // Verify: ensure nothing is stored under the key beforehand
        let pre_res = store.fetch::<i64>(scope.key(test_key.clone())).await;
        assert!(pre_res.is_ok());
        assert!(pre_res.unwrap().is_none());
        // Exercise: get default value from fetch_and_increment
        let fetch_res = store.fetch_and_increment(scope.key(test_key), 99).await;
        // Verify: ensure the default value was returned
        assert_eq!(fetch_res.unwrap(), 99i64);
    }

    #[tokio::test]
    async fn test_scope_separation() {
        // Setup: Load a database and get a connection
        let db_conn = load_fixture("05").await;
        let scope_a = PluginKVScope("scope-a".to_string());
        let scope_b = PluginKVScope("scope-b".to_string());
        // Setup: Prepare two stores with separate scopes
        let store = PluginKeyValueStore::new(db_conn.connection.clone());
        let test_key: String = "test-key".to_string();
        // Verify: ensure nothing is stored under the key beforehand
        let pre_res_a = store.fetch::<String>(scope_a.key(test_key.clone())).await;
        assert!(pre_res_a.is_ok());
        assert!(pre_res_a.unwrap().is_none());
        let pre_res_b = store.fetch::<String>(scope_b.key(test_key.clone())).await;
        assert!(pre_res_b.is_ok());
        assert!(pre_res_b.unwrap().is_none());
        // Exercise: Insert a value into store_a only
        let store_res = store
            .store(scope_a.key(test_key.clone()), "value-test".to_string())
            .await;
        assert!(store_res.is_ok());
        // Exercise: Fetch value stored with key
        let fetch_res_a = store.fetch::<String>(scope_a.key(test_key.clone())).await;
        let fetch_res_b = store.fetch::<String>(scope_b.key(test_key)).await;
        // Verify: ensure the expected value was stored in storeA
        assert_eq!(fetch_res_a.unwrap(), Some("value-test".to_string()));
        // Verify: still no stored value in storeB
        assert_eq!(fetch_res_b.unwrap(), None);
    }

    #[tokio::test]
    async fn test_remove_entry() {
        // Setup: Load a database and get a connection
        let db_conn = load_fixture("06").await;
        let scope = PluginKVScope("test".to_string());
        let store = PluginKeyValueStore::new(db_conn.connection.clone());
        let test_key: String = "test-key".to_string();
        // Verify: ensure nothing is stored under the key beforehand
        let pre_res = store.fetch::<String>(scope.key(test_key.clone())).await;
        assert!(pre_res.is_ok());
        assert!(pre_res.unwrap().is_none());
        // Exercise: Insert a value
        let store_res = store
            .store(scope.key(test_key.clone()), "value-test".to_string())
            .await;
        assert!(store_res.is_ok());
        // Exercise: Fetch the stored value
        let fetch_res = store.fetch::<String>(scope.key(test_key.clone())).await;
        // Verify: ensure something is stored
        assert!(fetch_res.unwrap().is_some());
        // Exercise: delete the entry
        let del_res = store.remove(scope.key(test_key.clone())).await;
        assert!(del_res.is_ok());
        // Verify: nothing stored anymore
        let fetch_res_post = store.fetch::<String>(scope.key(test_key)).await;
        assert!(fetch_res_post.is_ok());
        assert!(fetch_res_post.unwrap().is_none());
    }
}
