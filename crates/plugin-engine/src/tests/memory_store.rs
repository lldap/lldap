use std::{
    collections::HashMap,
    sync::{LazyLock, Mutex},
};

use async_trait::async_trait;

use lldap_domain::types::Serialized;
use lldap_key_value_store::api::{error::KeyValueError, store::KeyValueStore};
use lldap_plugin_kv_store::store::ScopeAndKey;
use serde::{de::DeserializeOwned, Serialize};
use uuid::Uuid;

static STORAGE: LazyLock<Mutex<HashMap<(Uuid, ScopeAndKey), Serialized>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

#[derive(Clone, Debug)]
pub struct InMemoryKeyValueStore {
    pub id: Uuid,
}

impl InMemoryKeyValueStore {
    pub fn new() -> Self {
        Self { id: Uuid::new_v4() }
    }
}

#[async_trait]
impl KeyValueStore<ScopeAndKey> for InMemoryKeyValueStore {
    async fn store<V: Serialize + Send>(
        &self,
        key: ScopeAndKey,
        value: V,
    ) -> Result<(), KeyValueError> {
        println!("{}", "Got write to store!");
        let serialized_value = Serialized::from(&value);
        STORAGE
            .lock()
            .unwrap()
            .insert((self.id.clone(), key), serialized_value);
        Ok(())
    }

    async fn fetch<T: DeserializeOwned>(
        &self,
        key: ScopeAndKey,
    ) -> Result<Option<T>, KeyValueError> {
        match STORAGE.lock().unwrap().get(&(self.id.clone(), key)) {
            Some(serialized_value) => match serialized_value.convert_to() {
                Ok(v) => Ok(Some(v)),
                Err(e) => Err(KeyValueError::DecodingError(e.to_string())),
            },
            None => Ok(None),
        }
    }

    async fn fetch_and_increment(
        &self,
        key: ScopeAndKey,
        default_value: i64,
    ) -> Result<i64, KeyValueError> {
        let key = (self.id.clone(), key);
        let mut guard = STORAGE.lock().unwrap();
        let res = match guard.get(&key) {
            Some(serialized_value) => match serialized_value.convert_to() {
                Ok(v) => v,
                Err(e) => return Err(KeyValueError::DecodingError(e.to_string())),
            },
            None => default_value,
        };
        let next_val: i64 = res + 1;
        let serialized_value = Serialized::from(&next_val);
        let _ = guard.insert(key, serialized_value);
        Ok(res)
    }

    async fn remove(&self, key: ScopeAndKey) -> Result<(), KeyValueError> {
        let _ = STORAGE.lock().unwrap().remove(&(self.id.clone(), key));
        Ok(())
    }
}

mod tests {
    use lldap_plugin_kv_store::store::PluginKVScope;

    use crate::tests::memory_store::InMemoryKeyValueStore;
    use lldap_key_value_store::api::store::KeyValueStore;

    #[tokio::test]
    async fn test_insert_and_fetch_string() {
        // Setup: Load a database and get a connection
        let scope = PluginKVScope("test".to_string());
        let store = InMemoryKeyValueStore::new();
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
        let scope = PluginKVScope("test".to_string());
        let store = InMemoryKeyValueStore::new();
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
        let scope = PluginKVScope("test".to_string());
        let store = InMemoryKeyValueStore::new();
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
        let scope = PluginKVScope("test".to_string());
        let store = InMemoryKeyValueStore::new();
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
        let scope_a = PluginKVScope("scope-a".to_string());
        let scope_b = PluginKVScope("scope-b".to_string());
        // Setup: Prepare two stores with separate scopes
        let store = InMemoryKeyValueStore::new();
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
        let scope = PluginKVScope("test".to_string());
        let store = InMemoryKeyValueStore::new();
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
