use async_trait::async_trait;
use lldap_domain::types::Serialized;
use sea_orm::{ActiveModelTrait, ActiveValue, DatabaseConnection, EntityTrait, TransactionTrait};
use serde::{de::DeserializeOwned, Serialize};

use lldap_domain_model::model;
use lldap_key_value_store::api::{error::KeyValueError, store::KeyValueStore};

#[derive(Clone, Debug)]
pub struct PluginKeyValueStore {
    pub(crate) sql_pool: DatabaseConnection,
}

impl PluginKeyValueStore {
    pub fn new(conn: DatabaseConnection) -> Self {
        Self { sql_pool: conn }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct PluginKVScope(pub String);
impl PluginKVScope {
    pub fn key(&self, k: String) -> ScopeAndKey {
        ScopeAndKey {
            scope: self.clone(),
            key: k,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct ScopeAndKey {
    pub scope: PluginKVScope,
    pub key: String,
}

#[async_trait]
impl KeyValueStore<ScopeAndKey> for PluginKeyValueStore {
    async fn store<V: Serialize + Send>(
        &self,
        key: ScopeAndKey,
        value: V,
    ) -> Result<(), KeyValueError> {
        let key_scope = key.scope.0.clone();
        let serialized_value = Serialized::from(&value);
        self.sql_pool
            .transaction::<_, (), KeyValueError>(|transaction| {
                Box::pin(async move {
                    // determine if we already have a value stored for this key
                    let existing =
                        model::PluginKeyValues::find_by_id((key_scope.clone(), key.key.clone()))
                            .one(transaction)
                            .await?;
                    // prepare model
                    let model = model::plugin_key_values::ActiveModel {
                        scope: ActiveValue::Set(key_scope.clone()),
                        key: ActiveValue::Set(key.key.clone()),
                        value: ActiveValue::Set(serialized_value),
                        ..Default::default()
                    };
                    if existing.is_some() {
                        model.update(transaction).await?;
                    } else {
                        model.insert(transaction).await?;
                    };
                    Ok(())
                })
            })
            .await?;
        Ok(())
    }

    async fn fetch<T: DeserializeOwned>(
        &self,
        key: ScopeAndKey,
    ) -> Result<Option<T>, KeyValueError> {
        let existing = model::PluginKeyValues::find_by_id((key.scope.0.clone(), key.key.clone()))
            .one(&self.sql_pool)
            .await?;
        match existing {
            Some(model) => match model.value.convert_to() {
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
        let key_scope = key.scope.0.clone();
        self.sql_pool
            .transaction::<_, i64, KeyValueError>(|transaction| {
                Box::pin(async move {
                    // determine if we already have a value stored for this key
                    let existing =
                        model::PluginKeyValues::find_by_id((key_scope.clone(), key.key.clone()))
                            .one(transaction)
                            .await?;
                    // prepare result value
                    let result_val: i64 = match existing.clone() {
                        Some(model) => match model.value.convert_to::<i64>() {
                            Ok(v) => v,
                            Err(e) => return Err(KeyValueError::DecodingError(e.to_string())),
                        },
                        None => default_value,
                    };
                    // prepare model
                    let next_val: i64 = result_val + 1;
                    let model = model::plugin_key_values::ActiveModel {
                        scope: ActiveValue::Set(key_scope.clone()),
                        key: ActiveValue::Set(key.key.clone()),
                        value: ActiveValue::Set(Serialized::from(&next_val)),
                        ..Default::default()
                    };
                    if existing.is_some() {
                        model.update(transaction).await?;
                    } else {
                        model.insert(transaction).await?;
                    };
                    Ok(result_val)
                })
            })
            .await
            .map_err(|e| e.into())
    }

    async fn remove(&self, key: ScopeAndKey) -> Result<(), KeyValueError> {
        model::PluginKeyValues::delete_by_id((key.scope.0.clone(), key.key.clone()))
            .exec(&self.sql_pool)
            .await?;
        Ok(())
    }
}
