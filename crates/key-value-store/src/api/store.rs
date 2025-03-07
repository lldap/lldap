use async_trait::async_trait;
use serde::{de::DeserializeOwned, Serialize};

use crate::api::error::KeyValueError;

#[async_trait]
pub trait KeyValueStore<K: Clone + Sync + Send>: Clone + Sync + Send {
    //
    // Store an arbitrary, serializable value under the given key
    //
    async fn store<V: Serialize + Send>(&self, key: K, value: V) -> Result<(), KeyValueError>;

    //
    // Fetch a previously stored value
    //
    async fn fetch<T: DeserializeOwned>(&self, key: K) -> Result<Option<T>, KeyValueError>;

    //
    // Fetches a stored integer value, or the given default value, if nothing
    // is found under the given key. In the same transaction, the value to be
    // returned is incremented, and stored.
    //
    async fn fetch_and_increment(&self, key: K, default_value: i64) -> Result<i64, KeyValueError>;

    //
    // Remove a stored value, if it exists.
    //
    async fn remove(&self, key: K) -> Result<(), KeyValueError>;
}
