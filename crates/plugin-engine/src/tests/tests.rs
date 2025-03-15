use lldap_key_value_store::api::store::KeyValueStore;
use lldap_plugin_kv_store::store::PluginKVScope;

use crate::tests::{exec_utils::run_plugin_init, memory_store::InMemoryKeyValueStore};

#[tokio::test]
async fn test_init01_can_initialize_without_error() {
    let res = run_plugin_init(InMemoryKeyValueStore::new(), r#""#).await;
    assert!(res.is_ok());
}

#[tokio::test]
async fn test_init02_init_can_trigger_failure() {
    let res = run_plugin_init(
        InMemoryKeyValueStore::new(),
        r#"
            error("Trigger failure", 1)
        "#,
    )
    .await;
    assert!(res.is_err());
}

#[tokio::test]
async fn test_init03_assert_eq_can_trigger_failure() {
    let res = run_plugin_init(
        InMemoryKeyValueStore::new(),
        r#"
            assert_eq("a", "b")
        "#,
    )
    .await;
    assert!(res.is_err());
}

#[tokio::test]
async fn test_init04_assert_eq_checks_equality() {
    let res = run_plugin_init(
        InMemoryKeyValueStore::new(),
        r#"
            assert_eq("a", "a")
            assert_eq("Hello, world!", "Hello, world!")
            assert_eq(true, true)
            assert_eq(false, false)
            assert_eq(42, 42)
            assert_eq(nil, nil)
            assert_eq({}, {})
            assert_eq({ a = "b" }, { a = "b" })
        "#,
    )
    .await;
    assert!(res.is_ok());
}

#[tokio::test]
async fn test_kvstore01_can_store() {
    let kvstore = InMemoryKeyValueStore::new();
    let res = run_plugin_init(
        kvstore.clone(),
        r#"
            local res, err = context.kvstore:store_str("greeting", "Hello, World!")
            assert_eq(err, nil)
            local res2, err2 = context.kvstore:fetch_str("greeting")
            assert_eq(err2, nil)
            assert_eq(res2, "Hello, World!")
        "#,
    )
    .await;
    // Verify: ensure the plugin ran correctly
    assert!(res.is_ok());
    // Verify: See if we can find the stored in the key value store
    let scope = PluginKVScope("default".to_string());
    let res_read = kvstore
        .fetch::<String>(scope.key("greeting".to_string()))
        .await;
    assert_eq!(res_read.unwrap().unwrap(), "Hello, World!".to_string());
}

#[tokio::test]
async fn test_kvstore02_can_remove() {
    let res = run_plugin_init(
        InMemoryKeyValueStore::new(),
        r#"
            local res, err = context.kvstore:store_str("greeting", "Hello, World!")
            assert_eq(err, nil)
            local res2, err2 = context.kvstore:fetch_str("greeting")
            assert_eq(err2, nil)
            assert_eq(res2, "Hello, World!")
            context.kvstore:remove("greeting")
            local res3, err3 = context.kvstore:fetch_str("greeting")
            assert_eq(err3, nil)
            assert_eq(res3, nil)
        "#,
    )
    .await;
    // Verify: ensure the plugin ran correctly
    assert!(res.is_ok());
}

#[tokio::test]
async fn test_kvstore02_can_fetch_and_inc() {
    let res = run_plugin_init(
        InMemoryKeyValueStore::new(),
        r#"
            local res, err = context.kvstore:store_int("i", 42)
            assert_eq(err, nil)
            local res2, err2 = context.kvstore:fetch_and_increment("i", 100)
            assert_eq(err2, nil)
            assert_eq(res2, 42)
            local res3, err3 = context.kvstore:fetch_int("i")
            assert_eq(err3, nil)
            assert_eq(res3, 43)
        "#,
    )
    .await;
    // Verify: ensure the plugin ran correctly
    assert!(res.is_ok());
}

#[tokio::test]
async fn test_kvstore03_can_fetch_and_inc_w_default() {
    let res = run_plugin_init(
        InMemoryKeyValueStore::new(),
        r#"
            local res, err = context.kvstore:fetch_and_increment("i", 100)
            assert_eq(err, nil)
            assert_eq(res, 100)
            local res2, err2 = context.kvstore:fetch_int("i")
            assert_eq(err2, nil)
            assert_eq(res2, 101)
        "#,
    )
    .await;
    // Verify: ensure the plugin ran correctly
    assert!(res.is_ok());
}

#[tokio::test]
async fn test_kvstore04_can_store_tables() {
    let res = run_plugin_init(
        InMemoryKeyValueStore::new(),
        r#"
            local t = {
                hello = "world",
                answer = 42
            }
            local res, err = context.kvstore:store_table("t", t)
            assert_eq(err, nil)
            local res2, err2 = context.kvstore:fetch_table("t")
            assert_eq(err2, nil)
            assert_eq(res2, t)
            assert_eq(res2.hello, "world")
            assert_eq(res2.answer, 42)
        "#,
    )
    .await;
    // Verify: ensure the plugin ran correctly
    assert!(res.is_ok());
}
