use crate::common::fixture::{LLDAPFixture, User};
use graphql_client::GraphQLQuery;
use ldap3::{LdapConn, Scope, SearchEntry};
use reqwest::blocking::{Client, ClientBuilder};
use serial_test::file_serial;
use std::collections::{HashMap, HashSet};
mod common;

#[test]
#[file_serial]
fn list_users() {
    let mut fixture = LLDAPFixture::new();
    let initial_state = vec![
        User::new("user1", vec!["group-one"]),
        User::new("user2", vec!["group-one", "group-two"]),
        User::new("user3", vec![]),
    ];
    fixture.load_state(&initial_state);

    let client = ClientBuilder::new()
        .connect_timeout(std::time::Duration::from_secs(2))
        .timeout(std::time::Duration::from_secs(5))
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .expect("failed to make http client");
    let token = common::fixture::get_token(&client).expect("failed to get token");
    let result = common::fixture::post::<ListUsers>(&client, &token, list_users::Variables {})
        .expect("failed to list users");
    let users: HashSet<String> = result.users.iter().map(|user| user.id.clone()).collect();
    assert!(users.contains("user1"));
    assert!(users.contains("user2"));
    assert!(users.contains("user3"));
}

#[derive(GraphQLQuery)]
#[graphql(
    schema_path = "../schema.graphql",
    query_path = "tests/queries/list_users.graphql",
    response_derives = "Debug",
    custom_scalars_module = "crate::infra::graphql"
)]
struct ListUsers;
