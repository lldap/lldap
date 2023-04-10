use crate::common::{
    auth::get_token,
    fixture::{new_id, LLDAPFixture, User},
    graphql::{post, ListUsers},
};
use reqwest::blocking::ClientBuilder;
use serial_test::file_serial;
use std::collections::HashSet;
mod common;

#[test]
#[file_serial]
fn list_users() {
    let mut fixture = LLDAPFixture::new();
    let prefix = "graphql-list_users-";
    let user1_name = new_id(Some(prefix));
    let user2_name = new_id(Some(prefix));
    let user3_name = new_id(Some(prefix));
    let group1_name = new_id(Some(prefix));
    let group2_name = new_id(Some(prefix));
    let initial_state = vec![
        User::new(&user1_name, vec![&group1_name]),
        User::new(&user2_name, vec![&group1_name, &group2_name]),
        User::new(&user3_name, vec![]),
    ];
    fixture.load_state(&initial_state);

    let client = ClientBuilder::new()
        .connect_timeout(std::time::Duration::from_secs(2))
        .timeout(std::time::Duration::from_secs(5))
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .expect("failed to make http client");
    let token = get_token(&client);
    let result = post::<ListUsers>(&client, &token, common::graphql::list_users::Variables {})
        .expect("failed to list users");
    let users: HashSet<String> = result.users.iter().map(|user| user.id.clone()).collect();
    assert!(users.contains(&user1_name));
    assert!(users.contains(&user2_name));
    assert!(users.contains(&user3_name));
}
