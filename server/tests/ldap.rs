use std::collections::{HashMap, HashSet};

use crate::common::fixture::{LLDAPFixture, User};
use ldap3::{LdapConn, Scope, SearchEntry};
use serial_test::file_serial;
mod common;

#[test]
#[file_serial]
fn basic_users_search() {
    let mut fixture = LLDAPFixture::new();
    let initial_state = vec![
        User::new("user1", vec!["group-one"]),
        User::new("user2", vec!["group-one", "group-two"]),
        User::new("user3", vec![]),
    ];
    fixture.load_state(&initial_state);

    let mut ldap = LdapConn::new(common::fixture::get_ldap_url().as_str())
        .expect("failed to create ldap connection");
    let base_dn = common::fixture::get_base_dn();
    let bind_dn = format!(
        "uid={},ou=people,{}",
        common::fixture::get_admin_dn(),
        base_dn
    );
    ldap.simple_bind(
        bind_dn.as_str(),
        common::fixture::get_admin_password().as_str(),
    )
    .expect("failed to bind to ldap");

    let attrs = vec!["uid", "memberof"];
    let results = ldap
        .search(
            common::fixture::get_base_dn().as_str(),
            Scope::Subtree,
            "(objectclass=person)",
            attrs,
        )
        .expect("failed to find users")
        .success()
        .expect("failed to get user results")
        .0;
    let mut found_users: HashMap<String, HashSet<String>> = HashMap::new();
    for result in results {
        let attrs = SearchEntry::construct(result).attrs;
        let user = attrs.get("uid").unwrap().get(0).unwrap();
        let user_groups = attrs.get("memberof").unwrap().clone();
        let mut groups: HashSet<String> = HashSet::new();
        groups.extend(user_groups.clone());
        found_users.insert(user.clone(), groups);
    }
    assert!(found_users.contains_key("user1"));
    assert!(found_users
        .get("user1")
        .unwrap()
        .contains(format!("cn={},ou=groups,{}", "group-one", base_dn).as_str()));
    assert!(found_users.contains_key("user2"));
    assert!(found_users
        .get("user2")
        .unwrap()
        .contains(format!("cn={},ou=groups,{}", "group-one", base_dn).as_str()));
    assert!(found_users
        .get("user2")
        .unwrap()
        .contains(format!("cn={},ou=groups,{}", "group-two", base_dn).as_str()));
    assert!(found_users.contains_key("user3"));
    assert!(found_users.get("user3").unwrap().is_empty());
    ldap.unbind().expect("failed to unbind ldap connection");
}
