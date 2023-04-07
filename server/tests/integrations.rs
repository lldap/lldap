use std::collections::{HashMap, HashSet};

use crate::common::fixture::{LLDAPFixture, User};
use ldap3::{LdapConn, Scope, SearchEntry};
use serial_test::file_serial;
mod common;

#[test]
#[file_serial]
fn gitea() {
    let mut fixture = LLDAPFixture::new();
    let gitea_user_group = "gitea_user";
    let initial_state = vec![
        User::new("bob", vec![gitea_user_group, "gitea-admin"]),
        User::new("alice", vec![gitea_user_group]),
        User::new("james", vec![]),
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

    let user_base = format!("ou=people,{}", common::fixture::get_base_dn());
    let attrs = vec!["uid", "givenName", "sn", "mail", "jpegPhoto"];
    let results = ldap
        .search(
            user_base.as_str(),
            Scope::Subtree,
            format!("(memberof=cn={},ou=groups,{})", gitea_user_group, base_dn).as_str(),
            attrs,
        )
        .expect("failed to find gitea users")
        .success()
        .expect("failed to get gitea user results")
        .0;
    let mut found_users: HashSet<String> = HashSet::new();
    for result in results {
        let attrs = SearchEntry::construct(result).attrs;
        let user = attrs.get("uid").unwrap().get(0).unwrap();
        found_users.insert(user.clone());
    }
    assert!(found_users.contains("bob"));
    assert!(found_users.contains("alice"));
    assert!(!found_users.contains("james"));
    ldap.unbind().expect("failed to unbind ldap connection");
}
