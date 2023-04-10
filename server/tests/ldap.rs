use std::collections::{HashMap, HashSet};

use crate::common::{
    env,
    fixture::{new_id, LLDAPFixture, User},
};
use ldap3::{LdapConn, Scope, SearchEntry};
use serial_test::file_serial;
mod common;

#[test]
#[file_serial]
fn basic_users_search() {
    let mut fixture = LLDAPFixture::new();
    let prefix = "ldap-basic_users_search-";
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

    let mut ldap =
        LdapConn::new(env::ldap_url().as_str()).expect("failed to create ldap connection");
    let base_dn = env::base_dn();
    let bind_dn = format!("uid={},ou=people,{}", env::admin_dn(), base_dn);
    ldap.simple_bind(bind_dn.as_str(), env::admin_password().as_str())
        .expect("failed to bind to ldap");

    let attrs = vec!["uid", "memberof"];
    let results = ldap
        .search(
            env::base_dn().as_str(),
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
    assert!(found_users.contains_key(&user1_name));
    assert!(found_users
        .get(&user1_name)
        .unwrap()
        .contains(format!("cn={},ou=groups,{}", &group1_name, base_dn).as_str()));
    assert!(found_users.contains_key(&user2_name));
    assert!(found_users
        .get(&user2_name)
        .unwrap()
        .contains(format!("cn={},ou=groups,{}", &group1_name, base_dn).as_str()));
    assert!(found_users
        .get(&user2_name)
        .unwrap()
        .contains(format!("cn={},ou=groups,{}", &group2_name, base_dn).as_str()));
    assert!(found_users.contains_key(&user3_name));
    assert!(found_users.get(&user3_name).unwrap().is_empty());
    ldap.unbind().expect("failed to unbind ldap connection");
}
