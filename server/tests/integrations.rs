use std::collections::HashSet;

use crate::common::{
    env,
    fixture::{LLDAPFixture, User, new_id},
};
use ldap3::{LdapConn, Scope, SearchEntry};
use serial_test::file_serial;
mod common;

#[test]
#[file_serial]
fn gitea() {
    let mut fixture = LLDAPFixture::new();
    let gitea_user_group = new_id(Some("gitea_user-"));
    let gitea_admin_group = new_id(Some("gitea_admin-"));
    let gitea_user1 = new_id(Some("gitea1-"));
    let gitea_user2 = new_id(Some("gitea2-"));
    let gitea_user3 = new_id(Some("gitea3-"));
    let initial_state = vec![
        User::new(&gitea_user1, vec![&gitea_user_group, &gitea_admin_group]),
        User::new(&gitea_user2, vec![&gitea_user_group]),
        User::new(&gitea_user3, vec![]),
    ];
    fixture.load_state(&initial_state);

    let mut ldap =
        LdapConn::new(env::ldap_url().as_str()).expect("failed to create ldap connection");
    let base_dn = env::base_dn();
    let bind_dn = format!("uid={},ou=people,{}", env::admin_dn(), base_dn);
    ldap.simple_bind(bind_dn.as_str(), env::admin_password().as_str())
        .expect("failed to bind to ldap");

    let user_base = format!("ou=people,{}", base_dn);
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
        let user = attrs.get("uid").unwrap().first().unwrap();
        found_users.insert(user.clone());
    }
    assert!(found_users.contains(&gitea_user1));
    assert!(found_users.contains(&gitea_user2));
    assert!(!found_users.contains(&gitea_user3));
    ldap.unbind().expect("failed to unbind ldap connection");
}
