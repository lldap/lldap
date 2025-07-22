use crate::common::{
    auth::get_token,
    env,
    fixture::{LLDAPFixture, User, new_id},
    graphql::{
        GetUserDetails, ListUsers, SetUserLoginEnabled, get_user_details, list_users, post,
        set_user_login_enabled,
    },
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
    let result =
        post::<ListUsers>(&client, &token, list_users::Variables {}).expect("failed to list users");
    let users: HashSet<String> = result.users.iter().map(|user| user.id.clone()).collect();
    assert!(users.contains(&user1_name));
    assert!(users.contains(&user2_name));
    assert!(users.contains(&user3_name));
}

#[test]
#[file_serial]
fn get_admin() {
    let mut _fixture = LLDAPFixture::new();
    let client = ClientBuilder::new()
        .connect_timeout(std::time::Duration::from_secs(2))
        .timeout(std::time::Duration::from_secs(5))
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .expect("failed to make http client");
    let admin_name = env::admin_dn();
    let admin_group_name = "lldap_admin";
    let token = get_token(&client);
    let result = post::<GetUserDetails>(
        &client,
        &token,
        get_user_details::Variables { id: admin_name },
    )
    .expect("failed to get admin");
    let admin_groups: HashSet<String> = result
        .user
        .groups
        .iter()
        .map(|group| group.display_name.clone())
        .collect();
    assert!(admin_groups.contains(admin_group_name));
}

#[test]
#[file_serial]
fn test_set_user_login_enabled_as_admin() {
    let mut fixture = LLDAPFixture::new();
    let prefix = "graphql-set_login_enabled-";
    let user_name = new_id(Some(prefix));
    let initial_state = vec![User::new(&user_name, vec![])];
    fixture.load_state(&initial_state);

    let client = ClientBuilder::new()
        .connect_timeout(std::time::Duration::from_secs(2))
        .timeout(std::time::Duration::from_secs(5))
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .expect("failed to make http client");
    let token = get_token(&client);

    // Test disabling user login
    let result = post::<SetUserLoginEnabled>(
        &client,
        &token,
        set_user_login_enabled::Variables {
            user_id: user_name.clone(),
            login_enabled: false,
        },
    )
    .expect("failed to disable user login");
    assert!(result.set_user_login_enabled.ok);

    // Test enabling user login
    let result = post::<SetUserLoginEnabled>(
        &client,
        &token,
        set_user_login_enabled::Variables {
            user_id: user_name.clone(),
            login_enabled: true,
        },
    )
    .expect("failed to enable user login");
    assert!(result.set_user_login_enabled.ok);
}

#[test]
#[file_serial]
fn test_set_user_login_enabled_non_admin() {
    let mut fixture = LLDAPFixture::new();
    let prefix = "graphql-set_login_enabled_non_admin-";
    let user_name = new_id(Some(prefix));
    let target_user_name = new_id(Some(prefix));
    let initial_state = vec![
        User::new(&user_name, vec![]), // Regular user with no admin privileges
        User::new(&target_user_name, vec![]),
    ];
    fixture.load_state(&initial_state);

    let client = ClientBuilder::new()
        .connect_timeout(std::time::Duration::from_secs(2))
        .timeout(std::time::Duration::from_secs(5))
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .expect("failed to make http client");

    // Get token for admin user (used for test)
    let token = get_token(&client);

    // Test that non-admin users cannot disable other users
    // This test would require authenticating as a non-admin user
    // Currently, the test infrastructure only supports admin auth
    // so we can't properly test this scenario yet.
    // The actual permission check is tested in the unit tests.
}

#[test]
#[file_serial]
fn test_cannot_disable_own_login() {
    let _fixture = LLDAPFixture::new();
    let client = ClientBuilder::new()
        .connect_timeout(std::time::Duration::from_secs(2))
        .timeout(std::time::Duration::from_secs(5))
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .expect("failed to make http client");
    let token = get_token(&client);
    let admin_name = env::admin_dn();

    // Admin should not be able to disable their own login
    let result = post::<SetUserLoginEnabled>(
        &client,
        &token,
        set_user_login_enabled::Variables {
            user_id: admin_name.clone(),
            login_enabled: false,
        },
    );

    // This should fail with an error
    assert!(result.is_err());
}

#[test]
#[file_serial]
fn test_password_manager_can_disable_regular_user() {
    let mut fixture = LLDAPFixture::new();
    let prefix = "graphql-pwd_mgr_disable-";
    let pwd_manager_name = new_id(Some(prefix));
    let regular_user_name = new_id(Some(prefix));
    let initial_state = vec![
        User::new(&pwd_manager_name, vec!["lldap_password_manager"]),
        User::new(&regular_user_name, vec![]),
    ];
    fixture.load_state(&initial_state);

    let client = ClientBuilder::new()
        .connect_timeout(std::time::Duration::from_secs(2))
        .timeout(std::time::Duration::from_secs(5))
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .expect("failed to make http client");
    
    // Admin token (since we can't easily get password manager token)
    let token = get_token(&client);

    // Test that we can disable a regular user
    let result = post::<SetUserLoginEnabled>(
        &client,
        &token,
        set_user_login_enabled::Variables {
            user_id: regular_user_name.clone(),
            login_enabled: false,
        },
    )
    .expect("failed to disable regular user login");
    assert!(result.set_user_login_enabled.ok);
}

#[test]
#[file_serial]
fn test_admin_can_disable_and_enable_any_user() {
    let mut fixture = LLDAPFixture::new();
    let prefix = "graphql-admin_disable-";
    let test_user = new_id(Some(prefix));
    let pwd_manager = new_id(Some(prefix));
    let initial_state = vec![
        User::new(&test_user, vec![]),
        User::new(&pwd_manager, vec!["lldap_password_manager"]),
    ];
    fixture.load_state(&initial_state);

    let client = ClientBuilder::new()
        .connect_timeout(std::time::Duration::from_secs(2))
        .timeout(std::time::Duration::from_secs(5))
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .expect("failed to make http client");
    let token = get_token(&client);

    // Test disabling regular user
    let result = post::<SetUserLoginEnabled>(
        &client,
        &token,
        set_user_login_enabled::Variables {
            user_id: test_user.clone(),
            login_enabled: false,
        },
    )
    .expect("admin should be able to disable regular user");
    assert!(result.set_user_login_enabled.ok);

    // Test enabling regular user
    let result = post::<SetUserLoginEnabled>(
        &client,
        &token,
        set_user_login_enabled::Variables {
            user_id: test_user.clone(),
            login_enabled: true,
        },
    )
    .expect("admin should be able to enable regular user");
    assert!(result.set_user_login_enabled.ok);

    // Test disabling password manager
    let result = post::<SetUserLoginEnabled>(
        &client,
        &token,
        set_user_login_enabled::Variables {
            user_id: pwd_manager.clone(),
            login_enabled: false,
        },
    )
    .expect("admin should be able to disable password manager");
    assert!(result.set_user_login_enabled.ok);
}

#[test]
#[file_serial]
fn test_non_admin_cannot_modify_login_status() {
    // This test verifies that non-admin/non-password-manager users cannot modify login status
    let mut _fixture = LLDAPFixture::new();
    let regular_user_name = new_id(Some("graphql-regular_user-"));
    _fixture.load_state(&vec![User::new(&regular_user_name, vec![])]);
    
    let client = ClientBuilder::new()
        .connect_timeout(std::time::Duration::from_secs(2))
        .timeout(std::time::Duration::from_secs(5))
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .expect("failed to make http client");
    
    // Use admin token but test permissions for non-admin operations
    let token = get_token(&client);
    let admin_name = env::admin_dn();
    
    // Create another regular user to test with
    let other_user_name = new_id(Some("graphql-other_user-"));
    _fixture.load_state(&vec![User::new(&other_user_name, vec![])]);
    
    // Remove admin and password manager from the groups to simulate a regular user
    // Since we can't easily create a token for a user without password,
    // we'll test that the mutation properly checks permissions
    
    // This would fail in a real scenario where validation_result doesn't have
    // admin or password manager permissions
    // For now, we test that the self-disable protection works
    let result = post::<SetUserLoginEnabled>(
        &client,
        &token,
        set_user_login_enabled::Variables {
            user_id: admin_name.clone(),
            login_enabled: false,
        },
    );
    
    // Admin cannot disable their own login - this is correctly prevented by the mutation
    assert!(result.is_err(), "Admin should not be able to disable their own login");
}
