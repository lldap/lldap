use crate::common::{
    auth::{get_token, get_token_for, register_password},
    env,
    fixture::{LLDAPFixture, User, new_id},
    graphql::{
        AddUserToGroup, FinishMfaEnrollment, ListGroups, ListUsers, StartMfaEnrollment,
        add_user_to_group, finish_mfa_enrollment, list_groups, list_users, post,
        start_mfa_enrollment,
    },
};
use ldap3::LdapConn;
use lldap_mfa::{TOTP_SEPARATOR, format_code, seed_from_base32, totp_code};
use reqwest::blocking::{Client, ClientBuilder};
use serial_test::file_serial;
use std::time::{SystemTime, UNIX_EPOCH};
mod common;

fn make_client() -> Client {
    ClientBuilder::new()
        .connect_timeout(std::time::Duration::from_secs(2))
        .timeout(std::time::Duration::from_secs(5))
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .expect("failed to make http client")
}

fn ldap_bind(bind_dn: &str, password: &str) -> (bool, String) {
    let mut ldap =
        LdapConn::new(env::ldap_url().as_str()).expect("failed to create ldap connection");
    let result = ldap
        .simple_bind(bind_dn, password)
        .expect("failed to send bind request");
    let success = result.rc == 0;
    let message = result.text.clone();
    let _ = ldap.unbind();
    (success, message)
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock before unix epoch")
        .as_secs()
}

fn code_at(seed: &[u8], unix_secs: u64) -> String {
    format_code(totp_code(seed, unix_secs).expect("failed to compute TOTP code"))
}

// A 6-digit code that is invalid at every step inside the acceptance window.
fn wrong_code(seed: &[u8], unix_secs: u64) -> String {
    let valid = [unix_secs - 30, unix_secs, unix_secs + 30].map(|t| code_at(seed, t));
    (0..1_000_000)
        .map(|n| format!("{n:06}"))
        .find(|candidate| !valid.contains(candidate))
        .expect("failed to find an invalid code")
}

#[test]
#[file_serial]
fn mfa_disabled_keeps_plain_binds() {
    let mut _fixture = LLDAPFixture::new();
    let base_dn = env::base_dn();
    let bind_dn = format!("uid={},ou=people,{}", env::admin_dn(), base_dn);
    let (success, message) = ldap_bind(&bind_dn, env::admin_password().as_str());
    assert!(success, "plain bind failed: {message}");
    // With MFA disabled the password is never split: the suffix makes it a wrong password.
    let combined = format!("{}{}123456", env::admin_password(), TOTP_SEPARATOR);
    let (success, _) = ldap_bind(&bind_dn, &combined);
    assert!(!success);

    let client = make_client();
    let token = get_token(&client);
    let error = post::<StartMfaEnrollment>(
        &client,
        &token,
        start_mfa_enrollment::Variables { current_code: None },
    )
    .expect_err("enrollment should be refused when MFA is disabled");
    assert!(
        format!("{error:#}").contains("MFA is disabled"),
        "unexpected error: {error:#}"
    );
}

#[test]
#[file_serial]
fn mfa_enrollment_and_ldap_bind() {
    let mut fixture = LLDAPFixture::new_with_env(&[("LLDAP_ENABLE_MFA", "true")]);
    let prefix = "mfa-enrollment_bind-";
    let user_name = new_id(Some(prefix));
    let user_password = "user_password";
    fixture.load_state(&vec![User::new(&user_name, vec![])]);

    let client = make_client();
    let admin_token = get_token(&client);
    register_password(&client, &admin_token, &user_name, user_password);
    let user_token = get_token_for(&client, &user_name, user_password);

    let base_dn = env::base_dn();
    let bind_dn = format!("uid={user_name},ou=people,{base_dn}");
    let (success, message) = ldap_bind(&bind_dn, user_password);
    assert!(success, "unenrolled plain bind failed: {message}");

    let start = post::<StartMfaEnrollment>(
        &client,
        &user_token,
        start_mfa_enrollment::Variables { current_code: None },
    )
    .expect("failed to start MFA enrollment")
    .start_mfa_enrollment;
    let seed = seed_from_base32(&start.secret_base32).expect("invalid enrollment secret");

    post::<FinishMfaEnrollment>(
        &client,
        &user_token,
        finish_mfa_enrollment::Variables {
            state: start.state.clone(),
            code: wrong_code(&seed, unix_now()),
        },
    )
    .expect_err("enrollment should be refused with a wrong code");
    let (success, message) = ldap_bind(&bind_dn, user_password);
    assert!(
        success,
        "plain bind failed after refused enrollment: {message}"
    );

    let enrollment_code = code_at(&seed, unix_now());
    post::<FinishMfaEnrollment>(
        &client,
        &user_token,
        finish_mfa_enrollment::Variables {
            state: start.state.clone(),
            code: enrollment_code,
        },
    )
    .expect("failed to finish MFA enrollment");

    let (success, message) = ldap_bind(&bind_dn, user_password);
    assert!(!success);
    assert!(
        message.contains("TOTP code required"),
        "unexpected diagnostic: {message}"
    );
    // A wrong code gets the generic refusal.
    let combined = format!(
        "{user_password}{TOTP_SEPARATOR}{}",
        wrong_code(&seed, unix_now())
    );
    let (success, message) = ldap_bind(&bind_dn, &combined);
    assert!(!success);
    assert!(message.is_empty(), "unexpected diagnostic: {message}");

    // The next step's code is inside the acceptance window and distinct from
    // the code spent at enrollment.
    let bind_code = code_at(&seed, unix_now() + 30);
    let combined = format!("{user_password}{TOTP_SEPARATOR}{bind_code}");
    let (success, message) = ldap_bind(&bind_dn, &combined);
    assert!(success, "bind with a fresh code failed: {message}");
    let (success, message) = ldap_bind(&bind_dn, &combined);
    assert!(!success);
    assert!(
        message.contains("wait for the next one"),
        "unexpected diagnostic: {message}"
    );

    let groups = post::<ListGroups>(&client, &admin_token, list_groups::Variables {})
        .expect("failed to list groups")
        .groups;
    let exempt_group_id = groups
        .iter()
        .find(|group| group.display_name == "lldap_mfa_disabled")
        .expect("lldap_mfa_disabled group was not bootstrapped")
        .id;
    post::<AddUserToGroup>(
        &client,
        &admin_token,
        add_user_to_group::Variables {
            user: user_name.clone(),
            group: exempt_group_id,
        },
    )
    .expect("failed to add user to the exemption group");
    let (success, message) = ldap_bind(&bind_dn, user_password);
    assert!(success, "exempt member's plain bind failed: {message}");
}

#[test]
#[file_serial]
fn mfa_always_gates_api_and_ldap() {
    let mut _fixture = LLDAPFixture::new_with_env(&[("LLDAP_ENABLE_MFA", "always")]);
    let client = make_client();
    // Web login stays open: enrollment needs a session.
    let token = get_token(&client);
    let error = post::<ListUsers>(&client, &token, list_users::Variables {})
        .expect_err("API should be gated for unenrolled users");
    assert!(
        format!("{error:#}").contains("MFA enrollment required"),
        "unexpected error: {error:#}"
    );
    post::<StartMfaEnrollment>(
        &client,
        &token,
        start_mfa_enrollment::Variables { current_code: None },
    )
    .expect("enrollment start should not be gated");
    // LDAP has no enrollment path, so an unenrolled bind is refused outright,
    // with guidance only after the password verified.
    let base_dn = env::base_dn();
    let bind_dn = format!("uid={},ou=people,{}", env::admin_dn(), base_dn);
    let (success, message) = ldap_bind(&bind_dn, env::admin_password().as_str());
    assert!(!success);
    assert!(
        message.contains("MFA enrollment required"),
        "unexpected diagnostic: {message}"
    );
}
