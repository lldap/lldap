mod common;

use common::{
    env,
    fixture::{LLDAPFixture, User, new_id},
};
use lldap_auth::login;
use reqwest::{
    StatusCode,
    blocking::{Client, Response},
    header::{AUTHORIZATION, SET_COOKIE},
};
use serde_json::{Value, json};
use serial_test::file_serial;

const TRUSTED_HEADER: &str = "Remote-User";

fn graphql_user(
    client: &Client,
    bearer: &str,
    trusted_user: Option<&str>,
    user_id: &str,
) -> Response {
    let mut request = client
        .post(format!("{}/api/graphql", env::http_url()))
        .header(AUTHORIZATION, format!("Bearer {bearer}"))
        .json(&json!({
            "query": "query($id: String!) { user(userId: $id) { id } }",
            "variables": { "id": user_id },
        }));
    if let Some(trusted_user) = trusted_user {
        request = request.header(TRUSTED_HEADER, trusted_user);
    }
    request.send().expect("GraphQL request failed")
}

#[test]
#[file_serial]
fn trusted_header_authentication_end_to_end() {
    let mut fixture = LLDAPFixture::new_with_server_args(&[
        "--trusted-header-enabled=true",
        "--trusted-header-logout-url=https://proxy.example/logout",
    ]);
    let header_user = new_id(Some("trusted-header-"));
    fixture.load_state(&vec![User::new(&header_user, vec![])]);

    let response = graphql_user(
        fixture.client(),
        fixture.token(),
        Some(&header_user),
        "admin",
    );
    assert_eq!(response.status(), StatusCode::OK);
    assert!(
        response
            .text()
            .expect("failed to read GraphQL response")
            .contains("Unauthorized access to user data"),
        "the trusted-header identity should take precedence over the bearer token"
    );

    let response = graphql_user(
        fixture.client(),
        "invalid-token",
        Some(&header_user),
        &header_user,
    );
    assert_eq!(response.status(), StatusCode::OK);
    let body: Value = response.json().expect("invalid GraphQL JSON response");
    assert_eq!(body["data"]["user"]["id"], header_user);

    let response = graphql_user(fixture.client(), fixture.token(), None, "admin");
    assert_eq!(response.status(), StatusCode::OK);
    let body: Value = response.json().expect("invalid GraphQL JSON response");
    assert_eq!(body["data"]["user"]["id"], "admin");

    let response = fixture
        .client()
        .get(format!("{}/auth/refresh", env::http_url()))
        .header(TRUSTED_HEADER, "admin")
        .send()
        .expect("refresh request failed");
    assert_eq!(response.status(), StatusCode::OK);
    let set_cookies: Vec<_> = response
        .headers()
        .get_all(SET_COOKIE)
        .iter()
        .map(|value| {
            value
                .to_str()
                .expect("invalid Set-Cookie header")
                .to_owned()
        })
        .collect();
    assert!(
        set_cookies
            .iter()
            .any(|cookie| cookie.starts_with("token=") && cookie.contains("Max-Age=0"))
    );
    assert!(
        set_cookies
            .iter()
            .any(|cookie| cookie.starts_with("refresh_token=") && cookie.contains("Max-Age=0"))
    );
    let body: login::ServerAuthResponse = response.json().expect("invalid refresh response");
    let login::ServerAuthResponse::TrustedHeader(header_response) = body else {
        panic!("trusted-header refresh returned the wrong response variant");
    };
    assert_eq!(header_response.user_id, "admin");
    assert!(header_response.is_admin);
    assert_eq!(
        header_response.logout_url.as_deref(),
        Some("https://proxy.example/logout")
    );
}

#[test]
#[file_serial]
fn untrusted_proxy_does_not_fall_back_to_bearer_authentication() {
    let fixture = LLDAPFixture::new_with_server_args(&[
        "--trusted-header-enabled=true",
        "--trusted-header-trusted-proxies=192.0.2.0/24",
    ]);

    let response = fixture
        .client()
        .post(format!("{}/api/graphql", env::http_url()))
        .header(AUTHORIZATION, format!("Bearer {}", fixture.token()))
        .header(TRUSTED_HEADER, "admin")
        .header("X-Forwarded-For", "127.0.0.1")
        .json(&json!({
            "query": "query($id: String!) { user(userId: $id) { id } }",
            "variables": { "id": "admin" },
        }))
        .send()
        .expect("GraphQL request failed");

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    let body = response.text().expect("failed to read error response");
    assert!(body.contains("untrusted client IP"));
    assert!(body.contains("trusted_proxies"));
    assert!(body.contains("prevent direct client access"));
}
