use crate::common::env;
use reqwest::blocking::Client;

pub fn get_token(client: &Client) -> String {
    let username = env::admin_dn();
    let password = env::admin_password();
    let base_url = env::http_url();
    let response = client
        .post(format!("{base_url}/auth/simple/login"))
        .header(reqwest::header::CONTENT_TYPE, "application/json")
        .body(
            serde_json::to_string(&lldap_auth::login::ClientSimpleLoginRequest {
                username: username,
                password: password,
            })
            .expect("Failed to encode the username/password as json to log in"),
        )
        .send()
        .expect("Failed to send auth request")
        .error_for_status()
        .expect("Auth attempt failed");
    serde_json::from_str::<lldap_auth::login::ServerLoginResponse>(
        &response.text().expect("Failed to get response as text"),
    )
    .expect("Failed to parse json")
    .token
}
