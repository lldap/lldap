#![allow(dead_code)]
use crate::common::env;
use lldap_auth::{opaque, registration};
use reqwest::blocking::Client;

pub fn get_token(client: &Client) -> String {
    get_token_for(client, &env::admin_dn(), &env::admin_password())
}

pub fn get_token_for(client: &Client, username: &str, password: &str) -> String {
    let base_url = env::http_url();
    let response = client
        .post(format!("{base_url}/auth/simple/login"))
        .header(reqwest::header::CONTENT_TYPE, "application/json")
        .body(
            serde_json::to_string(&lldap_auth::login::ClientSimpleLoginRequest {
                username: username.to_owned().into(),
                password: password.to_owned(),
            })
            .expect("Failed to encode the username/password as json to log in"),
        )
        .send()
        .expect("Failed to send auth request")
        .error_for_status()
        .expect("Auth attempt failed");
    serde_json::from_str::<lldap_auth::login::ServerLoginResponse>(
        &response.text().expect("Failed to get response text"),
    )
    .expect("Failed to parse json")
    .token
}

pub fn register_password(client: &Client, token: &str, username: &str, password: &str) {
    let base_url = env::http_url();
    let mut rng = rand::rngs::OsRng;
    let registration_start_request =
        opaque::client::registration::start_registration(password.as_bytes(), &mut rng)
            .expect("failed to start password registration");
    let start_request = registration::ClientRegistrationStartRequest {
        username: username.to_owned().into(),
        registration_start_request: registration_start_request.message,
    };
    let start_response = client
        .post(format!("{base_url}/auth/opaque/register/start"))
        .header(reqwest::header::CONTENT_TYPE, "application/json")
        .bearer_auth(token)
        .body(serde_json::to_string(&start_request).expect("failed to encode registration start"))
        .send()
        .expect("failed to send registration start")
        .error_for_status()
        .expect("registration start failed");
    let start_response: registration::ServerRegistrationStartResponse =
        serde_json::from_str(&start_response.text().expect("failed to get response text"))
            .expect("failed to parse registration start response");
    let registration_finish = opaque::client::registration::finish_registration(
        registration_start_request.state,
        start_response.registration_response,
        &mut rng,
    )
    .expect("failed to finish password registration");
    let finish_request = registration::ClientRegistrationFinishRequest {
        server_data: start_response.server_data,
        registration_upload: registration_finish.message,
    };
    client
        .post(format!("{base_url}/auth/opaque/register/finish"))
        .header(reqwest::header::CONTENT_TYPE, "application/json")
        .bearer_auth(token)
        .body(serde_json::to_string(&finish_request).expect("failed to encode registration finish"))
        .send()
        .expect("failed to send registration finish")
        .error_for_status()
        .expect("registration finish failed");
}
