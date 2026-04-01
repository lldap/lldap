use std::env;

use anyhow::{Context, Result, bail, ensure};
use clap::Parser;
use lldap_auth::{opaque, registration};
use lldap_frontend_options::{Options, validate_password};
use reqwest::Url;
use serde::Serialize;

/// Set the password for a user in LLDAP.
#[derive(Debug, Parser, Clone)]
pub struct CliOpts {
    /// Base LLDAP url, e.g. "https://lldap/".
    #[clap(short, long)]
    pub base_url: Url,

    /// Admin username.
    #[clap(long, default_value = "admin")]
    pub admin_username: String,

    /// Admin password.
    #[clap(long)]
    pub admin_password: Option<String>,

    /// Connection token (JWT).
    #[clap(short, long)]
    pub token: Option<String>,

    /// Username.
    #[clap(short, long)]
    pub username: String,

    /// New password for the user. Can also be passed as the environment variable LLDAP_USER_PASSWORD.
    #[clap(short, long)]
    pub password: Option<String>,

    /// Bypass password requirements such as minimum length. Unsafe.
    #[clap(long)]
    pub bypass_password_policy: bool,
}

fn append_to_url(base_url: &Url, path: &str) -> Url {
    let mut new_url = base_url.clone();
    new_url.path_segments_mut().unwrap().extend(path.split('/'));
    new_url
}

fn get_token(base_url: &Url, username: &str, password: &str) -> Result<String> {
    let client = reqwest::blocking::Client::new();
    let response = client
        .post(append_to_url(base_url, "auth/simple/login"))
        .header(reqwest::header::CONTENT_TYPE, "application/json")
        .body(
            serde_json::to_string(&lldap_auth::login::ClientSimpleLoginRequest {
                username: username.into(),
                password: password.to_string(),
            })
            .expect("Failed to encode the username/password as json to log in"),
        )
        .send()?
        .error_for_status()?;
    Ok(serde_json::from_str::<lldap_auth::login::ServerLoginResponse>(&response.text()?)?.token)
}

fn call_server(url: Url, token: &str, body: impl Serialize) -> Result<String> {
    let client = reqwest::blocking::Client::new();
    let request = client
        .post(url)
        .header("Content-Type", "application/json")
        .bearer_auth(token)
        .body(serde_json::to_string(&body)?);
    let response = request.send()?.error_for_status()?;
    Ok(response.text()?)
}

pub fn register_start(
    base_url: &Url,
    token: &str,
    request: registration::ClientRegistrationStartRequest,
) -> Result<registration::ServerRegistrationStartResponse> {
    let request = Some(request);
    let data = call_server(
        append_to_url(base_url, "auth/opaque/register/start"),
        token,
        request,
    )?;
    serde_json::from_str(&data).context("Could not parse response")
}

pub fn register_finish(
    base_url: &Url,
    token: &str,
    request: registration::ClientRegistrationFinishRequest,
) -> Result<()> {
    let request = Some(request);
    call_server(
        append_to_url(base_url, "auth/opaque/register/finish"),
        token,
        request,
    )
    .map(|_| ())
}

fn get_settings(base_url: &Url, token: &str) -> Result<Options> {
    let url = append_to_url(base_url, "settings");
    let client = reqwest::blocking::Client::builder()
        .timeout(std::time::Duration::from_secs(5))
        .build()?;
    let resp = client
        .get(url)
        .bearer_auth(token)
        .send()
        .context("Failed to GET /settings")?
        .error_for_status()?;
    let options: Options = resp.json().context("Failed to parse /settings response")?;
    Ok(options)
}

fn main() -> Result<()> {
    let opts = CliOpts::parse();

    let password = match opts.password {
        Some(v) => v,
        None => env::var("LLDAP_USER_PASSWORD").unwrap_or_default(),
    };

    ensure!(
        opts.base_url.scheme() == "http" || opts.base_url.scheme() == "https",
        "Base URL should start with `http://` or `https://`"
    );
    let token = match (opts.token.as_ref(), opts.admin_password.as_ref()) {
        (Some(token), _) => token.clone(),
        (None, Some(password)) => {
            get_token(&opts.base_url, &opts.admin_username, password).context("While logging in")?
        }
        (None, None) => bail!("Either the token or the admin password is required"),
    };

    if !opts.bypass_password_policy {
        let settings = get_settings(&opts.base_url, &token)?;
        validate_password(&password, &settings.password_policy)?;
    }

    let mut rng = rand::rngs::OsRng;
    let registration_start_request =
        opaque::client::registration::start_registration(password.as_bytes(), &mut rng)
            .context("Could not initiate password change")?;
    let start_request = registration::ClientRegistrationStartRequest {
        username: opts.username.clone().into(),
        registration_start_request: registration_start_request.message,
    };
    let res = register_start(&opts.base_url, &token, start_request)?;

    let registration_finish = opaque::client::registration::finish_registration(
        registration_start_request.state,
        res.registration_response,
        &mut rng,
    )
    .context("Error during password change")?;
    let req = registration::ClientRegistrationFinishRequest {
        server_data: res.server_data,
        registration_upload: registration_finish.message,
    };

    register_finish(&opts.base_url, &token, req)?;

    println!("Successfully changed {}'s password", &opts.username);
    Ok(())
}
