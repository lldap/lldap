use std::env;

use anyhow::{Context, Result, bail, ensure};
use clap::Parser;
use lldap_auth::{opaque, registration};
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

    /// Use trusted-header authentication instead of JWT/admin password.
    #[clap(long)]
    pub use_trusted_header: bool,

    /// Trusted header name carrying the authenticated username.
    #[clap(long, default_value = "Remote-User")]
    pub trusted_header_name: String,

    /// Trusted header value carrying the authenticated username.
    #[clap(long, default_value = "admin")]
    pub trusted_header_value: String,

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

#[derive(Debug, Clone)]
pub struct TrustedHeaderAuth {
    name: String,
    value: String,
}

#[derive(Debug, Clone)]
pub enum Auth {
    BearerToken(String),
    TrustedHeader(TrustedHeaderAuth),
}

fn call_server(url: Url, auth: &Auth, body: impl Serialize) -> Result<String> {
    let client = reqwest::blocking::Client::new();
    let request = client
        .post(url)
        .header("Content-Type", "application/json")
        .body(serde_json::to_string(&body)?);
    let request = match auth {
        Auth::BearerToken(token) => request.bearer_auth(token),
        Auth::TrustedHeader(header) => request.header(&header.name, &header.value),
    };
    let response = request.send()?.error_for_status()?;
    Ok(response.text()?)
}

pub fn register_start(
    base_url: &Url,
    auth: &Auth,
    request: registration::ClientRegistrationStartRequest,
) -> Result<registration::ServerRegistrationStartResponse> {
    let request = Some(request);
    let data = call_server(
        append_to_url(base_url, "auth/opaque/register/start"),
        auth,
        request,
    )?;
    serde_json::from_str(&data).context("Could not parse response")
}

pub fn register_finish(
    base_url: &Url,
    auth: &Auth,
    request: registration::ClientRegistrationFinishRequest,
) -> Result<()> {
    let request = Some(request);
    call_server(
        append_to_url(base_url, "auth/opaque/register/finish"),
        auth,
        request,
    )
    .map(|_| ())
}

fn main() -> Result<()> {
    let opts = CliOpts::parse();

    let password = opts
        .password
        .unwrap_or_else(|| env::var("LLDAP_USER_PASSWORD").unwrap_or_default());

    ensure!(
        opts.bypass_password_policy || password.len() >= 8,
        "New password is too short, expected at least 8 characters"
    );
    ensure!(
        opts.base_url.scheme() == "http" || opts.base_url.scheme() == "https",
        "Base URL should start with `http://` or `https://`"
    );
    let auth = if opts.use_trusted_header {
        Auth::TrustedHeader(TrustedHeaderAuth {
            name: opts.trusted_header_name.clone(),
            value: opts.trusted_header_value.clone(),
        })
    } else {
        let token = match (opts.token.as_ref(), opts.admin_password.as_ref()) {
            (Some(token), _) => token.clone(),
            (None, Some(password)) => get_token(&opts.base_url, &opts.admin_username, password)
                .context("While logging in")?,
            (None, None) => bail!(
                "Either the token or the admin password is required unless --use-trusted-header is set"
            ),
        };
        Auth::BearerToken(token)
    };

    let mut rng = rand::rngs::OsRng;
    let registration_start_request =
        opaque::client::registration::start_registration(password.as_bytes(), &mut rng)
            .context("Could not initiate password change")?;
    let start_request = registration::ClientRegistrationStartRequest {
        username: opts.username.clone().into(),
        registration_start_request: registration_start_request.message,
    };
    let res = register_start(&opts.base_url, &auth, start_request)?;

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

    register_finish(&opts.base_url, &auth, req)?;

    println!("Successfully changed {}'s password", &opts.username);
    Ok(())
}
