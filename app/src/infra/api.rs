use super::cookies::set_cookie;
use anyhow::{anyhow, Context, Result};
use gloo_net::http::{Method, Request};
use graphql_client::GraphQLQuery;
use lldap_auth::{login, registration, JWTClaims};

use serde::{de::DeserializeOwned, Serialize};
use web_sys::RequestCredentials;

#[derive(Default)]
pub struct HostService {}

fn get_claims_from_jwt(jwt: &str) -> Result<JWTClaims> {
    use jwt::*;
    let token = Token::<header::Header, JWTClaims, token::Unverified>::parse_unverified(jwt)?;
    Ok(token.claims().clone())
}

const NO_BODY: Option<()> = None;

async fn call_server(
    url: &str,
    body: Option<impl Serialize>,
    error_message: &'static str,
) -> Result<String> {
    let mut request = Request::new(url)
        .header("Content-Type", "application/json")
        .credentials(RequestCredentials::SameOrigin);
    if let Some(b) = body {
        request = request
            .body(serde_json::to_string(&b)?)
            .method(Method::POST);
    }
    let response = request.send().await?;
    if response.ok() {
        Ok(response.text().await?)
    } else {
        Err(anyhow!(
            "{}[{} {}]: {}",
            error_message,
            response.status(),
            response.status_text(),
            response.text().await?
        ))
    }
}

async fn call_server_json_with_error_message<CallbackResult, Body: Serialize>(
    url: &str,
    request: Option<Body>,
    error_message: &'static str,
) -> Result<CallbackResult>
where
    CallbackResult: DeserializeOwned + 'static,
{
    let data = call_server(url, request, error_message).await?;
    serde_json::from_str(&data).context("Could not parse response")
}

async fn call_server_empty_response_with_error_message<Body: Serialize>(
    url: &str,
    request: Option<Body>,
    error_message: &'static str,
) -> Result<()> {
    call_server(url, request, error_message).await.map(|_| ())
}

impl HostService {
    pub async fn graphql_query<QueryType>(
        variables: QueryType::Variables,
        error_message: &'static str,
    ) -> Result<QueryType::ResponseData>
    where
        QueryType: GraphQLQuery + 'static,
    {
        let unwrap_graphql_response = |graphql_client::Response { data, errors }| {
            data.ok_or_else(|| {
                anyhow!(
                    "Errors: [{}]",
                    errors
                        .unwrap_or_default()
                        .iter()
                        .map(ToString::to_string)
                        .collect::<Vec<_>>()
                        .join(", ")
                )
            })
        };
        let request_body = QueryType::build_query(variables);
        let response = call_server("/api/graphql", Some(request_body), error_message).await?;
        serde_json::from_str(&response)
            .context("Could not parse response")
            .and_then(unwrap_graphql_response)
    }

    pub async fn login_start(
        request: login::ClientLoginStartRequest,
    ) -> Result<Box<login::ServerLoginStartResponse>> {
        call_server_json_with_error_message(
            "/auth/opaque/login/start",
            Some(request),
            "Could not start authentication: ",
        )
        .await
    }

    pub async fn login_finish(request: login::ClientLoginFinishRequest) -> Result<(String, bool)> {
        let set_cookies = |jwt_claims: JWTClaims| {
            let is_admin = jwt_claims.groups.contains("lldap_admin");
            set_cookie("user_id", &jwt_claims.user, &jwt_claims.exp)
                .map(|_| set_cookie("is_admin", &is_admin.to_string(), &jwt_claims.exp))
                .map(|_| (jwt_claims.user.clone(), is_admin))
                .context("Error clearing cookie")
        };
        let response = call_server(
            "/auth/opaque/login/finish",
            Some(request),
            "Could not finish authentication",
        )
        .await?;
        serde_json::from_str::<login::ServerLoginResponse>(&response)
            .context("Could not parse response")
            .and_then(|r| {
                get_claims_from_jwt(r.token.as_str())
                    .context("Could not parse response")
                    .and_then(set_cookies)
            })
    }

    pub async fn register_start(
        request: registration::ClientRegistrationStartRequest,
    ) -> Result<Box<registration::ServerRegistrationStartResponse>> {
        call_server_json_with_error_message(
            "/auth/opaque/register/start",
            Some(request),
            "Could not start registration: ",
        )
        .await
    }

    pub async fn register_finish(
        request: registration::ClientRegistrationFinishRequest,
    ) -> Result<()> {
        call_server_empty_response_with_error_message(
            "/auth/opaque/register/finish",
            Some(request),
            "Could not finish registration",
        )
        .await
    }

    pub async fn refresh() -> Result<(String, bool)> {
        let set_cookies = |jwt_claims: JWTClaims| {
            let is_admin = jwt_claims.groups.contains("lldap_admin");
            set_cookie("user_id", &jwt_claims.user, &jwt_claims.exp)
                .map(|_| set_cookie("is_admin", &is_admin.to_string(), &jwt_claims.exp))
                .map(|_| (jwt_claims.user.clone(), is_admin))
                .context("Error clearing cookie")
        };
        let response =
            call_server("/auth/refresh", NO_BODY, "Could not start authentication: ").await?;
        serde_json::from_str::<login::ServerLoginResponse>(&response)
            .context("Could not parse response")
            .and_then(|r| {
                get_claims_from_jwt(r.token.as_str())
                    .context("Could not parse response")
                    .and_then(set_cookies)
            })
    }

    // The `_request` parameter is to make it the same shape as the other functions.
    pub async fn logout() -> Result<()> {
        call_server_empty_response_with_error_message("/auth/logout", NO_BODY, "Could not logout")
            .await
    }

    pub async fn reset_password_step1(username: String) -> Result<()> {
        call_server_empty_response_with_error_message(
            &format!("/auth/reset/step1/{}", url_escape::encode_query(&username)),
            NO_BODY,
            "Could not initiate password reset",
        )
        .await
    }

    pub async fn reset_password_step2(
        token: String,
    ) -> Result<lldap_auth::password_reset::ServerPasswordResetResponse> {
        call_server_json_with_error_message(
            &format!("/auth/reset/step2/{}", token),
            NO_BODY,
            "Could not validate token",
        )
        .await
    }

    pub async fn probe_password_reset() -> Result<bool> {
        Ok(
            gloo_net::http::Request::get("/auth/reset/step1/lldap_unlikely_very_long_user_name")
                .header("Content-Type", "application/json")
                .send()
                .await?
                .status()
                != http::StatusCode::NOT_FOUND,
        )
    }
}
