use super::cookies::set_cookie;
use anyhow::{anyhow, Context, Result};
use gloo_net::http::{Method, RequestBuilder};
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

enum RequestType<Body: Serialize> {
    Get,
    Post(Body),
}

const GET_REQUEST: RequestType<()> = RequestType::Get;

fn base_url() -> String {
    yew_router::utils::base_url().unwrap_or_default()
}

async fn call_server<Body: Serialize>(
    url: &str,
    body: RequestType<Body>,
    error_message: &'static str,
) -> Result<String> {
    let request_builder = RequestBuilder::new(url)
        .header("Content-Type", "application/json")
        .credentials(RequestCredentials::SameOrigin);
    let request = if let RequestType::Post(b) = body {
        request_builder
            .method(Method::POST)
            .body(serde_json::to_string(&b)?)?
    } else {
        request_builder.build()?
    };
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
    request: RequestType<Body>,
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
    request: RequestType<Body>,
    error_message: &'static str,
) -> Result<()> {
    call_server(url, request, error_message).await.map(|_| ())
}

fn set_cookies_from_jwt(response: login::ServerLoginResponse) -> Result<(String, bool)> {
    let jwt_claims = get_claims_from_jwt(response.token.as_str()).context("Could not parse JWT")?;
    let is_admin = jwt_claims.groups.contains("lldap_admin");
    set_cookie("user_id", &jwt_claims.user, &jwt_claims.exp)
        .map(|_| set_cookie("is_admin", &is_admin.to_string(), &jwt_claims.exp))
        .map(|_| (jwt_claims.user.clone(), is_admin))
        .context("Error setting cookie")
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
        call_server_json_with_error_message::<graphql_client::Response<_>, _>(
            &(base_url() + "/api/graphql"),
            RequestType::Post(request_body),
            error_message,
        )
        .await
        .and_then(unwrap_graphql_response)
    }

    pub async fn login_start(
        request: login::ClientLoginStartRequest,
    ) -> Result<Box<login::ServerLoginStartResponse>> {
        call_server_json_with_error_message(
            &(base_url() + "/auth/opaque/login/start"),
            RequestType::Post(request),
            "Could not start authentication: ",
        )
        .await
    }

    pub async fn login_finish(request: login::ClientLoginFinishRequest) -> Result<(String, bool)> {
        call_server_json_with_error_message::<login::ServerLoginResponse, _>(
            &(base_url() + "/auth/opaque/login/finish"),
            RequestType::Post(request),
            "Could not finish authentication",
        )
        .await
        .and_then(set_cookies_from_jwt)
    }

    pub async fn register_start(
        request: registration::ClientRegistrationStartRequest,
    ) -> Result<Box<registration::ServerRegistrationStartResponse>> {
        call_server_json_with_error_message(
            &(base_url() + "/auth/opaque/register/start"),
            RequestType::Post(request),
            "Could not start registration: ",
        )
        .await
    }

    pub async fn register_finish(
        request: registration::ClientRegistrationFinishRequest,
    ) -> Result<()> {
        call_server_empty_response_with_error_message(
            &(base_url() + "/auth/opaque/register/finish"),
            RequestType::Post(request),
            "Could not finish registration",
        )
        .await
    }

    pub async fn refresh() -> Result<(String, bool)> {
        call_server_json_with_error_message::<login::ServerLoginResponse, _>(
            &(base_url() + "/auth/refresh"),
            GET_REQUEST,
            "Could not start authentication: ",
        )
        .await
        .and_then(set_cookies_from_jwt)
    }

    // The `_request` parameter is to make it the same shape as the other functions.
    pub async fn logout() -> Result<()> {
        call_server_empty_response_with_error_message(
            &(base_url() + "/auth/logout"),
            GET_REQUEST,
            "Could not logout",
        )
        .await
    }

    pub async fn reset_password_step1(username: String) -> Result<()> {
        call_server_empty_response_with_error_message(
            &format!(
                "{}/auth/reset/step1/{}",
                base_url(),
                url_escape::encode_query(&username)
            ),
            RequestType::Post(""),
            "Could not initiate password reset",
        )
        .await
    }

    pub async fn reset_password_step2(
        token: String,
    ) -> Result<lldap_auth::password_reset::ServerPasswordResetResponse> {
        call_server_json_with_error_message(
            &format!("{}/auth/reset/step2/{}", base_url(), token),
            GET_REQUEST,
            "Could not validate token",
        )
        .await
    }

    pub async fn probe_password_reset() -> Result<bool> {
        Ok(gloo_net::http::Request::get(
            &(base_url() + "/auth/reset/step1/lldap_unlikely_very_long_user_name"),
        )
        .header("Content-Type", "application/json")
        .send()
        .await?
        .status()
            != http::StatusCode::NOT_FOUND)
    }
}
