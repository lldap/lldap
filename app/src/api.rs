use crate::cookies::set_cookie;
use anyhow::{anyhow, Result};
use lldap_model::*;

use yew::callback::Callback;
use yew::format::Json;
use yew::services::fetch::{Credentials, FetchOptions, FetchService, FetchTask, Request, Response};

#[derive(Default)]
pub struct HostService {}

fn get_default_options() -> FetchOptions {
    FetchOptions {
        credentials: Some(Credentials::SameOrigin),
        ..FetchOptions::default()
    }
}

fn get_claims_from_jwt(jwt: &str) -> Result<JWTClaims> {
    use jwt::*;
    let token = Token::<header::Header, JWTClaims, token::Unverified>::parse_unverified(jwt)?;
    Ok(token.claims().clone())
}

fn create_handler<Resp, CallbackResult, F>(
    callback: Callback<Result<CallbackResult>>,
    handler: F,
) -> Callback<Response<Result<Resp>>>
where
    F: Fn(http::StatusCode, Resp) -> Result<CallbackResult> + 'static,
    Resp: std::fmt::Display,
    CallbackResult: 'static,
{
    Callback::once(move |response: Response<Result<Resp>>| {
        let (meta, maybe_data) = response.into_parts();
        let message = maybe_data
            .map_err(|e| anyhow!("Could not reach server: {}", e))
            .and_then(|data| handler(meta.status, data));
        callback.emit(message)
    })
}

impl HostService {
    pub fn list_users(
        request: ListUsersRequest,
        callback: Callback<Result<Vec<User>>>,
    ) -> Result<FetchTask> {
        let url = "/api/users";
        let request = Request::post(url)
            .header("Content-Type", "application/json")
            .body(Json(&request))?;
        let handler = create_handler(callback, |status, data: String| {
            if status.is_success() {
                serde_json::from_str(&data).map_err(|e| anyhow!("Could not parse response: {}", e))
            } else {
                Err(anyhow!("[{}]: {}", status, data))
            }
        });
        FetchService::fetch_with_options(request, get_default_options(), handler)
    }

    pub fn authenticate(
        request: BindRequest,
        callback: Callback<Result<String>>,
    ) -> Result<FetchTask> {
        let url = "/auth";
        let request = Request::post(url)
            .header("Content-Type", "application/json")
            .body(Json(&request))?;
        let handler = create_handler(callback, |status, data: String| {
            if status.is_success() {
                get_claims_from_jwt(&data)
                    .map_err(|e| anyhow!("Could not parse response: {}", e))
                    .and_then(|jwt_claims| {
                        set_cookie("user_id", &jwt_claims.user, &jwt_claims.exp)
                            .map(|_| jwt_claims.user.clone())
                            .map_err(|e| anyhow!("Error clearing cookie: {}", e))
                    })
            } else if status == 401 {
                Err(anyhow!("Invalid username or password"))
            } else {
                Err(anyhow!("Could not authenticate: [{}]: {}", status, data))
            }
        });
        FetchService::fetch_with_options(request, get_default_options(), handler)
    }

    pub fn logout(callback: Callback<Result<()>>) -> Result<FetchTask> {
        let url = "/auth/logout";
        let request = Request::post(url).body(yew::format::Nothing)?;
        let handler = create_handler(callback, |status, data: String| {
            if status.is_success() {
                Ok(())
            } else {
                Err(anyhow!("Could not logout: [{}]: {}", status, data))
            }
        });
        FetchService::fetch_with_options(request, get_default_options(), handler)
    }
}
