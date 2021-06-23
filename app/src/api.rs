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

struct RequestBody<T>(T);

impl<'a, R> From<&'a R> for RequestBody<Json<&'a R>>
where
    R: serde::ser::Serialize,
{
    fn from(request: &'a R) -> Self {
        Self(Json(&request))
    }
}

impl From<yew::format::Nothing> for RequestBody<yew::format::Nothing> {
    fn from(request: yew::format::Nothing) -> Self {
        Self(request)
    }
}

fn call_server<Req, CallbackResult, Resp, F, RB>(
    url: &str,
    request: RB,
    callback: Callback<Result<CallbackResult>>,
    handler: F,
) -> Result<FetchTask>
where
    F: Fn(http::StatusCode, Resp) -> Result<CallbackResult> + 'static,
    CallbackResult: 'static,
    RB: Into<RequestBody<Req>>,
    Req: Into<yew::format::Text>,
    Result<Resp>: From<Result<String>> + 'static,
{
    let request = Request::post(url)
        .header("Content-Type", "application/json")
        .body(request.into().0)?;
    let handler = create_handler(callback, handler);
    FetchService::fetch_with_options(request, get_default_options(), handler)
}

impl HostService {
    pub fn list_users(
        request: ListUsersRequest,
        callback: Callback<Result<Vec<User>>>,
    ) -> Result<FetchTask> {
        call_server("/api/users", &request, callback, |status, data: String| {
            if status.is_success() {
                serde_json::from_str(&data).map_err(|e| anyhow!("Could not parse response: {}", e))
            } else {
                Err(anyhow!("[{}]: {}", status, data))
            }
        })
    }

    pub fn login_start(
        request: login::ClientLoginStartRequest,
        callback: Callback<Result<login::ServerLoginStartResponse>>,
    ) -> Result<FetchTask> {
        call_server(
            "/auth/opaque/login/start",
            &request,
            callback,
            |status, data: String| {
                if status.is_success() {
                    serde_json::from_str(&data)
                        .map_err(|e| anyhow!("Could not parse response: {}", e))
                } else {
                    Err(anyhow!(
                        "Could not start authentication: [{}]: {}",
                        status,
                        data
                    ))
                }
            },
        )
    }

    pub fn login_finish(
        request: login::ClientLoginFinishRequest,
        callback: Callback<Result<String>>,
    ) -> Result<FetchTask> {
        call_server(
            "/auth/opaque/login/finish",
            &request,
            callback,
            |status, data: String| {
                if status.is_success() {
                    get_claims_from_jwt(&data)
                        .map_err(|e| anyhow!("Could not parse response: {}", e))
                        .and_then(|jwt_claims| {
                            set_cookie("user_id", &jwt_claims.user, &jwt_claims.exp)
                                .map(|_| jwt_claims.user.clone())
                                .map_err(|e| anyhow!("Error clearing cookie: {}", e))
                        })
                } else {
                    Err(anyhow!(
                        "Could not finish authentication: [{}]: {}",
                        status,
                        data
                    ))
                }
            },
        )
    }

    pub fn logout(callback: Callback<Result<()>>) -> Result<FetchTask> {
        call_server(
            "/auth/logout",
            yew::format::Nothing,
            callback,
            |status, data: String| {
                if status.is_success() {
                    Ok(())
                } else {
                    Err(anyhow!("Could not logout: [{}]: {}", status, data))
                }
            },
        )
    }

    pub fn create_user(
        request: CreateUserRequest,
        callback: Callback<Result<()>>,
    ) -> Result<FetchTask> {
        call_server(
            "/api/users/create",
            &request,
            callback,
            |status, data: String| {
                if status.is_success() {
                    Ok(())
                } else {
                    Err(anyhow!("Could not create a user: [{}]: {}", status, data))
                }
            },
        )
    }
}
