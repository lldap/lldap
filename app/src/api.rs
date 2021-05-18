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

impl HostService {
    pub fn list_users(
        request: ListUsersRequest,
        callback: Callback<Result<Vec<User>>>,
    ) -> Result<FetchTask> {
        let url = "/api/users";
        let handler = move |response: Response<Result<String>>| {
            let (meta, maybe_data) = response.into_parts();
            let message = maybe_data
                .map_err(|e| anyhow!("Could not fetch: {}", e))
                .and_then(|data| {
                    if meta.status.is_success() {
                        serde_json::from_str(&data)
                            .map_err(|e| anyhow!("Could not parse response: {}", e))
                    } else {
                        Err(anyhow!("[{}]: {}", meta.status, data))
                    }
                });
            callback.emit(message)
        };
        let request = Request::post(url)
            .header("Content-Type", "application/json")
            .body(Json(&request))?;
        FetchService::fetch_with_options(request, get_default_options(), handler.into())
    }

    pub fn authenticate(
        request: BindRequest,
        callback: Callback<Result<String>>,
    ) -> Result<FetchTask> {
        let url = "/api/authorize";
        let handler = move |response: Response<Result<String>>| {
            let (meta, maybe_data) = response.into_parts();
            let message = maybe_data
                .map_err(|e| anyhow!("Could not reach authentication server: {}", e))
                .and_then(|data| {
                    if meta.status.is_success() {
                        get_claims_from_jwt(&data)
                            .map_err(|e| anyhow!("Could not parse response: {}", e))
                            .and_then(|jwt_claims| {
                                set_cookie("user_id", &jwt_claims.user, &jwt_claims.exp)
                                    .map(|_| jwt_claims.user.clone())
                                    .map_err(|e| anyhow!("Error clearing cookie: {}", e))
                            })
                    } else if meta.status == 401 {
                        Err(anyhow!("Invalid username or password"))
                    } else {
                        Err(anyhow!(
                            "Could not authenticate: [{}]: {}",
                            meta.status,
                            data
                        ))
                    }
                });
            callback.emit(message)
        };
        let request = Request::post(url)
            .header("Content-Type", "application/json")
            .body(Json(&request))?;
        FetchService::fetch_with_options(request, get_default_options(), handler.into())
    }
}
