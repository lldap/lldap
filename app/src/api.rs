use anyhow::{anyhow, Result};
use lldap_model::*;
use wasm_bindgen::JsCast;

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
            match maybe_data {
                Ok(data) => {
                    if meta.status.is_success() {
                        callback.emit(
                            serde_json::from_str(&data)
                                .map_err(|e| anyhow!("Could not parse response: {}", e)),
                        )
                    } else {
                        callback.emit(Err(anyhow!("[{}]: {}", meta.status, data)))
                    }
                }
                Err(e) => callback.emit(Err(anyhow!("Could not fetch: {}", e))),
            }
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
            match maybe_data {
                Ok(data) => {
                    if meta.status.is_success() {
                        match get_claims_from_jwt(&data) {
                            Ok(jwt_claims) => {
                                let document = web_sys::window()
                                    .unwrap()
                                    .document()
                                    .unwrap()
                                    .dyn_into::<web_sys::HtmlDocument>()
                                    .unwrap();
                                document
                                    .set_cookie(&format!(
                                        "user_id={}; expires={}",
                                        &jwt_claims.user, &jwt_claims.exp
                                    ))
                                    .unwrap();
                                callback.emit(Ok(jwt_claims.user.clone()))
                            }
                            Err(e) => {
                                callback.emit(Err(anyhow!("Could not parse response: {}", e)))
                            }
                        }
                    } else if meta.status == 401 {
                        callback.emit(Err(anyhow!("Invalid username or password")))
                    } else {
                        callback.emit(Err(anyhow!(
                            "Could not authenticate: [{}]: {}",
                            meta.status,
                            data
                        )))
                    }
                }
                Err(e) => {
                    callback.emit(Err(anyhow!("Could not reach authentication server: {}", e)))
                }
            }
        };
        let request = Request::post(url)
            .header("Content-Type", "application/json")
            .body(Json(&request))?;
        FetchService::fetch_with_options(request, get_default_options(), handler.into())
    }
}
