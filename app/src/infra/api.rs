use super::cookies::set_cookie;
use anyhow::{anyhow, Context, Result};
use graphql_client::GraphQLQuery;
use lldap_auth::{login, registration, JWTClaims};

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
            .context("Could not reach server")
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
        Self(Json(request))
    }
}

impl From<yew::format::Nothing> for RequestBody<yew::format::Nothing> {
    fn from(request: yew::format::Nothing) -> Self {
        Self(request)
    }
}

fn call_server<Req, CallbackResult, F, RB>(
    url: &str,
    request: RB,
    callback: Callback<Result<CallbackResult>>,
    error_message: &'static str,
    parse_response: F,
) -> Result<FetchTask>
where
    F: Fn(String) -> Result<CallbackResult> + 'static,
    CallbackResult: 'static,
    RB: Into<RequestBody<Req>>,
    Req: Into<yew::format::Text>,
{
    let request = {
        // If the request type is empty (if the size is 0), it's a get.
        if std::mem::size_of::<RB>() == 0 {
            Request::get(url)
        } else {
            Request::post(url)
        }
    }
    .header("Content-Type", "application/json")
    .body(request.into().0)?;
    let handler = create_handler(callback, move |status: http::StatusCode, data: String| {
        if status.is_success() {
            parse_response(data)
        } else {
            Err(anyhow!("{}[{}]: {}", error_message, status, data))
        }
    });
    FetchService::fetch_with_options(request, get_default_options(), handler)
}

fn call_server_json_with_error_message<CallbackResult, RB, Req>(
    url: &str,
    request: RB,
    callback: Callback<Result<CallbackResult>>,
    error_message: &'static str,
) -> Result<FetchTask>
where
    CallbackResult: serde::de::DeserializeOwned + 'static,
    RB: Into<RequestBody<Req>>,
    Req: Into<yew::format::Text>,
{
    call_server(url, request, callback, error_message, |data: String| {
        serde_json::from_str(&data).context("Could not parse response")
    })
}

fn call_server_empty_response_with_error_message<RB, Req>(
    url: &str,
    request: RB,
    callback: Callback<Result<()>>,
    error_message: &'static str,
) -> Result<FetchTask>
where
    RB: Into<RequestBody<Req>>,
    Req: Into<yew::format::Text>,
{
    call_server(
        url,
        request,
        callback,
        error_message,
        |_data: String| Ok(()),
    )
}

impl HostService {
    pub fn graphql_query<QueryType>(
        variables: QueryType::Variables,
        callback: Callback<Result<QueryType::ResponseData>>,
        error_message: &'static str,
    ) -> Result<FetchTask>
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
        let parse_graphql_response = move |data: String| {
            serde_json::from_str(&data)
                .context("Could not parse response")
                .and_then(unwrap_graphql_response)
        };
        let request_body = QueryType::build_query(variables);
        call_server(
            "/api/graphql",
            &request_body,
            callback,
            error_message,
            parse_graphql_response,
        )
    }

    pub fn login_start(
        request: login::ClientLoginStartRequest,
        callback: Callback<Result<Box<login::ServerLoginStartResponse>>>,
    ) -> Result<FetchTask> {
        call_server_json_with_error_message(
            "/auth/opaque/login/start",
            &request,
            callback,
            "Could not start authentication: ",
        )
    }

    pub fn login_finish(
        request: login::ClientLoginFinishRequest,
        callback: Callback<Result<(String, bool)>>,
    ) -> Result<FetchTask> {
        let set_cookies = |jwt_claims: JWTClaims| {
            let is_admin = jwt_claims.groups.contains("lldap_admin");
            set_cookie("user_id", &jwt_claims.user, &jwt_claims.exp)
                .map(|_| set_cookie("is_admin", &is_admin.to_string(), &jwt_claims.exp))
                .map(|_| (jwt_claims.user.clone(), is_admin))
                .context("Error clearing cookie")
        };
        let parse_token = move |data: String| {
            get_claims_from_jwt(&data)
                .context("Could not parse response")
                .and_then(set_cookies)
        };
        call_server(
            "/auth/opaque/login/finish",
            &request,
            callback,
            "Could not finish authentication",
            parse_token,
        )
    }

    pub fn register_start(
        request: registration::ClientRegistrationStartRequest,
        callback: Callback<Result<Box<registration::ServerRegistrationStartResponse>>>,
    ) -> Result<FetchTask> {
        call_server_json_with_error_message(
            "/auth/opaque/register/start",
            &request,
            callback,
            "Could not start registration: ",
        )
    }

    pub fn register_finish(
        request: registration::ClientRegistrationFinishRequest,
        callback: Callback<Result<()>>,
    ) -> Result<FetchTask> {
        call_server_empty_response_with_error_message(
            "/auth/opaque/register/finish",
            &request,
            callback,
            "Could not finish registration",
        )
    }

    pub fn logout(callback: Callback<Result<()>>) -> Result<FetchTask> {
        call_server_empty_response_with_error_message(
            "/auth/logout",
            yew::format::Nothing,
            callback,
            "Could not logout",
        )
    }
}
