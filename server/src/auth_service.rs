use crate::{
    tcp_backend_handler::*,
    tcp_server::{AppState, TcpError, TcpResult, error_to_http_response},
};
use actix_web::{
    FromRequest, HttpRequest, HttpResponse,
    cookie::{Cookie, SameSite},
    dev::{Service, ServiceRequest, ServiceResponse, Transform},
    error::{ErrorBadRequest, ErrorUnauthorized},
    http::header::HeaderValue,
    web,
};
use actix_web_httpauth::extractors::bearer::BearerAuth;
use anyhow::Result;
use chrono::prelude::*;
use futures::future::{Ready, ok};
use futures_util::FutureExt;
use hmac::Hmac;
use jwt::{SignWithKey, VerifyWithKey};
use lldap_access_control::{ReadonlyBackendHandler, UserReadableBackendHandler};
use lldap_auth::{
    JWTClaims, access_control::ValidationResults, login, password_reset, registration,
};
use lldap_domain::types::{GroupDetails, GroupName, UserId};
use lldap_domain_handlers::handler::{
    BackendHandler, BindRequest, LoginHandler, UserRequestFilter,
};
use lldap_domain_model::{error::DomainError, model::UserColumn};
use lldap_opaque_handler::OpaqueHandler;
use sha2::Sha512;
use std::{
    collections::HashSet,
    hash::Hash,
    net::IpAddr,
    pin::Pin,
    task::{Context, Poll},
};
use time::ext::NumericalDuration;
use tracing::{debug, info, instrument, warn};
use uuid::Uuid;

type Token<S> = jwt::Token<jwt::Header, JWTClaims, S>;
type SignedToken = Token<jwt::token::Signed>;

fn default_hash<T: Hash + ?Sized>(token: &T) -> u64 {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::Hasher;
    let mut s = DefaultHasher::new();
    token.hash(&mut s);
    s.finish()
}

async fn create_jwt<Handler: TcpBackendHandler>(
    handler: &Handler,
    key: &Hmac<Sha512>,
    user: &UserId,
    groups: HashSet<GroupDetails>,
) -> SignedToken {
    let claims = JWTClaims {
        exp: Utc::now() + chrono::Duration::days(1),
        iat: Utc::now(),
        jti: Uuid::new_v4(),
        user: user.to_string(),
        groups: groups
            .into_iter()
            .map(|g| g.display_name.into_string())
            .collect(),
    };
    let expiry = claims.exp.naive_utc();
    let header = jwt::Header {
        algorithm: jwt::AlgorithmType::Hs512,
        ..Default::default()
    };
    let token = jwt::Token::new(header, claims).sign_with_key(key).unwrap();
    handler
        .register_jwt(user, default_hash(token.as_str()), expiry)
        .await
        .unwrap();
    token
}

fn parse_refresh_token(token: &str) -> TcpResult<(u64, UserId)> {
    match token.split_once('+') {
        None => Err(DomainError::AuthenticationError("Invalid refresh token".to_string()).into()),
        Some((token, u)) => Ok((default_hash(token), UserId::new(u))),
    }
}

fn get_refresh_token(request: HttpRequest) -> TcpResult<(u64, UserId)> {
    match (
        request.cookie("refresh_token"),
        request.headers().get("refresh-token"),
    ) {
        (Some(c), _) => parse_refresh_token(c.value()),
        (_, Some(t)) => parse_refresh_token(t.to_str().unwrap()),
        (None, None) => {
            Err(DomainError::AuthenticationError("Missing refresh token".to_string()).into())
        }
    }
}

#[instrument(skip_all, level = "debug")]
async fn get_refresh<Backend>(
    data: web::Data<AppState<Backend>>,
    request: HttpRequest,
) -> TcpResult<HttpResponse>
where
    Backend: TcpBackendHandler + BackendHandler + 'static,
{
    if data.trusted_header_options.enabled
        && let Some(header_value) = request
            .headers()
            .get(&data.trusted_header_options.header_name)
    {
        return get_trusted_header_refresh_response(&data, &request, header_value).await;
    }
    try_refresh_token(&data, &request).await
}

async fn try_refresh_token<Backend>(
    data: &web::Data<AppState<Backend>>,
    request: &HttpRequest,
) -> TcpResult<HttpResponse>
where
    Backend: TcpBackendHandler + BackendHandler + 'static,
{
    let jwt_key = &data.jwt_key;
    let (refresh_token_hash, user) = get_refresh_token(request.clone())?;
    let found = data
        .get_tcp_handler()
        .check_token(refresh_token_hash, &user)
        .await?;
    if !found {
        return Err(TcpError::DomainError(DomainError::AuthenticationError(
            "Invalid refresh token".to_string(),
        )));
    }
    let mut path = data.server_url.path().to_string();
    if !path.ends_with('/') {
        path.push('/');
    };
    let groups = data.get_readonly_handler().get_user_groups(&user).await?;
    let token = create_jwt(data.get_tcp_handler(), jwt_key, &user, groups).await;
    Ok(HttpResponse::Ok()
        .cookie(
            Cookie::build("token", token.as_str())
                .max_age(1.days())
                .path(&path)
                .http_only(true)
                .same_site(SameSite::Strict)
                .finish(),
        )
        .json(login::ServerAuthResponse::Token(
            login::ServerLoginResponse {
                token: token.as_str().to_owned(),
                refresh_token: None,
            },
        )))
}

async fn validate_trusted_header<Backend>(
    data: &web::Data<AppState<Backend>>,
    request: &HttpRequest,
    header_value: &HeaderValue,
) -> TcpResult<(UserId, HashSet<GroupDetails>)>
where
    Backend: BackendHandler,
{
    // Validate client IP is in trusted CIDRs
    let client_ip = request
        .peer_addr()
        .map(|peer_addr| peer_addr.ip())
        .ok_or_else(|| TcpError::UnauthorizedError("Could not determine client IP".to_string()))?;

    validate_trusted_proxy(client_ip, &data.trusted_header_options.trusted_proxies)?;

    // Get the username from the trusted header value selected by the caller.
    let header_name = &data.trusted_header_options.header_name;
    let username = header_value.to_str().map_err(|_| {
        TcpError::UnauthorizedError(format!(
            "Trusted header `{}` is not valid UTF-8",
            header_name
        ))
    })?;

    // Validate the username is not empty
    if username.trim().is_empty() {
        return Err(TcpError::UnauthorizedError(
            "Empty username in trusted header".to_string(),
        ));
    }

    let user_id = UserId::new(username);
    let groups = data
        .get_readonly_handler()
        .get_user_groups(&user_id)
        .await?;

    Ok((user_id, groups))
}

fn validate_trusted_proxy(client_ip: IpAddr, trusted_proxies: &[ipnet::IpNet]) -> TcpResult<()> {
    if trusted_proxies.iter().any(|cidr| cidr.contains(&client_ip)) {
        return Ok(());
    }

    Err(TcpError::UnauthorizedError(format!(
        "Request arrived from untrusted client IP {client_ip}. When trusted header authentication is enabled, LLDAP must only be reachable through a trusted proxy. Configure the proxy's address or network in `trusted_proxies` and prevent direct client access to LLDAP"
    )))
}

async fn get_trusted_header_refresh_response<Backend>(
    data: &web::Data<AppState<Backend>>,
    request: &HttpRequest,
    header_value: &HeaderValue,
) -> TcpResult<HttpResponse>
where
    Backend: BackendHandler,
{
    let (user_id, groups) = validate_trusted_header(data, request, header_value).await?;
    let is_admin = groups
        .iter()
        .any(|g| g.display_name == "lldap_admin".into());

    Ok(gen_clear_session_cookies_response(&data.server_url).json(
        login::ServerAuthResponse::TrustedHeader(login::ServerTrustedHeaderResponse {
            user_id: user_id.to_string(),
            is_admin,
            logout_url: data.trusted_header_options.logout_url.clone(),
        }),
    ))
}

async fn get_refresh_handler<Backend>(
    data: web::Data<AppState<Backend>>,
    request: HttpRequest,
) -> HttpResponse
where
    Backend: TcpBackendHandler + BackendHandler + 'static,
{
    get_refresh(data, request)
        .await
        .unwrap_or_else(error_to_http_response)
}

#[instrument(skip_all, level = "debug")]
async fn get_password_reset_step1<Backend>(
    data: web::Data<AppState<Backend>>,
    request: HttpRequest,
) -> TcpResult<()>
where
    Backend: TcpBackendHandler + BackendHandler + 'static,
{
    let user_string = request
        .match_info()
        .get("user_id")
        .ok_or_else(|| TcpError::BadRequest("Missing user ID".to_string()))?;
    let user_results = data
        .get_readonly_handler()
        .list_users(
            Some(UserRequestFilter::Or(vec![
                UserRequestFilter::UserId(UserId::new(user_string)),
                UserRequestFilter::Equality(UserColumn::Email, user_string.to_owned()),
            ])),
            false,
        )
        .await?;
    if user_results.is_empty() {
        return Ok(());
    } else if user_results.len() > 1 {
        return Err(TcpError::InternalServerError(
            "Ambiguous user id or email".to_owned(),
        ));
    }
    let user = &user_results[0].user;
    let token = match data
        .get_tcp_handler()
        .start_password_reset(&user.user_id)
        .await?
    {
        None => return Ok(()),
        Some(token) => token,
    };
    if let Err(e) = super::mail::send_password_reset_email(
        user.display_name
            .as_deref()
            .unwrap_or_else(|| user.user_id.as_str()),
        user.user_id.as_str(),
        user.email.as_str(),
        &token,
        &data.server_url,
        &data.mail_options,
    )
    .await
    {
        warn!("Error sending email: {:#?}", e);
        info!("Reset token: {}", token);
        return Err(TcpError::InternalServerError(format!(
            "Could not send email: {e}"
        )));
    }
    Ok(())
}

async fn get_password_reset_step1_handler<Backend>(
    data: web::Data<AppState<Backend>>,
    request: HttpRequest,
) -> HttpResponse
where
    Backend: TcpBackendHandler + BackendHandler + 'static,
{
    get_password_reset_step1(data, request)
        .await
        .map(|()| HttpResponse::Ok().finish())
        .unwrap_or_else(error_to_http_response)
}

#[instrument(skip_all, level = "debug")]
async fn get_password_reset_step2<Backend>(
    data: web::Data<AppState<Backend>>,
    request: HttpRequest,
) -> TcpResult<HttpResponse>
where
    Backend: TcpBackendHandler + BackendHandler + 'static,
{
    let token = request
        .match_info()
        .get("token")
        .ok_or_else(|| TcpError::BadRequest("Missing reset token".to_owned()))?;
    let user_id = data
        .get_tcp_handler()
        .get_user_id_for_password_reset_token(token)
        .await
        .map_err(|e| {
            debug!("Reset token error: {e:#}");
            TcpError::NotFoundError("Wrong or expired reset token".to_owned())
        })?;
    let _ = data
        .get_tcp_handler()
        .delete_password_reset_token(token)
        .await;
    let groups = HashSet::new();
    let token = create_jwt(data.get_tcp_handler(), &data.jwt_key, &user_id, groups).await;
    let mut path = data.server_url.path().to_string();
    if !path.ends_with('/') {
        path.push('/');
    };
    Ok(HttpResponse::Ok()
        .cookie(
            Cookie::build("token", token.as_str())
                .max_age(5.minutes())
                // Cookie is only valid to reset the password.
                .path(format!("{path}auth"))
                .http_only(true)
                .same_site(SameSite::Strict)
                .finish(),
        )
        .json(&password_reset::ServerPasswordResetResponse {
            user_id: user_id.to_string(),
            token: token.as_str().to_owned(),
        }))
}

async fn get_password_reset_step2_handler<Backend>(
    data: web::Data<AppState<Backend>>,
    request: HttpRequest,
) -> HttpResponse
where
    Backend: TcpBackendHandler + BackendHandler + 'static,
{
    get_password_reset_step2(data, request)
        .await
        .unwrap_or_else(error_to_http_response)
}

#[instrument(skip_all, level = "debug")]
async fn get_logout<Backend>(
    data: web::Data<AppState<Backend>>,
    request: HttpRequest,
) -> TcpResult<HttpResponse>
where
    Backend: TcpBackendHandler + BackendHandler + 'static,
{
    let (refresh_token_hash, user) = get_refresh_token(request)?;
    data.get_tcp_handler()
        .delete_refresh_token(refresh_token_hash)
        .await?;
    let new_blacklisted_jwt_hashes = data.get_tcp_handler().blacklist_jwts(&user).await?;
    let mut jwt_blacklist = data.jwt_blacklist.write().unwrap();
    for jwt_hash in new_blacklisted_jwt_hashes {
        jwt_blacklist.insert(jwt_hash);
    }
    Ok(gen_clear_session_cookies_response(&data.server_url).finish())
}

async fn get_logout_handler<Backend>(
    data: web::Data<AppState<Backend>>,
    request: HttpRequest,
) -> HttpResponse
where
    Backend: TcpBackendHandler + BackendHandler + 'static,
{
    get_logout(data, request)
        .await
        .unwrap_or_else(error_to_http_response)
}

pub(crate) fn error_to_api_response<T, E: Into<TcpError>>(error: E) -> ApiResult<T> {
    ApiResult::Right(error_to_http_response(error.into()))
}

pub type ApiResult<M> = actix_web::Either<web::Json<M>, HttpResponse>;

#[instrument(skip_all, level = "debug")]
async fn opaque_login_start<Backend>(
    data: web::Data<AppState<Backend>>,
    request: web::Json<login::ClientLoginStartRequest>,
) -> ApiResult<login::ServerLoginStartResponse>
where
    Backend: OpaqueHandler + 'static,
{
    data.get_opaque_handler()
        .login_start(request.into_inner())
        .await
        .map(|res| ApiResult::Left(web::Json(res)))
        .unwrap_or_else(error_to_api_response)
}

#[instrument(skip_all, level = "debug")]
async fn get_login_successful_response<Backend>(
    data: &web::Data<AppState<Backend>>,
    name: &UserId,
) -> TcpResult<HttpResponse>
where
    Backend: TcpBackendHandler + BackendHandler,
{
    // The authentication was successful, we need to fetch the groups to create the JWT
    // token.
    let groups = data.get_readonly_handler().get_user_groups(name).await?;
    let (refresh_token, max_age) = data.get_tcp_handler().create_refresh_token(name).await?;
    let token = create_jwt(data.get_tcp_handler(), &data.jwt_key, name, groups).await;
    let refresh_token_plus_name = refresh_token + "+" + name.as_str();
    let mut path = data.server_url.path().to_string();
    if !path.ends_with('/') {
        path.push('/');
    };
    Ok(HttpResponse::Ok()
        .cookie(
            Cookie::build("token", token.as_str())
                .max_age(1.days())
                .path(&path)
                .http_only(true)
                .same_site(SameSite::Strict)
                .finish(),
        )
        .cookie(
            Cookie::build("refresh_token", refresh_token_plus_name.clone())
                .max_age(max_age.num_days().days())
                .path(format!("{path}auth"))
                .http_only(true)
                .same_site(SameSite::Strict)
                .finish(),
        )
        .json(&login::ServerLoginResponse {
            token: token.as_str().to_owned(),
            refresh_token: Some(refresh_token_plus_name),
        }))
}

#[instrument(skip_all, level = "debug")]
async fn opaque_login_finish<Backend>(
    data: web::Data<AppState<Backend>>,
    request: web::Json<login::ClientLoginFinishRequest>,
) -> TcpResult<HttpResponse>
where
    Backend: TcpBackendHandler + BackendHandler + OpaqueHandler + 'static,
{
    match data
        .get_opaque_handler()
        .login_finish(request.into_inner())
        .await
    {
        Ok(name) => get_login_successful_response(&data, &name).await,
        Err(e) => Err(e.into()),
    }
}

async fn opaque_login_finish_handler<Backend>(
    data: web::Data<AppState<Backend>>,
    request: web::Json<login::ClientLoginFinishRequest>,
) -> HttpResponse
where
    Backend: TcpBackendHandler + BackendHandler + OpaqueHandler + 'static,
{
    opaque_login_finish(data, request)
        .await
        .unwrap_or_else(error_to_http_response)
}

#[instrument(skip_all, level = "debug")]
async fn simple_login<Backend>(
    data: web::Data<AppState<Backend>>,
    request: web::Json<login::ClientSimpleLoginRequest>,
) -> TcpResult<HttpResponse>
where
    Backend: TcpBackendHandler + BackendHandler + OpaqueHandler + LoginHandler + 'static,
{
    let login::ClientSimpleLoginRequest { username, password } = request.into_inner();
    let bind_request = BindRequest {
        name: username.clone(),
        password,
    };
    data.get_login_handler().bind(bind_request).await?;
    get_login_successful_response(&data, &username).await
}

async fn simple_login_handler<Backend>(
    data: web::Data<AppState<Backend>>,
    request: web::Json<login::ClientSimpleLoginRequest>,
) -> HttpResponse
where
    Backend: TcpBackendHandler + BackendHandler + OpaqueHandler + LoginHandler + 'static,
{
    simple_login(data, request)
        .await
        .unwrap_or_else(error_to_http_response)
}

#[instrument(skip_all, level = "debug")]
async fn opaque_register_start<Backend>(
    request: actix_web::HttpRequest,
    payload: actix_web::web::Payload,
    data: web::Data<AppState<Backend>>,
) -> TcpResult<registration::ServerRegistrationStartResponse>
where
    Backend: BackendHandler + OpaqueHandler + 'static,
{
    use actix_web::FromRequest;
    let inner_payload = &mut payload.into_inner();
    let validation_result = get_validation_results(&data, &request, inner_payload)
        .await
        .map_err(|_| {
            TcpError::UnauthorizedError("Not authorized to change the user's password".to_string())
        })?;
    let registration_start_request =
        web::Json::<registration::ClientRegistrationStartRequest>::from_request(
            &request,
            inner_payload,
        )
        .await
        .map_err(|e| TcpError::BadRequest(format!("{e:#?}")))?
        .into_inner();
    let user_id = &registration_start_request.username;
    let user_is_admin = data
        .get_readonly_handler()
        .get_user_groups(user_id)
        .await?
        .iter()
        .any(|g| g.display_name == "lldap_admin".into());
    if !validation_result.can_change_password(user_id, user_is_admin) {
        return Err(TcpError::UnauthorizedError(
            "Not authorized to change the user's password".to_string(),
        ));
    }
    Ok(data
        .get_opaque_handler()
        .registration_start(registration_start_request)
        .await?)
}

async fn opaque_register_start_handler<Backend>(
    request: actix_web::HttpRequest,
    payload: actix_web::web::Payload,
    data: web::Data<AppState<Backend>>,
) -> ApiResult<registration::ServerRegistrationStartResponse>
where
    Backend: BackendHandler + OpaqueHandler + 'static,
{
    opaque_register_start(request, payload, data)
        .await
        .map(|res| ApiResult::Left(web::Json(res)))
        .unwrap_or_else(error_to_api_response)
}

#[instrument(skip_all, level = "debug")]
async fn opaque_register_finish<Backend>(
    data: web::Data<AppState<Backend>>,
    request: web::Json<registration::ClientRegistrationFinishRequest>,
) -> TcpResult<HttpResponse>
where
    Backend: TcpBackendHandler + BackendHandler + OpaqueHandler + 'static,
{
    data.get_opaque_handler()
        .registration_finish(request.into_inner())
        .await?;
    Ok(HttpResponse::Ok().finish())
}

async fn opaque_register_finish_handler<Backend>(
    data: web::Data<AppState<Backend>>,
    request: web::Json<registration::ClientRegistrationFinishRequest>,
) -> HttpResponse
where
    Backend: TcpBackendHandler + BackendHandler + OpaqueHandler + 'static,
{
    opaque_register_finish(data, request)
        .await
        .unwrap_or_else(error_to_http_response)
}

pub struct CookieToHeaderTranslatorFactory;

impl<S> Transform<S, ServiceRequest> for CookieToHeaderTranslatorFactory
where
    S: Service<ServiceRequest, Response = ServiceResponse, Error = actix_web::Error>,
    S::Future: 'static,
{
    type Response = ServiceResponse;
    type Error = actix_web::Error;
    type InitError = ();
    type Transform = CookieToHeaderTranslator<S>;
    type Future = Ready<Result<Self::Transform, Self::InitError>>;

    fn new_transform(&self, service: S) -> Self::Future {
        ok(CookieToHeaderTranslator { service })
    }
}

pub struct CookieToHeaderTranslator<S> {
    service: S,
}

impl<S> Service<ServiceRequest> for CookieToHeaderTranslator<S>
where
    S: Service<ServiceRequest, Response = ServiceResponse, Error = actix_web::Error>,
    S::Future: 'static,
{
    type Response = ServiceResponse;
    type Error = actix_web::Error;
    #[allow(clippy::type_complexity)]
    type Future = Pin<Box<dyn core::future::Future<Output = Result<Self::Response, Self::Error>>>>;

    fn poll_ready(&self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.service.poll_ready(cx)
    }

    fn call(&self, mut req: ServiceRequest) -> Self::Future {
        if let Some(token_cookie) = req.cookie("token") {
            if let Ok(header_value) = actix_http::header::HeaderValue::from_str(&format!(
                "Bearer {}",
                token_cookie.value()
            )) {
                req.headers_mut()
                    .insert(actix_http::header::AUTHORIZATION, header_value);
            } else {
                return async move {
                    Ok(req.error_response(ErrorBadRequest("Invalid token cookie")))
                }
                .boxed_local();
            }
        };

        Box::pin(self.service.call(req))
    }
}

#[instrument(skip_all, level = "debug", err, ret)]
pub(crate) async fn get_validation_results<Backend: BackendHandler>(
    data: &web::Data<AppState<Backend>>,
    request: &HttpRequest,
    payload: &mut actix_http::Payload,
) -> Result<ValidationResults, actix_web::Error> {
    if data.trusted_header_options.enabled
        && let Some(header_value) = request
            .headers()
            .get(&data.trusted_header_options.header_name)
    {
        return check_if_trusted_header_is_valid(data, request, header_value).await;
    }
    BearerAuth::from_request(request, payload)
        .await
        .map(|bearer| check_if_token_is_valid(data.get_ref(), bearer.token()))?
}

#[instrument(skip_all, level = "debug", err, ret)]
pub(crate) fn check_if_token_is_valid<Backend: BackendHandler>(
    state: &AppState<Backend>,
    token_str: &str,
) -> Result<ValidationResults, actix_web::Error> {
    let token: Token<_> = VerifyWithKey::verify_with_key(token_str, &state.jwt_key)
        .map_err(|_| ErrorUnauthorized("Invalid JWT"))?;
    if token.claims().exp.lt(&Utc::now()) {
        return Err(ErrorUnauthorized("Expired JWT"));
    }
    if token.header().algorithm != jwt::AlgorithmType::Hs512 {
        return Err(ErrorUnauthorized(format!(
            "Unsupported JWT algorithm: '{:?}'. Supported ones are: ['HS512']",
            token.header().algorithm
        )));
    }
    let jwt_hash = default_hash(token_str);
    if state.jwt_blacklist.read().unwrap().contains(&jwt_hash) {
        return Err(ErrorUnauthorized("JWT was logged out"));
    }
    Ok(state.backend_handler.get_permissions_from_groups(
        UserId::new(&token.claims().user),
        token
            .claims()
            .groups
            .iter()
            .map(|s| GroupName::from(s.as_str())),
    ))
}

#[instrument(skip_all, level = "debug", err, ret)]
pub(crate) async fn check_if_trusted_header_is_valid<Backend: BackendHandler>(
    data: &web::Data<AppState<Backend>>,
    request: &HttpRequest,
    header_value: &HeaderValue,
) -> Result<ValidationResults, actix_web::Error> {
    let (user_id, groups) = validate_trusted_header(data, request, header_value)
        .await
        .map_err(actix_web::Error::from)?;

    Ok(data.backend_handler.get_permissions_from_groups(
        user_id,
        groups
            .iter()
            .map(|g| GroupName::from(g.display_name.as_str())),
    ))
}

fn gen_clear_session_cookies_response(server_url: &url::Url) -> actix_web::HttpResponseBuilder {
    let mut path = server_url.path().to_string();
    if !path.ends_with('/') {
        path.push('/');
    };
    let mut builder = HttpResponse::Ok();
    builder
        .cookie(
            Cookie::build("token", "")
                .max_age(0.days())
                .path(&path)
                .http_only(true)
                .same_site(SameSite::Strict)
                .finish(),
        )
        .cookie(
            Cookie::build("refresh_token", "")
                .max_age(0.days())
                .path(format!("{path}auth"))
                .http_only(true)
                .same_site(SameSite::Strict)
                .finish(),
        );
    builder
}

pub fn configure_server<Backend>(cfg: &mut web::ServiceConfig, enable_password_reset: bool)
where
    Backend: TcpBackendHandler + LoginHandler + OpaqueHandler + BackendHandler + 'static,
{
    cfg.service(
        web::resource("/opaque/login/start").route(web::post().to(opaque_login_start::<Backend>)),
    )
    .service(
        web::resource("/opaque/login/finish")
            .route(web::post().to(opaque_login_finish_handler::<Backend>)),
    )
    .service(web::resource("/simple/login").route(web::post().to(simple_login_handler::<Backend>)))
    .service(web::resource("/refresh").route(web::get().to(get_refresh_handler::<Backend>)))
    .service(web::resource("/logout").route(web::get().to(get_logout_handler::<Backend>)))
    .service(
        web::scope("/opaque/register")
            .wrap(CookieToHeaderTranslatorFactory)
            .service(
                web::resource("/start")
                    .route(web::post().to(opaque_register_start_handler::<Backend>)),
            )
            .service(
                web::resource("/finish")
                    .route(web::post().to(opaque_register_finish_handler::<Backend>)),
            ),
    );
    if enable_password_reset {
        cfg.service(
            web::resource("/reset/step1/{user_id}")
                .route(web::post().to(get_password_reset_step1_handler::<Backend>)),
        )
        .service(
            web::resource("/reset/step2/{token}")
                .route(web::get().to(get_password_reset_step2_handler::<Backend>)),
        );
    } else {
        cfg.service(
            web::resource("/reset/step1/{user_id}").route(web::post().to(HttpResponse::NotFound)),
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::configuration::{MailOptions, TrustedHeaderOptions};
    use actix_web::{http::StatusCode, test as actix_test};
    use lldap_access_control::AccessControlledBackendHandler;
    use lldap_auth::opaque::server::generate_random_private_key;
    use lldap_domain::requests::CreateUserRequest;
    use lldap_domain_handlers::handler::UserBackendHandler;
    use lldap_sql_backend_handler::{SqlBackendHandler, sql_tables::init_table};
    use sea_orm::{ConnectOptions, Database};
    use std::{path::PathBuf, sync::RwLock};

    const HEADER_USER: &str = "header-user";

    struct AuthTestFixture {
        data: web::Data<AppState<SqlBackendHandler>>,
    }

    impl AuthTestFixture {
        async fn new() -> Self {
            let mut connect_options = ConnectOptions::new("sqlite::memory:");
            connect_options.max_connections(1);
            let pool = Database::connect(connect_options).await.unwrap();
            init_table(&pool).await.unwrap();

            let backend = SqlBackendHandler::new(generate_random_private_key(), pool);
            backend
                .create_user(CreateUserRequest {
                    user_id: UserId::new(HEADER_USER),
                    email: format!("{HEADER_USER}@example.com").into(),
                    display_name: None,
                    attributes: Vec::new(),
                })
                .await
                .unwrap();

            let trusted_header_options = TrustedHeaderOptions {
                enabled: true,
                header_name: "Remote-User".to_owned(),
                logout_url: None,
                trusted_proxies: vec!["127.0.0.0/8".parse().unwrap()],
            };
            let data = web::Data::new(AppState {
                backend_handler: AccessControlledBackendHandler::new(backend),
                jwt_key: hmac::Mac::new_from_slice(b"test-jwt-secret").unwrap(),
                jwt_blacklist: RwLock::new(HashSet::new()),
                server_url: "http://localhost/".parse().unwrap(),
                assets_path: PathBuf::new(),
                mail_options: MailOptions::default(),
                trusted_header_options,
            });
            Self { data }
        }
    }

    fn trusted_header_request() -> (HttpRequest, actix_http::Payload) {
        actix_test::TestRequest::default()
            .peer_addr("127.0.0.1:12345".parse().unwrap())
            .insert_header(("Remote-User", HEADER_USER))
            .to_http_parts()
    }

    #[test]
    fn untrusted_proxy_error_explains_how_to_fix_the_configuration() {
        let client_ip = "192.0.2.10".parse().unwrap();
        let trusted_proxies = ["127.0.0.0/8".parse().unwrap()];

        let error = validate_trusted_proxy(client_ip, &trusted_proxies).unwrap_err();
        let message = error.to_string();

        assert!(matches!(error, TcpError::UnauthorizedError(_)));
        assert!(message.contains("untrusted client IP 192.0.2.10"));
        assert!(message.contains("trusted_proxies"));
        assert!(message.contains("prevent direct client access"));
    }

    #[test]
    fn trusted_proxy_is_accepted() {
        let client_ip = "192.0.2.10".parse().unwrap();
        let trusted_proxies = ["192.0.2.0/24".parse().unwrap()];

        assert!(validate_trusted_proxy(client_ip, &trusted_proxies).is_ok());
    }

    #[actix_web::test]
    async fn trusted_header_backend_failure_remains_500() {
        let fixture = AuthTestFixture::new().await;
        fixture
            .data
            .backend_handler
            .unsafe_get_handler()
            .pool()
            .clone()
            .close()
            .await
            .unwrap();
        let (request, mut payload) = trusted_header_request();

        let error = get_validation_results(&fixture.data, &request, &mut payload)
            .await
            .unwrap_err();

        assert_eq!(
            error.as_response_error().status_code(),
            StatusCode::INTERNAL_SERVER_ERROR
        );
    }
}
