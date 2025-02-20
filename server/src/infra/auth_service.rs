use actix_web::{
    cookie::{Cookie, SameSite},
    dev::{Service, ServiceRequest, ServiceResponse, Transform},
    error::{ErrorBadRequest, ErrorUnauthorized},
    web, HttpRequest, HttpResponse,
};
use actix_web_httpauth::extractors::bearer::BearerAuth;
use anyhow::Result;
use chrono::prelude::*;
use futures::future::{ok, Ready};
use futures_util::FutureExt;
use hmac::Hmac;
use jwt::{SignWithKey, VerifyWithKey};
use sha2::Sha512;
use std::{
    collections::HashSet,
    hash::Hash,
    pin::Pin,
    task::{Context, Poll},
};
use time::ext::NumericalDuration;
use tracing::{debug, info, instrument, warn};

use lldap_auth::{
    access_control::ValidationResults, login, password_reset, registration, JWTClaims,
};
use lldap_domain::types::{GroupDetails, GroupName, UserId};
use lldap_domain_handlers::handler::{
    BackendHandler, BindRequest, LoginHandler, UserRequestFilter,
};
use lldap_domain_model::{error::DomainError, model::UserColumn};

use crate::{
    domain::opaque_handler::OpaqueHandler,
    infra::{
        access_control::{ReadonlyBackendHandler, UserReadableBackendHandler},
        tcp_backend_handler::*,
        tcp_server::{error_to_http_response, AppState, TcpError, TcpResult},
    },
};

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
    let jwt_key = &data.jwt_key;
    let (refresh_token_hash, user) = get_refresh_token(request)?;
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
        .json(&login::ServerLoginResponse {
            token: token.as_str().to_owned(),
            refresh_token: None,
        }))
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
            "Could not send email: {}",
            e
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
                .path(format!("{}auth", path))
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
    let mut path = data.server_url.path().to_string();
    if !path.ends_with('/') {
        path.push('/');
    };
    Ok(HttpResponse::Ok()
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
                .path(format!("{}auth", path))
                .http_only(true)
                .same_site(SameSite::Strict)
                .finish(),
        )
        .finish())
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
                .path(format!("{}auth", path))
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
    let validation_result = BearerAuth::from_request(&request, inner_payload)
        .await
        .ok()
        .and_then(|bearer| check_if_token_is_valid(&data, bearer.token()).ok())
        .ok_or_else(|| {
            TcpError::UnauthorizedError("Not authorized to change the user's password".to_string())
        })?;
    let registration_start_request =
        web::Json::<registration::ClientRegistrationStartRequest>::from_request(
            &request,
            inner_payload,
        )
        .await
        .map_err(|e| TcpError::BadRequest(format!("{:#?}", e)))?
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
