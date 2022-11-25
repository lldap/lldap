use std::collections::{hash_map::DefaultHasher, HashSet};
use std::hash::{Hash, Hasher};
use std::pin::Pin;
use std::task::{Context, Poll};

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
use time::ext::NumericalDuration;
use tracing::{debug, instrument, warn};

use lldap_auth::{login, password_reset, registration, JWTClaims};

use crate::{
    domain::{
        error::DomainError,
        handler::{BackendHandler, BindRequest, LoginHandler, UserRequestFilter},
        opaque_handler::OpaqueHandler,
        types::{GroupDetails, UserColumn, UserId},
    },
    infra::{
        tcp_backend_handler::*,
        tcp_server::{error_to_http_response, AppState, TcpError, TcpResult},
    },
};

type Token<S> = jwt::Token<jwt::Header, JWTClaims, S>;
type SignedToken = Token<jwt::token::Signed>;

fn create_jwt(key: &Hmac<Sha512>, user: String, groups: HashSet<GroupDetails>) -> SignedToken {
    let claims = JWTClaims {
        exp: Utc::now() + chrono::Duration::days(1),
        iat: Utc::now(),
        user,
        groups: groups.into_iter().map(|g| g.display_name).collect(),
    };
    let header = jwt::Header {
        algorithm: jwt::AlgorithmType::Hs512,
        ..Default::default()
    };
    jwt::Token::new(header, claims).sign_with_key(key).unwrap()
}

fn parse_refresh_token(token: &str) -> TcpResult<(u64, UserId)> {
    match token.split_once('+') {
        None => Err(DomainError::AuthenticationError("Invalid refresh token".to_string()).into()),
        Some((token, u)) => {
            let refresh_token_hash = {
                let mut s = DefaultHasher::new();
                token.hash(&mut s);
                s.finish()
            };
            Ok((refresh_token_hash, UserId::new(u)))
        }
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
    let backend_handler = &data.backend_handler;
    let jwt_key = &data.jwt_key;
    let (refresh_token_hash, user) = get_refresh_token(request)?;
    let found = data
        .backend_handler
        .check_token(refresh_token_hash, &user)
        .await?;
    if !found {
        return Err(TcpError::DomainError(DomainError::AuthenticationError(
            "Invalid refresh token".to_string(),
        )));
    }
    Ok(backend_handler
        .get_user_groups(&user)
        .await
        .map(|groups| create_jwt(jwt_key, user.to_string(), groups))
        .map(|token| {
            HttpResponse::Ok()
                .cookie(
                    Cookie::build("token", token.as_str())
                        .max_age(1.days())
                        .path("/")
                        .http_only(true)
                        .same_site(SameSite::Strict)
                        .finish(),
                )
                .json(&login::ServerLoginResponse {
                    token: token.as_str().to_owned(),
                    refresh_token: None,
                })
        })?)
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
        .backend_handler
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
        .backend_handler
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
        &user.email,
        &token,
        &data.server_url,
        &data.mail_options,
    )
    .await
    {
        warn!("Error sending email: {:#?}", e);
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
        .ok_or_else(|| TcpError::BadRequest("Missing reset token".to_string()))?;
    let user_id = data
        .backend_handler
        .get_user_id_for_password_reset_token(token)
        .await?;
    let _ = data
        .backend_handler
        .delete_password_reset_token(token)
        .await;
    let groups = HashSet::new();
    let token = create_jwt(&data.jwt_key, user_id.to_string(), groups);
    Ok(HttpResponse::Ok()
        .cookie(
            Cookie::build("token", token.as_str())
                .max_age(5.minutes())
                // Cookie is only valid to reset the password.
                .path("/auth")
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
    data.backend_handler
        .delete_refresh_token(refresh_token_hash)
        .await?;
    let new_blacklisted_jwts = data.backend_handler.blacklist_jwts(&user).await?;
    let mut jwt_blacklist = data.jwt_blacklist.write().unwrap();
    for jwt in new_blacklisted_jwts {
        jwt_blacklist.insert(jwt);
    }
    Ok(HttpResponse::Ok()
        .cookie(
            Cookie::build("token", "")
                .max_age(0.days())
                .path("/")
                .http_only(true)
                .same_site(SameSite::Strict)
                .finish(),
        )
        .cookie(
            Cookie::build("refresh_token", "")
                .max_age(0.days())
                .path("/auth")
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
    data.backend_handler
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
    let groups = data.backend_handler.get_user_groups(name).await?;
    let (refresh_token, max_age) = data.backend_handler.create_refresh_token(name).await?;
    let token = create_jwt(&data.jwt_key, name.to_string(), groups);
    let refresh_token_plus_name = refresh_token + "+" + name.as_str();

    Ok(HttpResponse::Ok()
        .cookie(
            Cookie::build("token", token.as_str())
                .max_age(1.days())
                .path("/")
                .http_only(true)
                .same_site(SameSite::Strict)
                .finish(),
        )
        .cookie(
            Cookie::build("refresh_token", refresh_token_plus_name.clone())
                .max_age(max_age.num_days().days())
                .path("/auth")
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
    let name = data
        .backend_handler
        .login_finish(request.into_inner())
        .await?;
    get_login_successful_response(&data, &name).await
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
    let user_id = UserId::new(&request.username);
    let bind_request = BindRequest {
        name: user_id.clone(),
        password: request.password.clone(),
    };
    data.backend_handler.bind(bind_request).await?;
    get_login_successful_response(&data, &user_id).await
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
async fn post_authorize<Backend>(
    data: web::Data<AppState<Backend>>,
    request: web::Json<BindRequest>,
) -> TcpResult<HttpResponse>
where
    Backend: TcpBackendHandler + BackendHandler + LoginHandler + 'static,
{
    let name = request.name.clone();
    debug!(%name);
    data.backend_handler.bind(request.into_inner()).await?;
    get_login_successful_response(&data, &name).await
}

async fn post_authorize_handler<Backend>(
    data: web::Data<AppState<Backend>>,
    request: web::Json<BindRequest>,
) -> HttpResponse
where
    Backend: TcpBackendHandler + BackendHandler + LoginHandler + 'static,
{
    post_authorize(data, request)
        .await
        .unwrap_or_else(error_to_http_response)
}

#[instrument(skip_all, level = "debug")]
async fn opaque_register_start<Backend>(
    request: actix_web::HttpRequest,
    mut payload: actix_web::web::Payload,
    data: web::Data<AppState<Backend>>,
) -> TcpResult<registration::ServerRegistrationStartResponse>
where
    Backend: BackendHandler + OpaqueHandler + 'static,
{
    use actix_web::FromRequest;
    let validation_result = BearerAuth::from_request(&request, &mut payload.0)
        .await
        .ok()
        .and_then(|bearer| check_if_token_is_valid(&data, bearer.token()).ok())
        .ok_or_else(|| {
            TcpError::UnauthorizedError("Not authorized to change the user's password".to_string())
        })?;
    let registration_start_request =
        web::Json::<registration::ClientRegistrationStartRequest>::from_request(
            &request,
            &mut payload.0,
        )
        .await
        .map_err(|e| TcpError::BadRequest(format!("{:#?}", e)))?
        .into_inner();
    let user_id = UserId::new(&registration_start_request.username);
    let user_is_admin = data
        .backend_handler
        .get_user_groups(&user_id)
        .await?
        .iter()
        .any(|g| g.display_name == "lldap_admin");
    if !validation_result.can_change_password(&user_id, user_is_admin) {
        return Err(TcpError::UnauthorizedError(
            "Not authorized to change the user's password".to_string(),
        ));
    }
    Ok(data
        .backend_handler
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
    data.backend_handler
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

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Permission {
    Admin,
    PasswordManager,
    Readonly,
    Regular,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidationResults {
    pub user: UserId,
    pub permission: Permission,
}

impl ValidationResults {
    #[cfg(test)]
    pub fn admin() -> Self {
        Self {
            user: UserId::new("admin"),
            permission: Permission::Admin,
        }
    }

    #[must_use]
    pub fn is_admin(&self) -> bool {
        self.permission == Permission::Admin
    }

    #[must_use]
    pub fn is_admin_or_readonly(&self) -> bool {
        self.permission == Permission::Admin
            || self.permission == Permission::Readonly
            || self.permission == Permission::PasswordManager
    }

    #[must_use]
    pub fn can_read(&self, user: &UserId) -> bool {
        self.permission == Permission::Admin
            || self.permission == Permission::PasswordManager
            || self.permission == Permission::Readonly
            || &self.user == user
    }

    #[must_use]
    pub fn can_change_password(&self, user: &UserId, user_is_admin: bool) -> bool {
        self.permission == Permission::Admin
            || (self.permission == Permission::PasswordManager && !user_is_admin)
            || &self.user == user
    }

    #[must_use]
    pub fn can_write(&self, user: &UserId) -> bool {
        self.permission == Permission::Admin || &self.user == user
    }
}

#[instrument(skip_all, level = "debug", err, ret)]
pub(crate) fn check_if_token_is_valid<Backend>(
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
    let jwt_hash = {
        let mut s = DefaultHasher::new();
        token_str.hash(&mut s);
        s.finish()
    };
    if state.jwt_blacklist.read().unwrap().contains(&jwt_hash) {
        return Err(ErrorUnauthorized("JWT was logged out"));
    }
    let is_in_group = |name| token.claims().groups.contains(name);
    Ok(ValidationResults {
        user: UserId::new(&token.claims().user),
        permission: if is_in_group("lldap_admin") {
            Permission::Admin
        } else if is_in_group("lldap_password_manager") {
            Permission::PasswordManager
        } else if is_in_group("lldap_strict_readonly") {
            Permission::Readonly
        } else {
            Permission::Regular
        },
    })
}

pub fn configure_server<Backend>(cfg: &mut web::ServiceConfig)
where
    Backend: TcpBackendHandler + LoginHandler + OpaqueHandler + BackendHandler + 'static,
{
    cfg.service(web::resource("").route(web::post().to(post_authorize_handler::<Backend>)))
        .service(
            web::resource("/opaque/login/start")
                .route(web::post().to(opaque_login_start::<Backend>)),
        )
        .service(
            web::resource("/opaque/login/finish")
                .route(web::post().to(opaque_login_finish_handler::<Backend>)),
        )
        .service(
            web::resource("/simple/login").route(web::post().to(simple_login_handler::<Backend>)),
        )
        .service(web::resource("/refresh").route(web::get().to(get_refresh_handler::<Backend>)))
        .service(
            web::resource("/reset/step1/{user_id}")
                .route(web::get().to(get_password_reset_step1_handler::<Backend>)),
        )
        .service(
            web::resource("/reset/step2/{token}")
                .route(web::get().to(get_password_reset_step2_handler::<Backend>)),
        )
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
}
