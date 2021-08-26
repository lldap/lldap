use crate::{
    domain::{
        error::DomainError,
        handler::{BackendHandler, LoginHandler},
        opaque_handler::OpaqueHandler,
    },
    infra::{
        tcp_api::{error_to_api_response, ApiResult},
        tcp_backend_handler::*,
        tcp_server::{error_to_http_response, AppState},
    },
};
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
use futures_util::{FutureExt, TryFutureExt};
use hmac::Hmac;
use jwt::{SignWithKey, VerifyWithKey};
use lldap_model::{login, registration, BindRequest, JWTClaims};
use log::*;
use sha2::Sha512;
use std::collections::{hash_map::DefaultHasher, HashSet};
use std::hash::{Hash, Hasher};
use std::pin::Pin;
use std::task::{Context, Poll};
use time::ext::NumericalDuration;

type Token<S> = jwt::Token<jwt::Header, JWTClaims, S>;
type SignedToken = Token<jwt::token::Signed>;

fn create_jwt(key: &Hmac<Sha512>, user: String, groups: HashSet<String>) -> SignedToken {
    let claims = JWTClaims {
        exp: Utc::now() + chrono::Duration::days(1),
        iat: Utc::now(),
        user,
        groups,
    };
    let header = jwt::Header {
        algorithm: jwt::AlgorithmType::Hs512,
        ..Default::default()
    };
    jwt::Token::new(header, claims).sign_with_key(key).unwrap()
}

fn get_refresh_token_from_cookie(
    request: HttpRequest,
) -> std::result::Result<(u64, String), HttpResponse> {
    match request.cookie("refresh_token") {
        None => Err(HttpResponse::Unauthorized().body("Missing refresh token")),
        Some(t) => match t.value().split_once("+") {
            None => Err(HttpResponse::Unauthorized().body("Invalid refresh token")),
            Some((token, u)) => {
                let refresh_token_hash = {
                    let mut s = DefaultHasher::new();
                    token.hash(&mut s);
                    s.finish()
                };
                Ok((refresh_token_hash, u.to_string()))
            }
        },
    }
}

async fn get_refresh<Backend>(
    data: web::Data<AppState<Backend>>,
    request: HttpRequest,
) -> HttpResponse
where
    Backend: TcpBackendHandler + BackendHandler + 'static,
{
    let backend_handler = &data.backend_handler;
    let jwt_key = &data.jwt_key;
    let (refresh_token_hash, user) = match get_refresh_token_from_cookie(request) {
        Ok(t) => t,
        Err(http_response) => return http_response,
    };
    let res_found = data
        .backend_handler
        .check_token(refresh_token_hash, &user)
        .await;
    // Async closures are not supported yet.
    match res_found {
        Ok(found) => {
            if found {
                backend_handler.get_user_groups(&user).await
            } else {
                Err(DomainError::AuthenticationError(
                    "Invalid refresh token".to_string(),
                ))
            }
        }
        Err(e) => Err(e),
    }
    .map(|groups| create_jwt(jwt_key, user.to_string(), groups))
    .map(|token| {
        HttpResponse::Ok()
            .cookie(
                Cookie::build("token", token.as_str())
                    .max_age(1.days())
                    .path("/api")
                    .http_only(true)
                    .same_site(SameSite::Strict)
                    .finish(),
            )
            .body(token.as_str().to_owned())
    })
    .unwrap_or_else(error_to_http_response)
}

async fn get_logout<Backend>(
    data: web::Data<AppState<Backend>>,
    request: HttpRequest,
) -> HttpResponse
where
    Backend: TcpBackendHandler + BackendHandler + 'static,
{
    let (refresh_token_hash, user) = match get_refresh_token_from_cookie(request) {
        Ok(t) => t,
        Err(http_response) => return http_response,
    };
    if let Err(response) = data
        .backend_handler
        .delete_refresh_token(refresh_token_hash)
        .map_err(error_to_http_response)
        .await
    {
        return response;
    };
    match data
        .backend_handler
        .blacklist_jwts(&user)
        .map_err(error_to_http_response)
        .await
    {
        Ok(new_blacklisted_jwts) => {
            let mut jwt_blacklist = data.jwt_blacklist.write().unwrap();
            for jwt in new_blacklisted_jwts {
                jwt_blacklist.insert(jwt);
            }
        }
        Err(response) => return response,
    };
    HttpResponse::Ok()
        .cookie(
            Cookie::build("token", "")
                .max_age(0.days())
                .path("/api")
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
        .finish()
}

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

async fn get_login_successful_response<Backend>(
    data: &web::Data<AppState<Backend>>,
    name: &str,
) -> HttpResponse
where
    Backend: TcpBackendHandler + BackendHandler,
{
    // The authentication was successful, we need to fetch the groups to create the JWT
    // token.
    data.backend_handler
        .get_user_groups(name)
        .and_then(|g| async { Ok((g, data.backend_handler.create_refresh_token(name).await?)) })
        .await
        .map(|(groups, (refresh_token, max_age))| {
            let token = create_jwt(&data.jwt_key, name.to_string(), groups);
            HttpResponse::Ok()
                .cookie(
                    Cookie::build("token", token.as_str())
                        .max_age(1.days())
                        .path("/api")
                        .http_only(true)
                        .same_site(SameSite::Strict)
                        .finish(),
                )
                .cookie(
                    Cookie::build("refresh_token", refresh_token + "+" + name)
                        .max_age(max_age.num_days().days())
                        .path("/auth")
                        .http_only(true)
                        .same_site(SameSite::Strict)
                        .finish(),
                )
                .body(token.as_str().to_owned())
        })
        .unwrap_or_else(error_to_http_response)
}

async fn opaque_login_finish<Backend>(
    data: web::Data<AppState<Backend>>,
    request: web::Json<login::ClientLoginFinishRequest>,
) -> HttpResponse
where
    Backend: TcpBackendHandler + BackendHandler + OpaqueHandler + 'static,
{
    let name = match data
        .backend_handler
        .login_finish(request.into_inner())
        .await
    {
        Ok(n) => n,
        Err(e) => return error_to_http_response(e),
    };
    get_login_successful_response(&data, &name).await
}

async fn post_authorize<Backend>(
    data: web::Data<AppState<Backend>>,
    request: web::Json<BindRequest>,
) -> HttpResponse
where
    Backend: TcpBackendHandler + BackendHandler + LoginHandler + 'static,
{
    let name = request.name.clone();
    if let Err(e) = data.backend_handler.bind(request.into_inner()).await {
        return error_to_http_response(e);
    }
    get_login_successful_response(&data, &name).await
}

async fn opaque_register_start<Backend>(
    data: web::Data<AppState<Backend>>,
    request: web::Json<registration::ClientRegistrationStartRequest>,
) -> ApiResult<registration::ServerRegistrationStartResponse>
where
    Backend: OpaqueHandler + 'static,
{
    data.backend_handler
        .registration_start(request.into_inner())
        .await
        .map(|res| ApiResult::Left(web::Json(res)))
        .unwrap_or_else(error_to_api_response)
}

async fn opaque_register_finish<Backend>(
    data: web::Data<AppState<Backend>>,
    request: web::Json<registration::ClientRegistrationFinishRequest>,
) -> HttpResponse
where
    Backend: TcpBackendHandler + BackendHandler + OpaqueHandler + 'static,
{
    if let Err(e) = data
        .backend_handler
        .registration_finish(request.into_inner())
        .await
    {
        return error_to_http_response(e);
    }
    HttpResponse::Ok().finish()
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

pub struct ValidationResults {
    pub user: String,
    pub is_admin: bool,
}

impl ValidationResults {
    #[cfg(test)]
    pub fn admin() -> Self {
        Self {
            user: "admin".to_string(),
            is_admin: true,
        }
    }

    pub fn can_access(&self, user: &str) -> bool {
        self.is_admin || self.user == user
    }
}

pub(crate) fn check_if_token_is_valid<Backend>(
    state: &AppState<Backend>,
    token_str: &str,
) -> Result<ValidationResults, actix_web::Error> {
    let token: Token<_> = VerifyWithKey::verify_with_key(token_str, &state.jwt_key)
        .map_err(|_| ErrorUnauthorized("Invalid JWT"))?;
    if token.claims().exp.lt(&Utc::now()) {
        return Err(ErrorUnauthorized("Expired JWT"));
    }
    let jwt_hash = {
        let mut s = DefaultHasher::new();
        token_str.hash(&mut s);
        s.finish()
    };
    if state.jwt_blacklist.read().unwrap().contains(&jwt_hash) {
        return Err(ErrorUnauthorized("JWT was logged out"));
    }
    let is_admin = token.claims().groups.contains("lldap_admin");
    Ok(ValidationResults {
        user: token.claims().user.clone(),
        is_admin,
    })
}

pub async fn token_validator<Backend>(
    req: ServiceRequest,
    credentials: BearerAuth,
    admin_required: bool,
) -> Result<ServiceRequest, actix_web::Error>
where
    Backend: TcpBackendHandler + BackendHandler + 'static,
{
    let state = req
        .app_data::<web::Data<AppState<Backend>>>()
        .expect("Invalid app config");
    let ValidationResults { user, is_admin } = check_if_token_is_valid(state, credentials.token())?;
    if is_admin || (!admin_required && req.match_info().get("user_id") == Some(&user)) {
        debug!("Got authorized token for user {}", &user);
        Ok(req)
    } else {
        Err(ErrorUnauthorized(
            "JWT error: User is not authorized to access this resource",
        ))
    }
}

pub async fn admin_token_validator<Backend>(
    req: ServiceRequest,
    credentials: BearerAuth,
) -> Result<ServiceRequest, actix_web::Error>
where
    Backend: TcpBackendHandler + BackendHandler + 'static,
{
    token_validator::<Backend>(req, credentials, true).await
}

pub async fn user_token_validator<Backend>(
    req: ServiceRequest,
    credentials: BearerAuth,
) -> Result<ServiceRequest, actix_web::Error>
where
    Backend: TcpBackendHandler + BackendHandler + 'static,
{
    token_validator::<Backend>(req, credentials, false).await
}

pub fn configure_server<Backend>(cfg: &mut web::ServiceConfig)
where
    Backend: TcpBackendHandler + LoginHandler + OpaqueHandler + BackendHandler + 'static,
{
    cfg.service(web::resource("").route(web::post().to(post_authorize::<Backend>)))
        .service(
            web::resource("/opaque/login/start")
                .route(web::post().to(opaque_login_start::<Backend>)),
        )
        .service(
            web::resource("/opaque/login/finish")
                .route(web::post().to(opaque_login_finish::<Backend>)),
        )
        .service(
            web::resource("/opaque/register/start")
                .route(web::post().to(opaque_register_start::<Backend>)),
        )
        .service(
            web::resource("/opaque/register/finish")
                .route(web::post().to(opaque_register_finish::<Backend>)),
        )
        .service(web::resource("/refresh").route(web::get().to(get_refresh::<Backend>)))
        .service(web::resource("/logout").route(web::get().to(get_logout::<Backend>)));
}
