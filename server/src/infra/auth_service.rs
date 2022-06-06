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
use futures_util::{FutureExt, TryFutureExt};
use hmac::Hmac;
use jwt::{SignWithKey, VerifyWithKey};
use log::*;
use sha2::Sha512;
use time::ext::NumericalDuration;

use lldap_auth::{login, opaque, password_reset, registration, JWTClaims};

use crate::{
    domain::{
        error::DomainError,
        handler::{BackendHandler, BindRequest, GroupIdAndName, LoginHandler, UserId},
        opaque_handler::OpaqueHandler,
    },
    infra::{
        tcp_backend_handler::*,
        tcp_server::{error_to_http_response, AppState},
    },
};

type Token<S> = jwt::Token<jwt::Header, JWTClaims, S>;
type SignedToken = Token<jwt::token::Signed>;

fn create_jwt(key: &Hmac<Sha512>, user: String, groups: HashSet<GroupIdAndName>) -> SignedToken {
    let claims = JWTClaims {
        exp: Utc::now() + chrono::Duration::days(1),
        iat: Utc::now(),
        user,
        groups: groups.into_iter().map(|g| g.1).collect(),
    };
    let header = jwt::Header {
        algorithm: jwt::AlgorithmType::Hs512,
        ..Default::default()
    };
    jwt::Token::new(header, claims).sign_with_key(key).unwrap()
}

fn parse_refresh_token(token: &str) -> std::result::Result<(u64, UserId), HttpResponse> {
    match token.split_once('+') {
        None => Err(HttpResponse::Unauthorized().body("Invalid refresh token")),
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

fn get_refresh_token(request: HttpRequest) -> std::result::Result<(u64, UserId), HttpResponse> {
    match (
        request.cookie("refresh_token"),
        request.headers().get("refresh-token"),
    ) {
        (Some(c), _) => parse_refresh_token(c.value()),
        (_, Some(t)) => parse_refresh_token(t.to_str().unwrap()),
        (None, None) => Err(HttpResponse::Unauthorized().body("Missing refresh token")),
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
    let (refresh_token_hash, user) = match get_refresh_token(request) {
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
                    .path("/")
                    .http_only(true)
                    .same_site(SameSite::Strict)
                    .finish(),
            )
            .json(&login::ServerLoginResponse {
                token: token.as_str().to_owned(),
                refresh_token: None,
            })
    })
    .unwrap_or_else(error_to_http_response)
}

async fn get_password_reset_step1<Backend>(
    data: web::Data<AppState<Backend>>,
    request: HttpRequest,
) -> HttpResponse
where
    Backend: TcpBackendHandler + BackendHandler + 'static,
{
    let user_id = match request.match_info().get("user_id") {
        None => return HttpResponse::BadRequest().body("Missing user ID"),
        Some(id) => UserId::new(id),
    };
    let token = match data.backend_handler.start_password_reset(&user_id).await {
        Err(e) => return HttpResponse::InternalServerError().body(e.to_string()),
        Ok(None) => return HttpResponse::Ok().finish(),
        Ok(Some(token)) => token,
    };
    let user = match data.backend_handler.get_user_details(&user_id).await {
        Err(e) => {
            warn!("Error getting used details: {:#?}", e);
            return HttpResponse::Ok().finish();
        }
        Ok(u) => u,
    };
    if let Err(e) = super::mail::send_password_reset_email(
        &user.display_name,
        &user.email,
        &token,
        &data.server_url,
        &data.mail_options,
    ) {
        warn!("Error sending email: {:#?}", e);
        return HttpResponse::InternalServerError().body(format!("Could not send email: {}", e));
    }
    HttpResponse::Ok().finish()
}

async fn get_password_reset_step2<Backend>(
    data: web::Data<AppState<Backend>>,
    request: HttpRequest,
) -> HttpResponse
where
    Backend: TcpBackendHandler + BackendHandler + 'static,
{
    let token = match request.match_info().get("token") {
        None => return HttpResponse::BadRequest().body("Missing token"),
        Some(token) => token,
    };
    let user_id = match data
        .backend_handler
        .get_user_id_for_password_reset_token(token)
        .await
    {
        Err(_) => return HttpResponse::Unauthorized().body("Invalid or expired token"),
        Ok(user_id) => user_id,
    };
    let _ = data
        .backend_handler
        .delete_password_reset_token(token)
        .await;
    let groups = HashSet::new();
    let token = create_jwt(&data.jwt_key, user_id.to_string(), groups);
    HttpResponse::Ok()
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
        })
}

async fn get_logout<Backend>(
    data: web::Data<AppState<Backend>>,
    request: HttpRequest,
) -> HttpResponse
where
    Backend: TcpBackendHandler + BackendHandler + 'static,
{
    let (refresh_token_hash, user) = match get_refresh_token(request) {
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
        .finish()
}

pub(crate) fn error_to_api_response<T>(error: DomainError) -> ApiResult<T> {
    ApiResult::Right(error_to_http_response(error))
}

pub type ApiResult<M> = actix_web::Either<web::Json<M>, HttpResponse>;

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
    name: &UserId,
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
            let refresh_token_plus_name = refresh_token + "+" + name.as_str();

            HttpResponse::Ok()
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
                })
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

async fn simple_login<Backend>(
    data: web::Data<AppState<Backend>>,
    request: web::Json<login::ClientSimpleLoginRequest>,
) -> HttpResponse
where
    Backend: TcpBackendHandler + BackendHandler + OpaqueHandler + 'static,
{
    let password = &request.password;
    let mut rng = rand::rngs::OsRng;
    let opaque::client::login::ClientLoginStartResult { state, message } =
        match opaque::client::login::start_login(password, &mut rng) {
            Ok(n) => n,
            Err(e) => {
                return HttpResponse::InternalServerError()
                    .body(format!("Internal Server Error: {:#?}", e))
            }
        };

    let username = request.username.clone();
    let start_request = login::ClientLoginStartRequest {
        username: username.clone(),
        login_start_request: message,
    };

    let start_response = match data.backend_handler.login_start(start_request).await {
        Ok(n) => n,
        Err(e) => return error_to_http_response(e),
    };

    let login_finish =
        match opaque::client::login::finish_login(state, start_response.credential_response) {
            Err(_) => {
                return error_to_http_response(DomainError::AuthenticationError(String::from(
                    "Invalid username or password",
                )))
            }
            Ok(l) => l,
        };

    let finish_request = login::ClientLoginFinishRequest {
        server_data: start_response.server_data,
        credential_finalization: login_finish.message,
    };

    let name = match data.backend_handler.login_finish(finish_request).await {
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
    request: actix_web::HttpRequest,
    mut payload: actix_web::web::Payload,
    data: web::Data<AppState<Backend>>,
) -> ApiResult<registration::ServerRegistrationStartResponse>
where
    Backend: OpaqueHandler + 'static,
{
    use actix_web::FromRequest;
    let validation_result = match BearerAuth::from_request(&request, &mut payload.0)
        .await
        .ok()
        .and_then(|bearer| check_if_token_is_valid(&data, bearer.token()).ok())
    {
        Some(t) => t,
        None => {
            return ApiResult::Right(
                HttpResponse::Unauthorized().body("Not authorized to change the user's password"),
            )
        }
    };
    let registration_start_request =
        match web::Json::<registration::ClientRegistrationStartRequest>::from_request(
            &request,
            &mut payload.0,
        )
        .await
        {
            Ok(r) => r,
            Err(e) => {
                return ApiResult::Right(
                    HttpResponse::BadRequest().body(format!("Bad request: {:#?}", e)),
                )
            }
        }
        .into_inner();
    let user_id = &registration_start_request.username;
    if !validation_result.can_write(user_id) {
        return ApiResult::Right(
            HttpResponse::Unauthorized().body("Not authorized to change the user's password"),
        );
    }
    data.backend_handler
        .registration_start(registration_start_request)
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

#[derive(Clone, Copy, PartialEq, Debug)]
pub enum Permission {
    Admin,
    Readonly,
    Regular,
}

pub struct ValidationResults {
    pub user: String,
    pub permission: Permission,
}

impl ValidationResults {
    #[cfg(test)]
    pub fn admin() -> Self {
        Self {
            user: "admin".to_string(),
            permission: Permission::Admin,
        }
    }

    #[must_use]
    pub fn is_admin(&self) -> bool {
        self.permission == Permission::Admin
    }

    #[must_use]
    pub fn is_admin_or_readonly(&self) -> bool {
        self.permission == Permission::Admin || self.permission == Permission::Readonly
    }

    #[must_use]
    pub fn can_read(&self, user: &str) -> bool {
        self.permission == Permission::Admin
            || self.permission == Permission::Readonly
            || self.user == user
    }

    #[must_use]
    pub fn can_write(&self, user: &str) -> bool {
        self.permission == Permission::Admin || self.user == user
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
        user: token.claims().user.clone(),
        permission: if is_in_group("lldap_admin") {
            Permission::Admin
        } else if is_in_group("lldap_readonly") {
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
    cfg.service(web::resource("").route(web::post().to(post_authorize::<Backend>)))
        .service(
            web::resource("/opaque/login/start")
                .route(web::post().to(opaque_login_start::<Backend>)),
        )
        .service(
            web::resource("/opaque/login/finish")
                .route(web::post().to(opaque_login_finish::<Backend>)),
        )
        .service(web::resource("/simple/login").route(web::post().to(simple_login::<Backend>)))
        .service(web::resource("/refresh").route(web::get().to(get_refresh::<Backend>)))
        .service(
            web::resource("/reset/step1/{user_id}")
                .route(web::get().to(get_password_reset_step1::<Backend>)),
        )
        .service(
            web::resource("/reset/step2/{token}")
                .route(web::get().to(get_password_reset_step2::<Backend>)),
        )
        .service(web::resource("/logout").route(web::get().to(get_logout::<Backend>)))
        .service(
            web::scope("/opaque/register")
                .wrap(CookieToHeaderTranslatorFactory)
                .service(
                    web::resource("/start").route(web::post().to(opaque_register_start::<Backend>)),
                )
                .service(
                    web::resource("/finish")
                        .route(web::post().to(opaque_register_finish::<Backend>)),
                ),
        );
}
