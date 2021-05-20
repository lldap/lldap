use crate::domain::handler::*;
use crate::infra::configuration::Configuration;
use actix_files::{Files, NamedFile};
use actix_http::HttpServiceBuilder;
use actix_server::ServerBuilder;
use actix_service::{map_config, Service};
use actix_web::{
    cookie::{Cookie, SameSite},
    dev::{AppConfig, ServiceRequest},
    error::{ErrorBadRequest, ErrorUnauthorized},
    web, App, HttpRequest, HttpResponse,
};
use actix_web_httpauth::{extractors::bearer::BearerAuth, middleware::HttpAuthentication};
use anyhow::{Context, Result};
use async_trait::async_trait;
use chrono::prelude::*;
use futures_util::FutureExt;
use futures_util::TryFutureExt;
use hmac::{Hmac, NewMac};
use jwt::{SignWithKey, VerifyWithKey};
use log::*;
use sha2::Sha512;
use std::collections::{hash_map::DefaultHasher, HashSet};
use std::hash::{Hash, Hasher};
use std::path::PathBuf;
use time::ext::NumericalDuration;

type Token<S> = jwt::Token<jwt::Header, JWTClaims, S>;
type SignedToken = Token<jwt::token::Signed>;

type DomainError = crate::domain::error::Error;
type DomainResult<T> = crate::domain::error::Result<T>;

#[async_trait]
pub trait TcpBackendHandler: BackendHandler {
    async fn get_jwt_blacklist(&self) -> Result<HashSet<u64>>;
    async fn create_refresh_token(&self, user: &str) -> DomainResult<(String, chrono::Duration)>;
    async fn check_token(&self, token: &str, user: &str) -> DomainResult<bool>;
}

async fn index(req: HttpRequest) -> actix_web::Result<NamedFile> {
    let mut path = PathBuf::new();
    path.push("app");
    let file = req.match_info().query("filename");
    path.push(if file.is_empty() { "index.html" } else { file });
    Ok(NamedFile::open(path)?)
}

fn error_to_http_response<T>(error: DomainError) -> ApiResult<T> {
    ApiResult::Right(
        match error {
            DomainError::AuthenticationError(_) => HttpResponse::Unauthorized(),
            DomainError::DatabaseError(_) => HttpResponse::InternalServerError(),
        }
        .body(error.to_string()),
    )
}

type ApiResult<M> = actix_web::Either<web::Json<M>, HttpResponse>;

async fn user_list_handler<Backend>(
    data: web::Data<AppState<Backend>>,
    info: web::Json<ListUsersRequest>,
) -> ApiResult<Vec<User>>
where
    Backend: TcpBackendHandler + 'static,
{
    let req: ListUsersRequest = info.clone();
    data.backend_handler
        .list_users(req)
        .await
        .map(|res| ApiResult::Left(web::Json(res)))
        .unwrap_or_else(error_to_http_response)
}

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

async fn get_refresh<Backend>(
    data: web::Data<AppState<Backend>>,
    request: HttpRequest,
) -> ApiResult<String>
where
    Backend: TcpBackendHandler + 'static,
{
    let backend_handler = &data.backend_handler;
    let jwt_key = &data.jwt_key;
    let (refresh_token, user) = match request.cookie("refresh_token") {
        None => {
            return ApiResult::Right(HttpResponse::Unauthorized().body("Missing refresh token"))
        }
        Some(t) => match t.value().split_once("+") {
            None => {
                return ApiResult::Right(HttpResponse::Unauthorized().body("Invalid refresh token"))
            }
            Some((t, u)) => (t.to_string(), u.to_string()),
        },
    };
    let res_found = data.backend_handler.check_token(&refresh_token, &user).await;
    // Async closures are not supported yet.
    match res_found {
        Ok(found) => {
            if found {
                backend_handler.get_user_groups(user.to_string()).await
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
        ApiResult::Right(
            HttpResponse::Ok()
                .cookie(
                    Cookie::build("token", token.as_str())
                        .max_age(1.days())
                        .path("/api")
                        .http_only(true)
                        .same_site(SameSite::Strict)
                        .finish(),
                )
                .body(token.as_str().to_owned()),
        )
    })
    .unwrap_or_else(error_to_http_response)
}

async fn post_authorize<Backend>(
    data: web::Data<AppState<Backend>>,
    request: web::Json<BindRequest>,
) -> ApiResult<String>
where
    Backend: TcpBackendHandler + 'static,
{
    let req: BindRequest = request.clone();
    data.backend_handler
        .bind(req)
        // If the authentication was successful, we need to fetch the groups to create the JWT
        // token.
        .and_then(|_| data.backend_handler.get_user_groups(request.name.clone()))
        .and_then(|g| async {
            Ok((
                g,
                data.backend_handler
                    .create_refresh_token(&request.name)
                    .await?,
            ))
        })
        .await
        .map(|(groups, (refresh_token, max_age))| {
            let token = create_jwt(&data.jwt_key, request.name.clone(), groups);
            ApiResult::Right(
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
                        Cookie::build("refresh_token", refresh_token + "+" + &request.name)
                            .max_age(max_age.num_days().days())
                            .path("/api/authorize/refresh")
                            .http_only(true)
                            .same_site(SameSite::Strict)
                            .finish(),
                    )
                    .body(token.as_str().to_owned()),
            )
        })
        .unwrap_or_else(error_to_http_response)
}

fn api_config<Backend>(cfg: &mut web::ServiceConfig)
where
    Backend: TcpBackendHandler + 'static,
{
    let json_config = web::JsonConfig::default()
        .limit(4096)
        .error_handler(|err, _req| {
            // create custom error response
            log::error!("API error: {}", err);
            let msg = err.to_string();
            actix_web::error::InternalError::from_response(
                err,
                HttpResponse::BadRequest().body(msg).into(),
            )
            .into()
        });
    cfg.service(
        web::resource("/users")
            .app_data(json_config)
            .route(web::post().to(user_list_handler::<Backend>)),
    );
}

async fn token_validator<Backend>(
    req: ServiceRequest,
    credentials: BearerAuth,
) -> Result<ServiceRequest, actix_web::Error>
where
    Backend: TcpBackendHandler + 'static,
{
    let state = req
        .app_data::<web::Data<AppState<Backend>>>()
        .expect("Invalid app config");
    let token: Token<_> = VerifyWithKey::verify_with_key(credentials.token(), &state.jwt_key)
        .map_err(|_| ErrorUnauthorized("Invalid JWT"))?;
    if token.claims().exp.lt(&Utc::now()) {
        return Err(ErrorUnauthorized("Expired JWT"));
    }
    let jwt_hash = {
        let mut s = DefaultHasher::new();
        credentials.token().hash(&mut s);
        s.finish()
    };
    if state.jwt_blacklist.contains(&jwt_hash) {
        return Err(ErrorUnauthorized("JWT was logged out"));
    }
    let groups = &token.claims().groups;
    if groups.contains("lldap_admin") {
        debug!("Got authorized token for user {}", &token.claims().user);
        Ok(req)
    } else {
        Err(ErrorUnauthorized(
            "JWT error: User is not in group lldap_admin",
        ))
    }
}

fn http_config<Backend>(
    cfg: &mut web::ServiceConfig,
    backend_handler: Backend,
    jwt_secret: String,
    jwt_blacklist: HashSet<u64>,
) where
    Backend: TcpBackendHandler + 'static,
{
    cfg.data(AppState::<Backend> {
        backend_handler,
        jwt_key: Hmac::new_varkey(&jwt_secret.as_bytes()).unwrap(),
        jwt_blacklist,
    })
    // Serve index.html and main.js, and default to index.html.
    .route(
        "/{filename:(index\\.html|main\\.js)?}",
        web::get().to(index),
    )
    .service(web::resource("/api/authorize").route(web::post().to(post_authorize::<Backend>)))
    .service(web::resource("/api/authorize/refresh").route(web::get().to(get_refresh::<Backend>)))
    // API endpoint.
    .service(
        web::scope("/api")
            .wrap(HttpAuthentication::bearer(token_validator::<Backend>))
            .wrap_fn(|mut req, srv| {
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
                Box::pin(srv.call(req))
            })
            .configure(api_config::<Backend>),
    )
    // Serve the /pkg path with the compiled WASM app.
    .service(Files::new("/pkg", "./app/pkg"))
    // Default to serve index.html for unknown routes, to support routing.
    .service(web::scope("/").route("/.*", web::get().to(index)));
}

struct AppState<Backend>
where
    Backend: TcpBackendHandler + 'static,
{
    pub backend_handler: Backend,
    pub jwt_key: Hmac<Sha512>,
    pub jwt_blacklist: HashSet<u64>,
}

pub async fn build_tcp_server<Backend>(
    config: &Configuration,
    backend_handler: Backend,
    server_builder: ServerBuilder,
) -> Result<ServerBuilder>
where
    Backend: TcpBackendHandler + 'static,
{
    let jwt_secret = config.jwt_secret.clone();
    let jwt_blacklist = backend_handler.get_jwt_blacklist().await?;
    server_builder
        .bind("http", ("0.0.0.0", config.http_port), move || {
            let backend_handler = backend_handler.clone();
            let jwt_secret = jwt_secret.clone();
            let jwt_blacklist = jwt_blacklist.clone();
            HttpServiceBuilder::new()
                .finish(map_config(
                    App::new().configure(move |cfg| {
                        http_config(cfg, backend_handler, jwt_secret, jwt_blacklist)
                    }),
                    |_| AppConfig::default(),
                ))
                .tcp()
        })
        .with_context(|| {
            format!(
                "While bringing up the TCP server with port {}",
                config.http_port
            )
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use actix_web::test::TestRequest;
    use std::path::Path;

    fn get_data(handler: MockTestBackendHandler) -> web::Data<AppState<MockTestBackendHandler>> {
        let app_state = AppState::<MockTestBackendHandler> {
            backend_handler: handler,
            jwt_key: Hmac::new_varkey(b"jwt_secret").unwrap(),
        };
        web::Data::<AppState<MockTestBackendHandler>>::new(app_state)
    }

    fn expect_json<T: std::fmt::Debug>(result: ApiResult<T>) -> T {
        if let ApiResult::Left(res) = result {
            res.0
        } else {
            panic!("Expected Json result, got: {:?}", result);
        }
    }

    #[actix_rt::test]
    async fn test_index_ok() {
        let req = TestRequest::default().to_http_request();
        let resp = index(req).await.unwrap();
        assert_eq!(resp.path(), Path::new("app/index.html"));
    }

    #[actix_rt::test]
    async fn test_index_main_js() {
        let req = TestRequest::default()
            .param("filename", "main.js")
            .to_http_request();
        let resp = index(req).await.unwrap();
        assert_eq!(resp.path(), Path::new("app/main.js"));
    }

    #[actix_rt::test]
    async fn test_user_list_ok() {
        let mut backend_handler = MockTestBackendHandler::new();
        backend_handler
            .expect_list_users()
            .times(1)
            .return_once(|_| {
                Ok(vec![User {
                    user_id: "bob".to_string(),
                    ..Default::default()
                }])
            });
        let json = web::Json(ListUsersRequest { filters: None });
        let resp = user_list_handler(get_data(backend_handler), json).await;
        assert_eq!(
            expect_json(resp),
            vec![User {
                user_id: "bob".to_string(),
                ..Default::default()
            }]
        );
    }
}
