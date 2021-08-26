use crate::{
    domain::{error::DomainError, handler::*},
    infra::{
        auth_service,
        tcp_backend_handler::*,
        tcp_server::{error_to_http_response, AppState},
    },
};
use actix_web::{web, HttpRequest, HttpResponse};
use actix_web_httpauth::middleware::HttpAuthentication;

pub(crate) fn error_to_api_response<T>(error: DomainError) -> ApiResult<T> {
    ApiResult::Right(error_to_http_response(error))
}

pub type ApiResult<M> = actix_web::Either<web::Json<M>, HttpResponse>;

async fn user_list_handler<Backend>(
    data: web::Data<AppState<Backend>>,
    info: web::Json<ListUsersRequest>,
) -> ApiResult<Vec<User>>
where
    Backend: TcpBackendHandler + BackendHandler + 'static,
{
    data.backend_handler
        .list_users(info.into_inner())
        .await
        .map(|res| ApiResult::Left(web::Json(res)))
        .unwrap_or_else(error_to_api_response)
}

async fn user_details_handler<Backend>(
    data: web::Data<AppState<Backend>>,
    request: HttpRequest,
) -> ApiResult<User>
where
    Backend: TcpBackendHandler + BackendHandler + 'static,
{
    let request = UserDetailsRequest {
        user_id: request.match_info().get("user_id").unwrap().to_string(),
    };
    data.backend_handler
        .get_user_details(request)
        .await
        .map(|res| ApiResult::Left(web::Json(res)))
        .unwrap_or_else(error_to_api_response)
}

async fn create_user_handler<Backend>(
    data: web::Data<AppState<Backend>>,
    info: web::Json<CreateUserRequest>,
) -> ApiResult<()>
where
    Backend: TcpBackendHandler + BackendHandler + 'static,
{
    data.backend_handler
        .create_user(info.into_inner())
        .await
        .map(|res| ApiResult::Left(web::Json(res)))
        .unwrap_or_else(error_to_api_response)
}

pub fn api_config<Backend>(cfg: &mut web::ServiceConfig)
where
    Backend: TcpBackendHandler + BackendHandler + Sync + 'static,
{
    let json_config = web::JsonConfig::default()
        .limit(4096)
        .error_handler(|err, _req| {
            // create custom error response
            log::error!("API error: {}", err);
            let msg = err.to_string();
            actix_web::error::InternalError::from_response(
                err,
                HttpResponse::BadRequest().body(msg),
            )
            .into()
        });
    cfg.app_data(json_config);
    super::graphql::api::configure_endpoint::<Backend>(cfg);
    cfg.service(
        web::resource("/user/{user_id}")
            .route(web::get().to(user_details_handler::<Backend>))
            .wrap(HttpAuthentication::bearer(
                auth_service::user_token_validator::<Backend>,
            )),
    );
    cfg.service(
        web::scope("/users")
            .wrap(HttpAuthentication::bearer(
                auth_service::admin_token_validator::<Backend>,
            ))
            .guard(actix_web::guard::Header("content-type", "application/json"))
            .service(web::resource("").route(web::post().to(user_list_handler::<Backend>)))
            .service(
                web::resource("/create").route(web::post().to(create_user_handler::<Backend>)),
            ),
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use hmac::{Hmac, NewMac};
    use std::collections::HashSet;
    use std::sync::RwLock;

    fn get_data(
        handler: MockTestTcpBackendHandler,
    ) -> web::Data<AppState<MockTestTcpBackendHandler>> {
        let app_state = AppState::<MockTestTcpBackendHandler> {
            backend_handler: handler,
            jwt_key: Hmac::new_varkey(b"jwt_secret").unwrap(),
            jwt_blacklist: RwLock::new(HashSet::new()),
        };
        web::Data::<AppState<MockTestTcpBackendHandler>>::new(app_state)
    }

    fn expect_json<T: std::fmt::Debug>(result: ApiResult<T>) -> T {
        if let ApiResult::Left(res) = result {
            res.0
        } else {
            panic!("Expected Json result, got: {:?}", result);
        }
    }

    #[actix_rt::test]
    async fn test_user_list_ok() {
        let mut backend_handler = MockTestTcpBackendHandler::new();
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
