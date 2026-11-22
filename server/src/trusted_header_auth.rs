//! Trusted-header SSO middleware (issue #352).
//!
//! When `trusted_auth_header` is configured (e.g. `X-Forwarded-User` or
//! `Remote-User`, set by a reverse proxy such as Authelia/Traefik
//! forward-auth after its own 2FA check), requests to the API that carry the
//! header are authenticated as the named user without a password login. The
//! middleware validates that the user exists, then injects a fresh
//! short-lived `Authorization: Bearer <jwt>` header so all downstream
//! handlers work unchanged. Requests that already carry an `Authorization`
//! header (real login session) are left untouched, so an explicit session
//! always wins over the trusted header.

use std::collections::HashSet;
use std::future::{Ready, ready};
use std::marker::PhantomData;
use std::pin::Pin;
use std::rc::Rc;
use std::task::{Context, Poll};

use actix_http::header::{AUTHORIZATION, HeaderName, HeaderValue};
use actix_web::dev::{Service, ServiceRequest, ServiceResponse, Transform};
use actix_web::{Error, web};
use lldap_access_control::UserReadableBackendHandler;
use lldap_domain::types::{GroupDetails, UserId};
use lldap_domain_handlers::handler::BackendHandler;

use crate::auth_service::mint_jwt;
use crate::tcp_server::AppState;

pub struct TrustedHeaderAuthFactory<Backend> {
    header_name: Option<HeaderName>,
    _backend: PhantomData<Backend>,
}

impl<Backend> TrustedHeaderAuthFactory<Backend> {
    pub fn new(header_name: &str) -> actix_web::Result<Self> {
        Ok(Self {
            header_name: Some(
                HeaderName::from_bytes(header_name.as_bytes()).map_err(|_| {
                    actix_web::error::ErrorBadRequest("invalid trusted header name")
                })?,
            ),
            _backend: PhantomData,
        })
    }

    /// A factory for when no trusted header is configured: the middleware is
    /// a pass-through.
    pub fn disabled() -> Self {
        Self {
            header_name: None,
            _backend: PhantomData,
        }
    }
}

impl<S, Backend> Transform<S, ServiceRequest> for TrustedHeaderAuthFactory<Backend>
where
    S: Service<ServiceRequest, Response = ServiceResponse, Error = Error> + 'static,
    S::Future: 'static,
    Backend: BackendHandler + 'static,
{
    type Response = ServiceResponse;
    type Error = Error;
    type InitError = ();
    type Transform = TrustedHeaderAuth<S, Backend>;
    type Future = Ready<Result<Self::Transform, Self::InitError>>;

    fn new_transform(&self, service: S) -> Self::Future {
        ready(Ok(TrustedHeaderAuth {
            service: Rc::new(service),
            header_name: self.header_name.clone(),
            _backend: PhantomData,
        }))
    }
}

pub struct TrustedHeaderAuth<S, Backend> {
    service: Rc<S>,
    header_name: Option<HeaderName>,
    _backend: PhantomData<Backend>,
}

impl<S, Backend> Service<ServiceRequest> for TrustedHeaderAuth<S, Backend>
where
    S: Service<ServiceRequest, Response = ServiceResponse, Error = Error> + 'static,
    S::Future: 'static,
    Backend: BackendHandler + 'static,
{
    type Response = ServiceResponse;
    type Error = Error;
    #[allow(clippy::type_complexity)]
    type Future = Pin<Box<dyn core::future::Future<Output = Result<Self::Response, Self::Error>>>>;

    fn poll_ready(&self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.service.poll_ready(cx)
    }

    fn call(&self, mut req: ServiceRequest) -> Self::Future {
        // An explicit Authorization header (from a real login) wins.
        if req.headers().contains_key(AUTHORIZATION) {
            return Box::pin(self.service.call(req));
        }
        let Some(header_name) = &self.header_name else {
            return Box::pin(self.service.call(req));
        };
        let Some(header_value) = req
            .headers()
            .get(header_name)
            .and_then(|v| v.to_str().ok())
            .map(str::trim)
            .filter(|v| !v.is_empty())
        else {
            return Box::pin(self.service.call(req));
        };
        let Some(state) = req.app_data::<web::Data<AppState<Backend>>>().cloned() else {
            return Box::pin(self.service.call(req));
        };
        let user_id = UserId::new(header_value);
        let service = self.service.clone();
        Box::pin(async move {
            let readonly = state.get_readonly_handler();
            // Only authenticate users that actually exist.
            if readonly.get_user_details(&user_id).await.is_err() {
                return service.call(req).await;
            }
            let groups: HashSet<GroupDetails> =
                readonly.get_user_groups(&user_id).await.unwrap_or_default();
            let token = mint_jwt(&state.jwt_key, &user_id, groups).await;
            if let Ok(value) = HeaderValue::from_str(&format!("Bearer {}", token.as_str())) {
                req.headers_mut().insert(AUTHORIZATION, value);
            }
            service.call(req).await
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth_service::{CookieToHeaderTranslatorFactory, check_if_token_is_valid};
    use crate::configuration::MailOptionsBuilder;
    use crate::tcp_server::AppState;
    use actix_web::{App, HttpRequest, HttpResponse, test};
    use lldap_access_control::AccessControlledBackendHandler;
    use lldap_domain::types::User;
    use lldap_domain_model::error::DomainError;
    use lldap_test_utils::MockTestBackendHandler;
    use std::sync::RwLock;

    fn make_state(mock: MockTestBackendHandler) -> web::Data<AppState<MockTestBackendHandler>> {
        web::Data::new(AppState {
            backend_handler: AccessControlledBackendHandler::new(mock),
            jwt_key: hmac::Mac::new_from_slice(b"test-secret").unwrap(),
            jwt_blacklist: RwLock::new(HashSet::new()),
            server_url: url::Url::parse("http://localhost").unwrap(),
            assets_path: std::path::PathBuf::from("./app"),
            mail_options: MailOptionsBuilder::default().build().unwrap(),
        })
    }

    async fn whoami(
        req: HttpRequest,
        state: web::Data<AppState<MockTestBackendHandler>>,
    ) -> HttpResponse {
        let Some(auth) = req
            .headers()
            .get(AUTHORIZATION)
            .and_then(|v| v.to_str().ok())
        else {
            return HttpResponse::Unauthorized().finish();
        };
        let token = auth.strip_prefix("Bearer ").unwrap_or(auth);
        match check_if_token_is_valid(&state, token) {
            Ok(results) => HttpResponse::Ok().body(results.user.to_string()),
            Err(e) => e.into(),
        }
    }

    fn mock_backend() -> MockTestBackendHandler {
        let mut mock = MockTestBackendHandler::new();
        mock.expect_get_user_details().returning(|user_id| {
            if user_id.as_str() == "admin" {
                Ok(User::default())
            } else {
                Err(DomainError::AuthenticationError("no such user".into()))
            }
        });
        mock.expect_get_user_groups()
            .returning(|_| Ok(HashSet::new()));
        mock
    }

    async fn build_app(
        header: Option<&str>,
    ) -> impl Service<actix_http::Request, Response = ServiceResponse, Error = Error> {
        let factory = match header {
            Some(h) => TrustedHeaderAuthFactory::<MockTestBackendHandler>::new(h).unwrap(),
            None => TrustedHeaderAuthFactory::disabled(),
        };
        test::init_service(
            App::new().app_data(make_state(mock_backend())).service(
                web::scope("/api")
                    .wrap(factory)
                    .wrap(CookieToHeaderTranslatorFactory)
                    .route("/whoami", web::get().to(whoami)),
            ),
        )
        .await
    }

    #[actix_web::test]
    async fn trusted_header_authenticates_existing_user() {
        let app = build_app(Some("x-forwarded-user")).await;
        let req = test::TestRequest::get()
            .uri("/api/whoami")
            .insert_header(("x-forwarded-user", "admin"))
            .to_request();
        let resp = app.call(req).await.unwrap();
        assert_eq!(resp.status(), 200);
        let body = test::read_body(resp).await;
        assert_eq!(body, "admin");
    }

    #[actix_web::test]
    async fn trusted_header_rejects_unknown_user() {
        let app = build_app(Some("x-forwarded-user")).await;
        let req = test::TestRequest::get()
            .uri("/api/whoami")
            .insert_header(("x-forwarded-user", "ghost"))
            .to_request();
        let resp = app.call(req).await.unwrap();
        assert_eq!(resp.status(), 401);
    }

    #[actix_web::test]
    async fn no_trusted_header_means_unauthorized() {
        let app = build_app(Some("x-forwarded-user")).await;
        let req = test::TestRequest::get().uri("/api/whoami").to_request();
        let resp = app.call(req).await.unwrap();
        assert_eq!(resp.status(), 401);
    }

    #[actix_web::test]
    async fn explicit_authorization_header_wins_over_trusted_header() {
        let app = build_app(Some("x-forwarded-user")).await;
        // Mint a valid token for "admin" directly.
        let state = make_state(mock_backend());
        let token = mint_jwt(&state.jwt_key, &UserId::new("admin"), HashSet::new()).await;
        let req = test::TestRequest::get()
            .uri("/api/whoami")
            .insert_header((AUTHORIZATION, format!("Bearer {}", token.as_str())))
            .insert_header(("x-forwarded-user", "ghost")) // would be rejected alone
            .to_request();
        let resp = app.call(req).await.unwrap();
        assert_eq!(resp.status(), 200);
        let body = test::read_body(resp).await;
        assert_eq!(body, "admin");
    }

    #[actix_web::test]
    async fn disabled_factory_is_passthrough() {
        let app = build_app(None).await;
        let req = test::TestRequest::get()
            .uri("/api/whoami")
            .insert_header(("x-forwarded-user", "admin"))
            .to_request();
        let resp = app.call(req).await.unwrap();
        assert_eq!(resp.status(), 401);
    }

    #[actix_web::test]
    async fn empty_trusted_header_value_is_ignored() {
        let app = build_app(Some("x-forwarded-user")).await;
        let req = test::TestRequest::get()
            .uri("/api/whoami")
            .insert_header(("x-forwarded-user", "   "))
            .to_request();
        let resp = app.call(req).await.unwrap();
        assert_eq!(resp.status(), 401);
    }
}
