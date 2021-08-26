use crate::{
    domain::handler::BackendHandler,
    infra::{
        auth_service::{check_if_token_is_valid, ValidationResults},
        tcp_server::AppState,
    },
};
use actix_web::{web, Error, HttpResponse};
use actix_web_httpauth::extractors::bearer::BearerAuth;
use juniper::{EmptyMutation, EmptySubscription, RootNode};
use juniper_actix::{graphiql_handler, graphql_handler, playground_handler};

use super::query::Query;

pub struct Context<Handler: BackendHandler> {
    pub handler: Box<Handler>,
    pub validation_result: ValidationResults,
}

impl<Handler: BackendHandler> juniper::Context for Context<Handler> {}

type Schema<Handler> = RootNode<
    'static,
    Query<Handler>,
    EmptyMutation<Context<Handler>>,
    EmptySubscription<Context<Handler>>,
>;

fn schema<Handler: BackendHandler + Sync>() -> Schema<Handler> {
    Schema::new(
        Query::<Handler>::new(),
        EmptyMutation::<Context<Handler>>::new(),
        EmptySubscription::<Context<Handler>>::new(),
    )
}

async fn graphiql_route() -> Result<HttpResponse, Error> {
    graphiql_handler("/api/graphql", None).await
}
async fn playground_route() -> Result<HttpResponse, Error> {
    playground_handler("/api/graphql", None).await
}

async fn graphql_route<Handler: BackendHandler + Sync>(
    req: actix_web::HttpRequest,
    mut payload: actix_web::web::Payload,
    data: web::Data<AppState<Handler>>,
) -> Result<HttpResponse, Error> {
    use actix_web::FromRequest;
    let bearer = BearerAuth::from_request(&req, &mut payload.0).await?;
    let validation_result = check_if_token_is_valid(&data, bearer.token())?;
    let context = Context::<Handler> {
        handler: Box::new(data.backend_handler.clone()),
        validation_result,
    };
    graphql_handler(&schema(), &context, req, payload).await
}

pub fn configure_endpoint<Backend>(cfg: &mut web::ServiceConfig)
where
    Backend: BackendHandler + Sync + 'static,
{
    cfg.service(
        web::resource("/graphql")
            .route(web::post().to(graphql_route::<Backend>))
            .route(web::get().to(graphql_route::<Backend>)),
    );
    cfg.service(web::resource("/graphql/playground").route(web::get().to(playground_route)));
    cfg.service(web::resource("/graphql/graphiql").route(web::get().to(graphiql_route)));
}
