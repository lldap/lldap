use crate::{
    domain::{handler::BackendHandler, types::UserId},
    infra::{
        access_control::{
            AccessControlledBackendHandler, AdminBackendHandler, ReadonlyBackendHandler,
            UserReadableBackendHandler, UserWriteableBackendHandler, ValidationResults,
        },
        auth_service::check_if_token_is_valid,
        cli::ExportGraphQLSchemaOpts,
        graphql::{mutation::Mutation, query::Query},
        tcp_server::AppState,
    },
};
use actix_web::{web, Error, HttpResponse};
use actix_web_httpauth::extractors::bearer::BearerAuth;
use juniper::{EmptySubscription, FieldError, RootNode};
use juniper_actix::{graphiql_handler, graphql_handler, playground_handler};
use tracing::debug;

pub struct Context<Handler: BackendHandler> {
    pub handler: AccessControlledBackendHandler<Handler>,
    pub validation_result: ValidationResults,
}

pub fn field_error_callback<'a>(
    span: &'a tracing::Span,
    error_message: &'a str,
) -> impl 'a + FnOnce() -> FieldError {
    move || {
        span.in_scope(|| debug!("Unauthorized"));
        FieldError::from(error_message)
    }
}

impl<Handler: BackendHandler> Context<Handler> {
    #[cfg(test)]
    pub fn new_for_tests(handler: Handler, validation_result: ValidationResults) -> Self {
        Self {
            handler: AccessControlledBackendHandler::new(handler),
            validation_result,
        }
    }

    pub fn get_admin_handler(&self) -> Option<&impl AdminBackendHandler> {
        self.handler.get_admin_handler(&self.validation_result)
    }

    pub fn get_readonly_handler(&self) -> Option<&impl ReadonlyBackendHandler> {
        self.handler.get_readonly_handler(&self.validation_result)
    }

    pub fn get_writeable_handler(
        &self,
        user_id: &UserId,
    ) -> Option<&impl UserWriteableBackendHandler> {
        self.handler
            .get_writeable_handler(&self.validation_result, user_id)
    }

    pub fn get_readable_handler(
        &self,
        user_id: &UserId,
    ) -> Option<&impl UserReadableBackendHandler> {
        self.handler
            .get_readable_handler(&self.validation_result, user_id)
    }
}

impl<Handler: BackendHandler> juniper::Context for Context<Handler> {}

type Schema<Handler> =
    RootNode<'static, Query<Handler>, Mutation<Handler>, EmptySubscription<Context<Handler>>>;

fn schema<Handler: BackendHandler>() -> Schema<Handler> {
    Schema::new(
        Query::<Handler>::new(),
        Mutation::<Handler>::new(),
        EmptySubscription::<Context<Handler>>::new(),
    )
}

pub fn export_schema(opts: ExportGraphQLSchemaOpts) -> anyhow::Result<()> {
    use crate::domain::sql_backend_handler::SqlBackendHandler;
    use anyhow::Context;
    let output = schema::<SqlBackendHandler>().as_schema_language();
    match opts.output_file {
        None => println!("{}", output),
        Some(path) => {
            use std::fs::File;
            use std::io::prelude::*;
            use std::path::Path;
            let path = Path::new(&path);
            let mut file =
                File::create(path).context(format!("unable to open '{}'", path.display()))?;
            file.write_all(output.as_bytes())
                .context(format!("unable to write in '{}'", path.display()))?;
        }
    }
    Ok(())
}

async fn graphiql_route() -> Result<HttpResponse, Error> {
    graphiql_handler("/api/graphql", None).await
}
async fn playground_route() -> Result<HttpResponse, Error> {
    playground_handler("/api/graphql", None).await
}

async fn graphql_route<Handler: BackendHandler + Clone>(
    req: actix_web::HttpRequest,
    mut payload: actix_web::web::Payload,
    data: web::Data<AppState<Handler>>,
) -> Result<HttpResponse, Error> {
    use actix_web::FromRequest;
    let bearer = BearerAuth::from_request(&req, &mut payload.0).await?;
    let validation_result = check_if_token_is_valid(&data, bearer.token())?;
    let context = Context::<Handler> {
        handler: data.backend_handler.clone(),
        validation_result,
    };
    graphql_handler(&schema(), &context, req, payload).await
}

pub fn configure_endpoint<Backend>(cfg: &mut web::ServiceConfig)
where
    Backend: BackendHandler + Clone + 'static,
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
    cfg.app_data(web::PayloadConfig::new(1 << 24)); // Max payload size: 16MB, allows for a 12MB image.
    cfg.service(
        web::resource("/graphql")
            .route(web::post().to(graphql_route::<Backend>))
            .route(web::get().to(graphql_route::<Backend>)),
    );
    cfg.service(web::resource("/graphql/playground").route(web::get().to(playground_route)));
    cfg.service(web::resource("/graphql/graphiql").route(web::get().to(graphiql_route)));
}
