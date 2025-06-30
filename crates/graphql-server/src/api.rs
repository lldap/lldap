use crate::{mutation::Mutation, query::Query};
use juniper::{EmptySubscription, FieldError, RootNode};
use lldap_access_control::{
    AccessControlledBackendHandler, AdminBackendHandler, ReadonlyBackendHandler,
    UserReadableBackendHandler, UserWriteableBackendHandler,
};
use lldap_auth::{access_control::ValidationResults, types::UserId};
use lldap_domain_handlers::handler::BackendHandler;
use std::collections::HashSet;
use std::sync::{Arc, RwLock};
use tracing::debug;

pub struct Context<Handler: BackendHandler> {
    pub handler: AccessControlledBackendHandler<Handler>,
    pub validation_result: ValidationResults,
    pub jwt_blacklist: Option<Arc<RwLock<HashSet<u64>>>>,
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
            jwt_blacklist: None,
        }
    }

    pub fn get_admin_handler(&self) -> Option<&(impl AdminBackendHandler + use<Handler>)> {
        self.handler.get_admin_handler(&self.validation_result)
    }

    pub fn get_readonly_handler(&self) -> Option<&(impl ReadonlyBackendHandler + use<Handler>)> {
        self.handler.get_readonly_handler(&self.validation_result)
    }

    pub fn get_writeable_handler(
        &self,
        user_id: &UserId,
    ) -> Option<&(impl UserWriteableBackendHandler + use<Handler>)> {
        self.handler
            .get_writeable_handler(&self.validation_result, user_id)
    }

    pub fn get_login_enabled_writeable_handler(
        &self,
        user_id: &UserId,
    ) -> Option<&(impl UserWriteableBackendHandler + use<Handler>)> {
        self.handler
            .get_login_enabled_writeable_handler(&self.validation_result, user_id)
    }

    pub fn get_readable_handler(
        &self,
        user_id: &UserId,
    ) -> Option<&(impl UserReadableBackendHandler + use<Handler>)> {
        self.handler
            .get_readable_handler(&self.validation_result, user_id)
    }
}

impl<Handler: BackendHandler> juniper::Context for Context<Handler> {}

type Schema<Handler> =
    RootNode<'static, Query<Handler>, Mutation<Handler>, EmptySubscription<Context<Handler>>>;

pub fn schema<Handler: BackendHandler>() -> Schema<Handler> {
    Schema::new(
        Query::<Handler>::new(),
        Mutation::<Handler>::new(),
        EmptySubscription::<Context<Handler>>::new(),
    )
}

pub fn export_schema(output_file: Option<String>) -> anyhow::Result<()> {
    use anyhow::Context;
    use lldap_sql_backend_handler::SqlBackendHandler;
    let output = schema::<SqlBackendHandler>().as_schema_language();
    match output_file {
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
