use crate::domain::handler::{BackendHandler, CreateUserRequest};
use juniper::{graphql_object, FieldResult, GraphQLInputObject};

use super::api::Context;

#[derive(PartialEq, Eq, Debug)]
/// The top-level GraphQL mutation type.
pub struct Mutation<Handler: BackendHandler> {
    _phantom: std::marker::PhantomData<Box<Handler>>,
}

impl<Handler: BackendHandler> Mutation<Handler> {
    pub fn new() -> Self {
        Self {
            _phantom: std::marker::PhantomData,
        }
    }
}

#[derive(PartialEq, Eq, Debug, GraphQLInputObject)]
/// The details required to create a user.
pub struct UserInput {
    id: String,
    email: String,
    display_name: Option<String>,
    first_name: Option<String>,
    last_name: Option<String>,
}

#[graphql_object(context = Context<Handler>)]
impl<Handler: BackendHandler + Sync> Mutation<Handler> {
    async fn create_user(
        context: &Context<Handler>,
        user: UserInput,
    ) -> FieldResult<super::query::User<Handler>> {
        if !context.validation_result.is_admin {
            return Err("Unauthorized user creation".into());
        }
        context
            .handler
            .create_user(CreateUserRequest {
                user_id: user.id.clone(),
                email: user.email,
                display_name: user.display_name,
                first_name: user.first_name,
                last_name: user.last_name,
            })
            .await?;
        Ok(context
            .handler
            .get_user_details(&user.id)
            .await
            .map(Into::into)?)
    }
}
