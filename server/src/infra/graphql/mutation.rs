use crate::domain::handler::{BackendHandler, CreateUserRequest, GroupId, UpdateUserRequest};
use juniper::{graphql_object, FieldResult, GraphQLInputObject, GraphQLObject};

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
pub struct CreateUserInput {
    id: String,
    email: String,
    display_name: Option<String>,
    first_name: Option<String>,
    last_name: Option<String>,
}

#[derive(PartialEq, Eq, Debug, GraphQLInputObject)]
/// The fields that can be updated for a user.
pub struct UpdateUserInput {
    id: String,
    email: Option<String>,
    display_name: Option<String>,
    first_name: Option<String>,
    last_name: Option<String>,
}

#[derive(PartialEq, Eq, Debug, GraphQLObject)]
pub struct Success {
    ok: bool,
}

impl Success {
    fn new() -> Self {
        Self { ok: true }
    }
}

#[graphql_object(context = Context<Handler>)]
impl<Handler: BackendHandler + Sync> Mutation<Handler> {
    async fn create_user(
        context: &Context<Handler>,
        user: CreateUserInput,
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

    async fn update_user(
        context: &Context<Handler>,
        user: UpdateUserInput,
    ) -> FieldResult<Success> {
        if !context.validation_result.can_access(&user.id) {
            return Err("Unauthorized user update".into());
        }
        context
            .handler
            .update_user(UpdateUserRequest {
                user_id: user.id,
                email: user.email,
                display_name: user.display_name,
                first_name: user.first_name,
                last_name: user.last_name,
            })
            .await?;
        Ok(Success::new())
    }

    async fn add_user_to_group(
        context: &Context<Handler>,
        user_id: String,
        group_id: i32,
    ) -> FieldResult<Success> {
        if !context.validation_result.is_admin {
            return Err("Unauthorized group membership modification".into());
        }
        context
            .handler
            .add_user_to_group(&user_id, GroupId(group_id))
            .await?;
        Ok(Success::new())
    }

    async fn remove_user_from_group(
        context: &Context<Handler>,
        user_id: String,
        group_id: i32,
    ) -> FieldResult<Success> {
        if !context.validation_result.is_admin {
            return Err("Unauthorized group membership modification".into());
        }
        context
            .handler
            .remove_user_from_group(&user_id, GroupId(group_id))
            .await?;
        Ok(Success::new())
    }
}
