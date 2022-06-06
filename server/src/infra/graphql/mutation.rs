use crate::domain::handler::{
    BackendHandler, CreateUserRequest, GroupId, UpdateGroupRequest, UpdateUserRequest, UserId,
};
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

#[derive(PartialEq, Eq, Debug, GraphQLInputObject)]
/// The fields that can be updated for a group.
pub struct UpdateGroupInput {
    id: i32,
    display_name: Option<String>,
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
        if !context.validation_result.is_admin() {
            return Err("Unauthorized user creation".into());
        }
        let user_id = UserId::new(&user.id);
        context
            .handler
            .create_user(CreateUserRequest {
                user_id: user_id.clone(),
                email: user.email,
                display_name: user.display_name,
                first_name: user.first_name,
                last_name: user.last_name,
            })
            .await?;
        Ok(context
            .handler
            .get_user_details(&user_id)
            .await
            .map(Into::into)?)
    }

    async fn create_group(
        context: &Context<Handler>,
        name: String,
    ) -> FieldResult<super::query::Group<Handler>> {
        if !context.validation_result.is_admin() {
            return Err("Unauthorized group creation".into());
        }
        let group_id = context.handler.create_group(&name).await?;
        Ok(context
            .handler
            .get_group_details(group_id)
            .await
            .map(Into::into)?)
    }

    async fn update_user(
        context: &Context<Handler>,
        user: UpdateUserInput,
    ) -> FieldResult<Success> {
        if !context.validation_result.can_write(&user.id) {
            return Err("Unauthorized user update".into());
        }
        context
            .handler
            .update_user(UpdateUserRequest {
                user_id: UserId::new(&user.id),
                email: user.email,
                display_name: user.display_name,
                first_name: user.first_name,
                last_name: user.last_name,
            })
            .await?;
        Ok(Success::new())
    }

    async fn update_group(
        context: &Context<Handler>,
        group: UpdateGroupInput,
    ) -> FieldResult<Success> {
        if !context.validation_result.is_admin() {
            return Err("Unauthorized group update".into());
        }
        if group.id == 1 {
            return Err("Cannot change admin group details".into());
        }
        context
            .handler
            .update_group(UpdateGroupRequest {
                group_id: GroupId(group.id),
                display_name: group.display_name,
            })
            .await?;
        Ok(Success::new())
    }

    async fn add_user_to_group(
        context: &Context<Handler>,
        user_id: String,
        group_id: i32,
    ) -> FieldResult<Success> {
        if !context.validation_result.is_admin() {
            return Err("Unauthorized group membership modification".into());
        }
        context
            .handler
            .add_user_to_group(&UserId::new(&user_id), GroupId(group_id))
            .await?;
        Ok(Success::new())
    }

    async fn remove_user_from_group(
        context: &Context<Handler>,
        user_id: String,
        group_id: i32,
    ) -> FieldResult<Success> {
        if !context.validation_result.is_admin() {
            return Err("Unauthorized group membership modification".into());
        }
        if context.validation_result.user == user_id && group_id == 1 {
            return Err("Cannot remove admin rights for current user".into());
        }
        context
            .handler
            .remove_user_from_group(&UserId::new(&user_id), GroupId(group_id))
            .await?;
        Ok(Success::new())
    }

    async fn delete_user(context: &Context<Handler>, user_id: String) -> FieldResult<Success> {
        if !context.validation_result.is_admin() {
            return Err("Unauthorized user deletion".into());
        }
        if context.validation_result.user == user_id {
            return Err("Cannot delete current user".into());
        }
        context.handler.delete_user(&UserId::new(&user_id)).await?;
        Ok(Success::new())
    }

    async fn delete_group(context: &Context<Handler>, group_id: i32) -> FieldResult<Success> {
        if !context.validation_result.is_admin() {
            return Err("Unauthorized group deletion".into());
        }
        if group_id == 1 {
            return Err("Cannot delete admin group".into());
        }
        context.handler.delete_group(GroupId(group_id)).await?;
        Ok(Success::new())
    }
}
