use crate::{
    domain::{
        handler::{
            BackendHandler, CreateAttributeRequest, CreateGroupRequest, CreateUserRequest,
            UpdateGroupRequest, UpdateUserRequest,
        },
        types::{AttributeType, GroupId, JpegPhoto, UserId},
    },
    infra::{
        access_control::{
            AdminBackendHandler, ReadonlyBackendHandler, UserReadableBackendHandler,
            UserWriteableBackendHandler,
        },
        graphql::api::{field_error_callback, Context},
    },
};
use anyhow::Context as AnyhowContext;
use base64::Engine;
use juniper::{graphql_object, FieldResult, GraphQLInputObject, GraphQLObject};
use tracing::{debug, debug_span, Instrument};

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
    // Base64 encoded JpegPhoto.
    avatar: Option<String>,
}

#[derive(PartialEq, Eq, Debug, GraphQLInputObject)]
/// The fields that can be updated for a user.
pub struct UpdateUserInput {
    id: String,
    email: Option<String>,
    display_name: Option<String>,
    first_name: Option<String>,
    last_name: Option<String>,
    // Base64 encoded JpegPhoto.
    avatar: Option<String>,
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
impl<Handler: BackendHandler> Mutation<Handler> {
    async fn create_user(
        context: &Context<Handler>,
        user: CreateUserInput,
    ) -> FieldResult<super::query::User<Handler>> {
        let span = debug_span!("[GraphQL mutation] create_user");
        span.in_scope(|| {
            debug!("{:?}", &user.id);
        });
        let handler = context
            .get_admin_handler()
            .ok_or_else(field_error_callback(&span, "Unauthorized user creation"))?;
        let user_id = UserId::new(&user.id);
        let avatar = user
            .avatar
            .map(|bytes| base64::engine::general_purpose::STANDARD.decode(bytes))
            .transpose()
            .context("Invalid base64 image")?
            .map(JpegPhoto::try_from)
            .transpose()
            .context("Provided image is not a valid JPEG")?;
        handler
            .create_user(CreateUserRequest {
                user_id: user_id.clone(),
                email: user.email,
                display_name: user.display_name,
                first_name: user.first_name,
                last_name: user.last_name,
                avatar,
                ..Default::default()
            })
            .instrument(span.clone())
            .await?;
        Ok(handler
            .get_user_details(&user_id)
            .instrument(span)
            .await
            .map(Into::into)?)
    }

    async fn create_group(
        context: &Context<Handler>,
        name: String,
    ) -> FieldResult<super::query::Group<Handler>> {
        let span = debug_span!("[GraphQL mutation] create_group");
        span.in_scope(|| {
            debug!(?name);
        });
        let handler = context
            .get_admin_handler()
            .ok_or_else(field_error_callback(&span, "Unauthorized group creation"))?;
        let request = CreateGroupRequest {
            display_name: name,
            ..Default::default()
        };
        let group_id = handler.create_group(request).await?;
        Ok(handler
            .get_group_details(group_id)
            .instrument(span)
            .await
            .map(Into::into)?)
    }

    async fn update_user(
        context: &Context<Handler>,
        user: UpdateUserInput,
    ) -> FieldResult<Success> {
        let span = debug_span!("[GraphQL mutation] update_user");
        span.in_scope(|| {
            debug!(?user.id);
        });
        let user_id = UserId::new(&user.id);
        let handler = context
            .get_writeable_handler(&user_id)
            .ok_or_else(field_error_callback(&span, "Unauthorized user update"))?;
        let avatar = user
            .avatar
            .map(|bytes| base64::engine::general_purpose::STANDARD.decode(bytes))
            .transpose()
            .context("Invalid base64 image")?
            .map(JpegPhoto::try_from)
            .transpose()
            .context("Provided image is not a valid JPEG")?;
        handler
            .update_user(UpdateUserRequest {
                user_id,
                email: user.email,
                display_name: user.display_name,
                first_name: user.first_name,
                last_name: user.last_name,
                avatar,
                ..Default::default()
            })
            .instrument(span)
            .await?;
        Ok(Success::new())
    }

    async fn update_group(
        context: &Context<Handler>,
        group: UpdateGroupInput,
    ) -> FieldResult<Success> {
        let span = debug_span!("[GraphQL mutation] update_group");
        span.in_scope(|| {
            debug!(?group.id);
        });
        let handler = context
            .get_admin_handler()
            .ok_or_else(field_error_callback(&span, "Unauthorized group update"))?;
        if group.id == 1 {
            span.in_scope(|| debug!("Cannot change admin group details"));
            return Err("Cannot change admin group details".into());
        }
        handler
            .update_group(UpdateGroupRequest {
                group_id: GroupId(group.id),
                display_name: group.display_name,
                delete_attributes: Vec::new(),
                insert_attributes: Vec::new(),
            })
            .instrument(span)
            .await?;
        Ok(Success::new())
    }

    async fn add_user_to_group(
        context: &Context<Handler>,
        user_id: String,
        group_id: i32,
    ) -> FieldResult<Success> {
        let span = debug_span!("[GraphQL mutation] add_user_to_group");
        span.in_scope(|| {
            debug!(?user_id, ?group_id);
        });
        let handler = context
            .get_admin_handler()
            .ok_or_else(field_error_callback(
                &span,
                "Unauthorized group membership modification",
            ))?;
        handler
            .add_user_to_group(&UserId::new(&user_id), GroupId(group_id))
            .instrument(span)
            .await?;
        Ok(Success::new())
    }

    async fn remove_user_from_group(
        context: &Context<Handler>,
        user_id: String,
        group_id: i32,
    ) -> FieldResult<Success> {
        let span = debug_span!("[GraphQL mutation] remove_user_from_group");
        span.in_scope(|| {
            debug!(?user_id, ?group_id);
        });
        let handler = context
            .get_admin_handler()
            .ok_or_else(field_error_callback(
                &span,
                "Unauthorized group membership modification",
            ))?;
        let user_id = UserId::new(&user_id);
        if context.validation_result.user == user_id && group_id == 1 {
            span.in_scope(|| debug!("Cannot remove admin rights for current user"));
            return Err("Cannot remove admin rights for current user".into());
        }
        handler
            .remove_user_from_group(&user_id, GroupId(group_id))
            .instrument(span)
            .await?;
        Ok(Success::new())
    }

    async fn delete_user(context: &Context<Handler>, user_id: String) -> FieldResult<Success> {
        let span = debug_span!("[GraphQL mutation] delete_user");
        span.in_scope(|| {
            debug!(?user_id);
        });
        let user_id = UserId::new(&user_id);
        let handler = context
            .get_admin_handler()
            .ok_or_else(field_error_callback(&span, "Unauthorized user deletion"))?;
        if context.validation_result.user == user_id {
            span.in_scope(|| debug!("Cannot delete current user"));
            return Err("Cannot delete current user".into());
        }
        handler.delete_user(&user_id).instrument(span).await?;
        Ok(Success::new())
    }

    async fn delete_group(context: &Context<Handler>, group_id: i32) -> FieldResult<Success> {
        let span = debug_span!("[GraphQL mutation] delete_group");
        span.in_scope(|| {
            debug!(?group_id);
        });
        let handler = context
            .get_admin_handler()
            .ok_or_else(field_error_callback(&span, "Unauthorized group deletion"))?;
        if group_id == 1 {
            span.in_scope(|| debug!("Cannot delete admin group"));
            return Err("Cannot delete admin group".into());
        }
        handler
            .delete_group(GroupId(group_id))
            .instrument(span)
            .await?;
        Ok(Success::new())
    }

    async fn add_user_attribute(
        context: &Context<Handler>,
        name: String,
        attribute_type: AttributeType,
        is_list: bool,
        is_visible: bool,
        is_editable: bool,
    ) -> FieldResult<Success> {
        let span = debug_span!("[GraphQL mutation] add_user_attribute");
        span.in_scope(|| {
            debug!(?name, ?attribute_type, is_list, is_visible, is_editable);
        });
        let handler = context
            .get_admin_handler()
            .ok_or_else(field_error_callback(
                &span,
                "Unauthorized attribute creation",
            ))?;
        handler
            .add_user_attribute(CreateAttributeRequest {
                name,
                attribute_type,
                is_list,
                is_visible,
                is_editable,
            })
            .instrument(span)
            .await?;
        Ok(Success::new())
    }

    async fn add_group_attribute(
        context: &Context<Handler>,
        name: String,
        attribute_type: AttributeType,
        is_list: bool,
        is_visible: bool,
        is_editable: bool,
    ) -> FieldResult<Success> {
        let span = debug_span!("[GraphQL mutation] add_group_attribute");
        span.in_scope(|| {
            debug!(?name, ?attribute_type, is_list, is_visible, is_editable);
        });
        let handler = context
            .get_admin_handler()
            .ok_or_else(field_error_callback(
                &span,
                "Unauthorized attribute creation",
            ))?;
        handler
            .add_group_attribute(CreateAttributeRequest {
                name,
                attribute_type,
                is_list,
                is_visible,
                is_editable,
            })
            .instrument(span)
            .await?;
        Ok(Success::new())
    }

    async fn delete_user_attribute(
        context: &Context<Handler>,
        name: String,
    ) -> FieldResult<Success> {
        let span = debug_span!("[GraphQL mutation] delete_user_attribute");
        span.in_scope(|| {
            debug!(?name);
        });
        let handler = context
            .get_admin_handler()
            .ok_or_else(field_error_callback(
                &span,
                "Unauthorized attribute deletion",
            ))?;
        handler
            .delete_user_attribute(&name)
            .instrument(span)
            .await?;
        Ok(Success::new())
    }

    async fn delete_group_attribute(
        context: &Context<Handler>,
        name: String,
    ) -> FieldResult<Success> {
        let span = debug_span!("[GraphQL mutation] delete_group_attribute");
        span.in_scope(|| {
            debug!(?name);
        });
        let handler = context
            .get_admin_handler()
            .ok_or_else(field_error_callback(
                &span,
                "Unauthorized attribute deletion",
            ))?;
        handler
            .delete_group_attribute(&name)
            .instrument(span)
            .await?;
        Ok(Success::new())
    }
}
