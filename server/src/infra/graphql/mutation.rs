use crate::{
    domain::{
        handler::{
            AttributeList, BackendHandler, CreateAttributeRequest, CreateGroupRequest,
            CreateUserRequest, UpdateGroupRequest, UpdateUserRequest,
        },
        types::{
            AttributeType, AttributeValue as DomainAttributeValue, GroupId, JpegPhoto, Serialized,
            UserId,
        },
    },
    infra::{
        access_control::{
            AdminBackendHandler, ReadonlyBackendHandler, UserReadableBackendHandler,
            UserWriteableBackendHandler,
        },
        graphql::api::{field_error_callback, Context},
    },
};
use anyhow::{anyhow, Context as AnyhowContext};
use base64::Engine;
use juniper::{graphql_object, FieldResult, GraphQLInputObject, GraphQLObject};
use tracing::{debug, debug_span, Instrument, Span};

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
// This conflicts with the attribute values returned by the user/group queries.
#[graphql(name = "AttributeValueInput")]
struct AttributeValue {
    /// The name of the attribute. It must be present in the schema, and the type informs how
    /// to interpret the values.
    name: String,
    /// The values of the attribute.
    /// If the attribute is not a list, the vector must contain exactly one element.
    /// Integers (signed 64 bits) are represented as strings.
    /// Dates are represented as strings in RFC3339 format, e.g. "2019-10-12T07:20:50.52Z".
    /// JpegPhotos are represented as base64 encoded strings. They must be valid JPEGs.
    value: Vec<String>,
}

#[derive(PartialEq, Eq, Debug, GraphQLInputObject)]
/// The details required to create a user.
pub struct CreateUserInput {
    id: String,
    email: String,
    display_name: Option<String>,
    first_name: Option<String>,
    last_name: Option<String>,
    /// Base64 encoded JpegPhoto.
    avatar: Option<String>,
    /// User-defined attributes.
    attributes: Option<Vec<AttributeValue>>,
}

#[derive(PartialEq, Eq, Debug, GraphQLInputObject)]
/// The details required to create a group.
pub struct CreateGroupInput {
    display_name: String,
    /// User-defined attributes.
    attributes: Option<Vec<AttributeValue>>,
}

#[derive(PartialEq, Eq, Debug, GraphQLInputObject)]
/// The fields that can be updated for a user.
pub struct UpdateUserInput {
    id: String,
    email: Option<String>,
    display_name: Option<String>,
    first_name: Option<String>,
    last_name: Option<String>,
    /// Base64 encoded JpegPhoto.
    avatar: Option<String>,
    /// Attribute names to remove.
    /// They are processed before insertions.
    remove_attributes: Option<Vec<String>>,
    /// Inserts or updates the given attributes.
    /// For lists, the entire list must be provided.
    insert_attributes: Option<Vec<AttributeValue>>,
}

#[derive(PartialEq, Eq, Debug, GraphQLInputObject)]
/// The fields that can be updated for a group.
pub struct UpdateGroupInput {
    /// The group ID.
    id: i32,
    /// The new display name.
    display_name: Option<String>,
    /// Attribute names to remove.
    /// They are processed before insertions.
    remove_attributes: Option<Vec<String>>,
    /// Inserts or updates the given attributes.
    /// For lists, the entire list must be provided.
    insert_attributes: Option<Vec<AttributeValue>>,
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
        let schema = handler.get_schema().await?;
        let attributes = user
            .attributes
            .unwrap_or_default()
            .into_iter()
            .map(|attr| deserialize_attribute(&schema.get_schema().user_attributes, attr))
            .collect::<Result<Vec<_>, _>>()?;
        handler
            .create_user(CreateUserRequest {
                user_id: user_id.clone(),
                email: user.email,
                display_name: user.display_name,
                first_name: user.first_name,
                last_name: user.last_name,
                avatar,
                attributes,
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
        create_group_with_details(
            context,
            CreateGroupInput {
                display_name: name,
                attributes: Some(Vec::new()),
            },
            span,
        )
        .await
    }
    async fn create_group_with_details(
        context: &Context<Handler>,
        request: CreateGroupInput,
    ) -> FieldResult<super::query::Group<Handler>> {
        let span = debug_span!("[GraphQL mutation] create_group_with_details");
        span.in_scope(|| {
            debug!(?request);
        });
        create_group_with_details(context, request, span).await
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
        let schema = handler.get_schema().await?;
        let insert_attributes = user
            .insert_attributes
            .unwrap_or_default()
            .into_iter()
            .map(|attr| deserialize_attribute(&schema.get_schema().user_attributes, attr))
            .collect::<Result<Vec<_>, _>>()?;
        handler
            .update_user(UpdateUserRequest {
                user_id,
                email: user.email,
                display_name: user.display_name,
                first_name: user.first_name,
                last_name: user.last_name,
                avatar,
                delete_attributes: user.remove_attributes.unwrap_or_default(),
                insert_attributes,
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
        if group.id == 1 && group.display_name.is_some() {
            span.in_scope(|| debug!("Cannot change lldap_admin group name"));
            return Err("Cannot change lldap_admin group name".into());
        }
        let schema = handler.get_schema().await?;
        let insert_attributes = group
            .insert_attributes
            .unwrap_or_default()
            .into_iter()
            .map(|attr| deserialize_attribute(&schema.get_schema().group_attributes, attr))
            .collect::<Result<Vec<_>, _>>()?;
        handler
            .update_group(UpdateGroupRequest {
                group_id: GroupId(group.id),
                display_name: group.display_name,
                delete_attributes: group.remove_attributes.unwrap_or_default(),
                insert_attributes,
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

async fn create_group_with_details<Handler: BackendHandler>(
    context: &Context<Handler>,
    request: CreateGroupInput,
    span: Span,
) -> FieldResult<super::query::Group<Handler>> {
    let handler = context
        .get_admin_handler()
        .ok_or_else(field_error_callback(&span, "Unauthorized group creation"))?;
    let schema = handler.get_schema().await?;
    let attributes = request
        .attributes
        .unwrap_or_default()
        .into_iter()
        .map(|attr| deserialize_attribute(&schema.get_schema().group_attributes, attr))
        .collect::<Result<Vec<_>, _>>()?;
    let request = CreateGroupRequest {
        display_name: request.display_name,
        attributes,
    };
    let group_id = handler.create_group(request).await?;
    Ok(handler
        .get_group_details(group_id)
        .instrument(span)
        .await
        .map(Into::into)?)
}

fn deserialize_attribute(
    attribute_schema: &AttributeList,
    attribute: AttributeValue,
) -> FieldResult<DomainAttributeValue> {
    let attribute_type = attribute_schema
        .get_attribute_type(&attribute.name)
        .ok_or_else(|| anyhow!("Attribute {} is not defined in the schema", attribute.name))?;
    if !attribute_type.1 && attribute.value.len() != 1 {
        return Err(anyhow!(
            "Attribute {} is not a list, but multiple values were provided",
            attribute.name
        )
        .into());
    }
    let parse_int = |value: &String| -> FieldResult<i64> {
        Ok(value
            .parse::<i64>()
            .with_context(|| format!("Invalid integer value {}", value))?)
    };
    let parse_date = |value: &String| -> FieldResult<chrono::NaiveDateTime> {
        Ok(chrono::DateTime::parse_from_rfc3339(value)
            .with_context(|| format!("Invalid date value {}", value))?
            .naive_utc())
    };
    let parse_photo = |value: &String| -> FieldResult<JpegPhoto> {
        Ok(JpegPhoto::try_from(value.as_str()).context("Provided image is not a valid JPEG")?)
    };
    let deserialized_values = match attribute_type {
        (AttributeType::String, false) => Serialized::from(&attribute.value[0]),
        (AttributeType::String, true) => Serialized::from(&attribute.value),
        (AttributeType::Integer, false) => Serialized::from(&parse_int(&attribute.value[0])?),
        (AttributeType::Integer, true) => Serialized::from(
            &attribute
                .value
                .iter()
                .map(parse_int)
                .collect::<FieldResult<Vec<_>>>()?,
        ),
        (AttributeType::DateTime, false) => Serialized::from(&parse_date(&attribute.value[0])?),
        (AttributeType::DateTime, true) => Serialized::from(
            &attribute
                .value
                .iter()
                .map(parse_date)
                .collect::<FieldResult<Vec<_>>>()?,
        ),
        (AttributeType::JpegPhoto, false) => Serialized::from(&parse_photo(&attribute.value[0])?),
        (AttributeType::JpegPhoto, true) => Serialized::from(
            &attribute
                .value
                .iter()
                .map(parse_photo)
                .collect::<FieldResult<Vec<_>>>()?,
        ),
    };
    Ok(DomainAttributeValue {
        name: attribute.name,
        value: deserialized_values,
    })
}
