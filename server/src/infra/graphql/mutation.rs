use std::{collections::BTreeMap, sync::Arc};

use crate::{
    domain::{deserialize::deserialize_attribute_value, schema::PublicSchema},
    infra::{
        access_control::{
            AdminBackendHandler, ReadonlyBackendHandler, UserReadableBackendHandler,
            UserWriteableBackendHandler,
        },
        graphql::api::{field_error_callback, Context},
    },
};
use anyhow::{anyhow, Context as AnyhowContext};
use juniper::{graphql_object, FieldError, FieldResult, GraphQLInputObject, GraphQLObject};
use lldap_domain::{
    requests::{
        CreateAttributeRequest, CreateGroupRequest, CreateUserRequest, UpdateGroupRequest,
        UpdateUserRequest,
    },
    schema::AttributeList,
    types::{
        Attribute as DomainAttribute, AttributeName, AttributeType, Email, GroupId,
        LdapObjectClass, UserId,
    },
};
use lldap_domain_handlers::handler::BackendHandler;
use lldap_validation::attributes::{validate_attribute_name, ALLOWED_CHARACTERS_DESCRIPTION};
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

#[derive(Clone, PartialEq, Eq, Debug, GraphQLInputObject)]
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
    // The email can be specified as an attribute, but one of the two is required.
    email: Option<String>,
    display_name: Option<String>,
    /// First name of user. Deprecated: use attribute instead.
    /// If both field and corresponding attribute is supplied, the attribute will take precedence.
    first_name: Option<String>,
    /// Last name of user. Deprecated: use attribute instead.
    /// If both field and corresponding attribute is supplied, the attribute will take precedence.
    last_name: Option<String>,
    /// Base64 encoded JpegPhoto. Deprecated: use attribute instead.
    /// If both field and corresponding attribute is supplied, the attribute will take precedence.
    avatar: Option<String>,
    /// Attributes.
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
    /// First name of user. Deprecated: use attribute instead.
    /// If both field and corresponding attribute is supplied, the attribute will take precedence.
    first_name: Option<String>,
    /// Last name of user. Deprecated: use attribute instead.
    /// If both field and corresponding attribute is supplied, the attribute will take precedence.
    last_name: Option<String>,
    /// Base64 encoded JpegPhoto. Deprecated: use attribute instead.
    /// If both field and corresponding attribute is supplied, the attribute will take precedence.
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

struct UnpackedAttributes {
    email: Option<Email>,
    display_name: Option<String>,
    attributes: Vec<DomainAttribute>,
}

fn unpack_attributes(
    attributes: Vec<AttributeValue>,
    schema: &PublicSchema,
    is_admin: bool,
) -> FieldResult<UnpackedAttributes> {
    let email = attributes
        .iter()
        .find(|attr| attr.name == "mail")
        .cloned()
        .map(|attr| deserialize_attribute(&schema.get_schema().user_attributes, attr, is_admin))
        .transpose()?
        .map(|attr| attr.value.into_string().unwrap())
        .map(Email::from);
    let display_name = attributes
        .iter()
        .find(|attr| attr.name == "display_name")
        .cloned()
        .map(|attr| deserialize_attribute(&schema.get_schema().user_attributes, attr, is_admin))
        .transpose()?
        .map(|attr| attr.value.into_string().unwrap());
    let attributes = attributes
        .into_iter()
        .filter(|attr| attr.name != "mail" && attr.name != "display_name")
        .map(|attr| deserialize_attribute(&schema.get_schema().user_attributes, attr, is_admin))
        .collect::<Result<Vec<_>, _>>()?;
    Ok(UnpackedAttributes {
        email,
        display_name,
        attributes,
    })
}

/// Consolidates caller supplied user fields and attributes into a list of attributes.
///
/// A number of user fields are internally represented as attributes, but are still also
/// available as fields on user objects. This function consolidates these fields and the
/// given attributes into a resulting attribute list. If a value is supplied for both a
/// field and the corresponding attribute, the attribute will take precedence.
fn consolidate_attributes(
    attributes: Vec<AttributeValue>,
    first_name: Option<String>,
    last_name: Option<String>,
    avatar: Option<String>,
) -> Vec<AttributeValue> {
    // Prepare map of the client provided attributes
    let mut provided_attributes: BTreeMap<AttributeName, AttributeValue> = attributes
        .into_iter()
        .map(|x| {
            (
                x.name.clone().into(),
                AttributeValue {
                    name: x.name.to_ascii_lowercase(),
                    value: x.value,
                },
            )
        })
        .collect::<BTreeMap<_, _>>();
    // Prepare list of fallback attribute values
    let field_attrs = [
        ("first_name", first_name),
        ("last_name", last_name),
        ("avatar", avatar),
    ];
    for (name, value) in field_attrs.into_iter() {
        if let Some(val) = value {
            let attr_name: AttributeName = name.into();
            provided_attributes
                .entry(attr_name)
                .or_insert_with(|| AttributeValue {
                    name: name.to_string(),
                    value: vec![val],
                });
        }
    }
    // Return the values of the resulting map
    provided_attributes.into_values().collect()
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
        let schema = handler.get_schema().await?;
        let consolidated_attributes = consolidate_attributes(
            user.attributes.unwrap_or_default(),
            user.first_name,
            user.last_name,
            user.avatar,
        );
        let UnpackedAttributes {
            email,
            display_name,
            attributes,
        } = unpack_attributes(consolidated_attributes, &schema, true)?;
        handler
            .create_user(CreateUserRequest {
                user_id: user_id.clone(),
                email: user
                    .email
                    .map(Email::from)
                    .or(email)
                    .ok_or_else(|| anyhow!("Email is required when creating a new user"))?,
                display_name: user.display_name.or(display_name),
                attributes,
            })
            .instrument(span.clone())
            .await?;
        let user_details = handler.get_user_details(&user_id).instrument(span).await?;
        super::query::User::<Handler>::from_user(user_details, Arc::new(schema))
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
        let is_admin = context.validation_result.is_admin();
        let schema = handler.get_schema().await?;
        // Consolidate attributes and fields into a combined attribute list
        let consolidated_attributes = consolidate_attributes(
            user.insert_attributes.unwrap_or_default(),
            user.first_name,
            user.last_name,
            user.avatar,
        );
        // Extract any empty attributes into a list of attributes for deletion
        let (delete_attrs, insert_attrs): (Vec<_>, Vec<_>) = consolidated_attributes
            .into_iter()
            .partition(|a| a.value == vec!["".to_string()]);
        // Combine lists of attributes for removal
        let mut delete_attributes: Vec<String> =
            delete_attrs.iter().map(|a| a.name.to_owned()).collect();
        delete_attributes.extend(user.remove_attributes.unwrap_or_default());
        // Unpack attributes for update
        let UnpackedAttributes {
            email,
            display_name,
            attributes: insert_attributes,
        } = unpack_attributes(insert_attrs, &schema, is_admin)?;
        let display_name = display_name.or_else(|| {
            // If the display name is not inserted, but removed, reset it.
            delete_attributes
                .iter()
                .find(|attr| *attr == "display_name")
                .map(|_| String::new())
        });
        handler
            .update_user(UpdateUserRequest {
                user_id,
                email: user.email.map(Into::into).or(email),
                display_name: user.display_name.or(display_name),
                delete_attributes: delete_attributes
                    .into_iter()
                    .filter(|attr| attr != "mail" && attr != "display_name")
                    .map(Into::into)
                    .collect(),
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
        let new_display_name = group.display_name.clone().or_else(|| {
            group.insert_attributes.as_ref().and_then(|a| {
                a.iter()
                    .find(|attr| attr.name == "display_name")
                    .map(|attr| attr.value[0].clone())
            })
        });
        if group.id == 1 && new_display_name.is_some() {
            span.in_scope(|| debug!("Cannot change lldap_admin group name"));
            return Err("Cannot change lldap_admin group name".into());
        }
        let schema = handler.get_schema().await?;
        let insert_attributes = group
            .insert_attributes
            .unwrap_or_default()
            .into_iter()
            .filter(|attr| attr.name != "display_name")
            .map(|attr| deserialize_attribute(&schema.get_schema().group_attributes, attr, true))
            .collect::<Result<Vec<_>, _>>()?;
        handler
            .update_group(UpdateGroupRequest {
                group_id: GroupId(group.id),
                display_name: new_display_name.map(|s| s.as_str().into()),
                delete_attributes: group
                    .remove_attributes
                    .unwrap_or_default()
                    .into_iter()
                    .filter(|attr| attr != "display_name")
                    .map(Into::into)
                    .collect(),
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
        validate_attribute_name(&name).map_err(|invalid_chars: Vec<char>| -> FieldError {
            let chars = String::from_iter(invalid_chars);
            span.in_scope(|| {
                debug!(
                    "Cannot create attribute with invalid name. Valid characters: {}. Invalid chars found: {}",
                    ALLOWED_CHARACTERS_DESCRIPTION,
                    chars
                )
            });
            anyhow!(
                "Cannot create attribute with invalid name. Valid characters: {}. Invalid chars found: {}",
                ALLOWED_CHARACTERS_DESCRIPTION,
                chars
            )
            .into()
        })?;
        let handler = context
            .get_admin_handler()
            .ok_or_else(field_error_callback(
                &span,
                "Unauthorized attribute creation",
            ))?;
        handler
            .add_user_attribute(CreateAttributeRequest {
                name: name.into(),
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
        validate_attribute_name(&name).map_err(|invalid_chars: Vec<char>| -> FieldError {
            let chars = String::from_iter(invalid_chars);
            span.in_scope(|| {
                debug!(
                    "Cannot create attribute with invalid name. Invalid chars found: {}",
                    chars
                )
            });
            anyhow!(
                "Cannot create attribute with invalid name. Valid characters: {}",
                ALLOWED_CHARACTERS_DESCRIPTION
            )
            .into()
        })?;
        let handler = context
            .get_admin_handler()
            .ok_or_else(field_error_callback(
                &span,
                "Unauthorized attribute creation",
            ))?;
        handler
            .add_group_attribute(CreateAttributeRequest {
                name: name.into(),
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
        let name = AttributeName::from(name);
        span.in_scope(|| {
            debug!(?name);
        });
        let handler = context
            .get_admin_handler()
            .ok_or_else(field_error_callback(
                &span,
                "Unauthorized attribute deletion",
            ))?;
        let schema = handler.get_schema().await?;
        let attribute_schema = schema
            .get_schema()
            .user_attributes
            .get_attribute_schema(&name)
            .ok_or_else(|| anyhow!("Attribute {} is not defined in the schema", &name))?;
        if attribute_schema.is_hardcoded {
            return Err(anyhow!("Permission denied: Attribute {} cannot be deleted", &name).into());
        }
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
        let name = AttributeName::from(name);
        span.in_scope(|| {
            debug!(?name);
        });
        let handler = context
            .get_admin_handler()
            .ok_or_else(field_error_callback(
                &span,
                "Unauthorized attribute deletion",
            ))?;
        let schema = handler.get_schema().await?;
        let attribute_schema = schema
            .get_schema()
            .group_attributes
            .get_attribute_schema(&name)
            .ok_or_else(|| anyhow!("Attribute {} is not defined in the schema", &name))?;
        if attribute_schema.is_hardcoded {
            return Err(anyhow!("Permission denied: Attribute {} cannot be deleted", &name).into());
        }
        handler
            .delete_group_attribute(&name)
            .instrument(span)
            .await?;
        Ok(Success::new())
    }

    async fn add_user_object_class(
        context: &Context<Handler>,
        name: String,
    ) -> FieldResult<Success> {
        let span = debug_span!("[GraphQL mutation] add_user_object_class");
        span.in_scope(|| {
            debug!(?name);
        });
        let handler = context
            .get_admin_handler()
            .ok_or_else(field_error_callback(
                &span,
                "Unauthorized object class addition",
            ))?;
        handler
            .add_user_object_class(&LdapObjectClass::from(name))
            .instrument(span)
            .await?;
        Ok(Success::new())
    }

    async fn add_group_object_class(
        context: &Context<Handler>,
        name: String,
    ) -> FieldResult<Success> {
        let span = debug_span!("[GraphQL mutation] add_group_object_class");
        span.in_scope(|| {
            debug!(?name);
        });
        let handler = context
            .get_admin_handler()
            .ok_or_else(field_error_callback(
                &span,
                "Unauthorized object class addition",
            ))?;
        handler
            .add_group_object_class(&LdapObjectClass::from(name))
            .instrument(span)
            .await?;
        Ok(Success::new())
    }

    async fn delete_user_object_class(
        context: &Context<Handler>,
        name: String,
    ) -> FieldResult<Success> {
        let span = debug_span!("[GraphQL mutation] delete_user_object_class");
        span.in_scope(|| {
            debug!(?name);
        });
        let handler = context
            .get_admin_handler()
            .ok_or_else(field_error_callback(
                &span,
                "Unauthorized object class deletion",
            ))?;
        handler
            .delete_user_object_class(&LdapObjectClass::from(name))
            .instrument(span)
            .await?;
        Ok(Success::new())
    }

    async fn delete_group_object_class(
        context: &Context<Handler>,
        name: String,
    ) -> FieldResult<Success> {
        let span = debug_span!("[GraphQL mutation] delete_group_object_class");
        span.in_scope(|| {
            debug!(?name);
        });
        let handler = context
            .get_admin_handler()
            .ok_or_else(field_error_callback(
                &span,
                "Unauthorized object class deletion",
            ))?;
        handler
            .delete_group_object_class(&LdapObjectClass::from(name))
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
        .map(|attr| deserialize_attribute(&schema.get_schema().group_attributes, attr, true))
        .collect::<Result<Vec<_>, _>>()?;
    let request = CreateGroupRequest {
        display_name: request.display_name.into(),
        attributes,
    };
    let group_id = handler.create_group(request).await?;
    let group_details = handler.get_group_details(group_id).instrument(span).await?;
    super::query::Group::<Handler>::from_group_details(group_details, Arc::new(schema))
}

fn deserialize_attribute(
    attribute_schema: &AttributeList,
    attribute: AttributeValue,
    is_admin: bool,
) -> FieldResult<DomainAttribute> {
    let attribute_name = AttributeName::from(attribute.name.as_str());
    let attribute_schema = attribute_schema
        .get_attribute_schema(&attribute_name)
        .ok_or_else(|| anyhow!("Attribute {} is not defined in the schema", attribute.name))?;
    if attribute_schema.is_readonly {
        return Err(anyhow!(
            "Permission denied: Attribute {} is read-only",
            attribute.name
        )
        .into());
    }
    if !is_admin && !attribute_schema.is_editable {
        return Err(anyhow!(
            "Permission denied: Attribute {} is not editable by regular users",
            attribute.name
        )
        .into());
    }
    let deserialized_values = deserialize_attribute_value(
        &attribute.value,
        attribute_schema.attribute_type,
        attribute_schema.is_list,
    )
    .context(format!("While deserializing attribute {}", attribute.name))?;
    Ok(DomainAttribute {
        name: attribute_name,
        value: deserialized_values,
    })
}

#[cfg(test)]
mod tests {

    use super::*;
    use crate::infra::{graphql::query::Query, test_utils::MockTestBackendHandler};
    use juniper::{
        execute, graphql_value, DefaultScalarValue, EmptySubscription, GraphQLType, InputValue,
        RootNode, Variables,
    };
    use lldap_auth::access_control::{Permission, ValidationResults};
    use lldap_domain::types::{AttributeName, AttributeType};
    use mockall::predicate::eq;
    use pretty_assertions::assert_eq;

    fn mutation_schema<'q, C, Q, M>(
        query_root: Q,
        mutation_root: M,
    ) -> RootNode<'q, Q, M, EmptySubscription<C>>
    where
        Q: GraphQLType<DefaultScalarValue, Context = C, TypeInfo = ()> + 'q,
        M: GraphQLType<DefaultScalarValue, Context = C, TypeInfo = ()> + 'q,
    {
        RootNode::new(query_root, mutation_root, EmptySubscription::<C>::new())
    }

    #[tokio::test]
    async fn test_create_user_attribute_valid() {
        const QUERY: &str = r#"
            mutation CreateUserAttribute($name: String!, $attributeType: AttributeType!, $isList: Boolean!, $isVisible: Boolean!, $isEditable: Boolean!) {
                addUserAttribute(name: $name, attributeType: $attributeType, isList: $isList, isVisible: $isVisible, isEditable: $isEditable) {
                    ok
                }
            }
        "#;
        let mut mock = MockTestBackendHandler::new();
        mock.expect_add_user_attribute()
            .with(eq(CreateAttributeRequest {
                name: AttributeName::new("AttrName0"),
                attribute_type: AttributeType::String,
                is_list: false,
                is_visible: false,
                is_editable: false,
            }))
            .return_once(|_| Ok(()));
        let context = Context::<MockTestBackendHandler>::new_for_tests(
            mock,
            ValidationResults {
                user: UserId::new("bob"),
                permission: Permission::Admin,
            },
        );
        let vars = Variables::from([
            ("name".to_string(), InputValue::scalar("AttrName0")),
            (
                "attributeType".to_string(),
                InputValue::enum_value("STRING"),
            ),
            ("isList".to_string(), InputValue::scalar(false)),
            ("isVisible".to_string(), InputValue::scalar(false)),
            ("isEditable".to_string(), InputValue::scalar(false)),
        ]);
        let schema = mutation_schema(
            Query::<MockTestBackendHandler>::new(),
            Mutation::<MockTestBackendHandler>::new(),
        );
        assert_eq!(
            execute(QUERY, None, &schema, &vars, &context).await,
            Ok((
                graphql_value!(
                {
                    "addUserAttribute": {
                        "ok": true
                    }
                } ),
                vec![]
            ))
        );
    }

    #[tokio::test]
    async fn test_create_user_attribute_invalid() {
        const QUERY: &str = r#"
            mutation CreateUserAttribute($name: String!, $attributeType: AttributeType!, $isList: Boolean!, $isVisible: Boolean!, $isEditable: Boolean!) {
                addUserAttribute(name: $name, attributeType: $attributeType, isList: $isList, isVisible: $isVisible, isEditable: $isEditable) {
                    ok
                }
            }
        "#;
        let mock = MockTestBackendHandler::new();
        let context = Context::<MockTestBackendHandler>::new_for_tests(
            mock,
            ValidationResults {
                user: UserId::new("bob"),
                permission: Permission::Admin,
            },
        );
        let vars = Variables::from([
            ("name".to_string(), InputValue::scalar("AttrName_0")),
            (
                "attributeType".to_string(),
                InputValue::enum_value("STRING"),
            ),
            ("isList".to_string(), InputValue::scalar(false)),
            ("isVisible".to_string(), InputValue::scalar(false)),
            ("isEditable".to_string(), InputValue::scalar(false)),
        ]);
        let schema = mutation_schema(
            Query::<MockTestBackendHandler>::new(),
            Mutation::<MockTestBackendHandler>::new(),
        );
        let result = execute(QUERY, None, &schema, &vars, &context).await;
        match result {
            Ok(res) => {
                let (response, errors) = res;
                assert!(response.is_null());
                let expected_error_msg =
                    "Cannot create attribute with invalid name. Valid characters: a-z, A-Z, 0-9, and dash (-). Invalid chars found: _"
                        .to_string();
                assert!(errors
                    .iter()
                    .all(|e| e.error().message() == expected_error_msg));
            }
            Err(_) => {
                panic!();
            }
        }
    }

    #[tokio::test]
    async fn test_create_group_attribute_valid() {
        const QUERY: &str = r#"
            mutation CreateGroupAttribute($name: String!, $attributeType: AttributeType!, $isList: Boolean!, $isVisible: Boolean!) {
                addGroupAttribute(name: $name, attributeType: $attributeType, isList: $isList, isVisible: $isVisible, isEditable: false) {
                    ok
                }
            }
        "#;
        let mut mock = MockTestBackendHandler::new();
        mock.expect_add_group_attribute()
            .with(eq(CreateAttributeRequest {
                name: AttributeName::new("AttrName0"),
                attribute_type: AttributeType::String,
                is_list: false,
                is_visible: false,
                is_editable: false,
            }))
            .return_once(|_| Ok(()));
        let context = Context::<MockTestBackendHandler>::new_for_tests(
            mock,
            ValidationResults {
                user: UserId::new("bob"),
                permission: Permission::Admin,
            },
        );
        let vars = Variables::from([
            ("name".to_string(), InputValue::scalar("AttrName0")),
            (
                "attributeType".to_string(),
                InputValue::enum_value("STRING"),
            ),
            ("isList".to_string(), InputValue::scalar(false)),
            ("isVisible".to_string(), InputValue::scalar(false)),
            ("isEditable".to_string(), InputValue::scalar(false)),
        ]);
        let schema = mutation_schema(
            Query::<MockTestBackendHandler>::new(),
            Mutation::<MockTestBackendHandler>::new(),
        );
        assert_eq!(
            execute(QUERY, None, &schema, &vars, &context).await,
            Ok((
                graphql_value!(
                {
                    "addGroupAttribute": {
                        "ok": true
                    }
                } ),
                vec![]
            ))
        );
    }

    #[tokio::test]
    async fn test_create_group_attribute_invalid() {
        const QUERY: &str = r#"
            mutation CreateUserAttribute($name: String!, $attributeType: AttributeType!, $isList: Boolean!, $isVisible: Boolean!, $isEditable: Boolean!) {
                addUserAttribute(name: $name, attributeType: $attributeType, isList: $isList, isVisible: $isVisible, isEditable: $isEditable) {
                    ok
                }
            }
        "#;
        let mock = MockTestBackendHandler::new();
        let context = Context::<MockTestBackendHandler>::new_for_tests(
            mock,
            ValidationResults {
                user: UserId::new("bob"),
                permission: Permission::Admin,
            },
        );
        let vars = Variables::from([
            ("name".to_string(), InputValue::scalar("AttrName_0")),
            (
                "attributeType".to_string(),
                InputValue::enum_value("STRING"),
            ),
            ("isList".to_string(), InputValue::scalar(false)),
            ("isVisible".to_string(), InputValue::scalar(false)),
            ("isEditable".to_string(), InputValue::scalar(false)),
        ]);
        let schema = mutation_schema(
            Query::<MockTestBackendHandler>::new(),
            Mutation::<MockTestBackendHandler>::new(),
        );
        let result = execute(QUERY, None, &schema, &vars, &context).await;
        match result {
            Ok(res) => {
                let (response, errors) = res;
                assert!(response.is_null());
                let expected_error_msg =
                    "Cannot create attribute with invalid name. Valid characters: a-z, A-Z, 0-9, and dash (-). Invalid chars found: _"
                        .to_string();
                assert!(errors
                    .iter()
                    .all(|e| e.error().message() == expected_error_msg));
            }
            Err(_) => {
                panic!();
            }
        }
    }

    #[tokio::test]
    async fn test_attribute_consolidation_attr_precedence() {
        let attributes = vec![
            AttributeValue {
                name: "first_name".to_string(),
                value: vec!["expected-first".to_string()],
            },
            AttributeValue {
                name: "last_name".to_string(),
                value: vec!["expected-last".to_string()],
            },
            AttributeValue {
                name: "avatar".to_string(),
                value: vec!["expected-avatar".to_string()],
            },
        ];
        let res = consolidate_attributes(
            attributes.clone(),
            Some("overridden-first".to_string()),
            Some("overridden-last".to_string()),
            Some("overriden-avatar".to_string()),
        );
        assert_eq!(
            res,
            vec![
                AttributeValue {
                    name: "avatar".to_string(),
                    value: vec!["expected-avatar".to_string()],
                },
                AttributeValue {
                    name: "first_name".to_string(),
                    value: vec!["expected-first".to_string()],
                },
                AttributeValue {
                    name: "last_name".to_string(),
                    value: vec!["expected-last".to_string()],
                },
            ]
        );
    }

    #[tokio::test]
    async fn test_attribute_consolidation_field_fallback() {
        let attributes = Vec::new();
        let res = consolidate_attributes(
            attributes.clone(),
            Some("expected-first".to_string()),
            Some("expected-last".to_string()),
            Some("expected-avatar".to_string()),
        );
        assert_eq!(
            res,
            vec![
                AttributeValue {
                    name: "avatar".to_string(),
                    value: vec!["expected-avatar".to_string()],
                },
                AttributeValue {
                    name: "first_name".to_string(),
                    value: vec!["expected-first".to_string()],
                },
                AttributeValue {
                    name: "last_name".to_string(),
                    value: vec!["expected-last".to_string()],
                },
            ]
        );
    }

    #[tokio::test]
    async fn test_attribute_consolidation_field_fallback_2() {
        let attributes = vec![AttributeValue {
            name: "First_Name".to_string(),
            value: vec!["expected-first".to_string()],
        }];
        let res = consolidate_attributes(
            attributes.clone(),
            Some("overriden-first".to_string()),
            Some("expected-last".to_string()),
            Some("expected-avatar".to_string()),
        );
        assert_eq!(
            res,
            vec![
                AttributeValue {
                    name: "avatar".to_string(),
                    value: vec!["expected-avatar".to_string()],
                },
                AttributeValue {
                    name: "first_name".to_string(),
                    value: vec!["expected-first".to_string()],
                },
                AttributeValue {
                    name: "last_name".to_string(),
                    value: vec!["expected-last".to_string()],
                },
            ]
        );
    }
}
