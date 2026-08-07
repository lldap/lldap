pub mod helpers;
pub mod inputs;

// Re-export public types
pub use inputs::{
    AttributeValue, CreateGroupInput, CreateUserInput, MfaEnrollmentStart, Success,
    UpdateGroupInput, UpdateUserInput,
};

use crate::api::{Context, check_mfa_enrollment, field_error_callback};
use anyhow::anyhow;
use juniper::{FieldError, FieldResult, graphql_object};
use lldap_access_control::{
    AdminBackendHandler, UserReadableBackendHandler, UserWriteableBackendHandler,
};
use lldap_domain::{
    requests::{CreateAttributeRequest, CreateUserRequest, UpdateGroupRequest, UpdateUserRequest},
    types::{AttributeName, AttributeType, Email, GroupId, LdapObjectClass, UserId},
};
use lldap_domain_handlers::handler::{BackendHandler, MfaBackendHandler, MfaPolicy};
use lldap_validation::attributes::{ALLOWED_CHARACTERS_DESCRIPTION, validate_attribute_name};
use std::sync::Arc;
use tracing::{Instrument, debug, debug_span};

use helpers::{
    UnpackedAttributes, consolidate_attributes, create_group_with_details, deserialize_attribute,
    unpack_attributes,
};

#[derive(PartialEq, Eq, Debug)]
/// The top-level GraphQL mutation type.
pub struct Mutation<Handler: BackendHandler> {
    _phantom: std::marker::PhantomData<Box<Handler>>,
}

impl<Handler: BackendHandler> Default for Mutation<Handler> {
    fn default() -> Self {
        Self::new()
    }
}

impl<Handler: BackendHandler> Mutation<Handler> {
    pub fn new() -> Self {
        Self {
            _phantom: std::marker::PhantomData,
        }
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
        check_mfa_enrollment(context, &span).await?;
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
        check_mfa_enrollment(context, &span).await?;
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
        check_mfa_enrollment(context, &span).await?;
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
        check_mfa_enrollment(context, &span).await?;
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
        check_mfa_enrollment(context, &span).await?;
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
        check_mfa_enrollment(context, &span).await?;
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
        check_mfa_enrollment(context, &span).await?;
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
        check_mfa_enrollment(context, &span).await?;
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
        check_mfa_enrollment(context, &span).await?;
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

    async fn reset_user_mfa(context: &Context<Handler>, user_id: String) -> FieldResult<Success> {
        let span = debug_span!("[GraphQL mutation] reset_user_mfa");
        span.in_scope(|| {
            debug!(?user_id);
        });
        check_mfa_enrollment(context, &span).await?;
        let user_id = UserId::new(&user_id);
        // Under "always" nobody gives up their own factor, admins included:
        // recovery is another admin, or the password reset that clears both.
        if context.mfa_policy == MfaPolicy::Always && user_id == context.validation_result.user {
            span.in_scope(|| debug!("MFA is required by the server configuration"));
            return Err(
                "Cannot reset your own MFA when it is required by the server configuration".into(),
            );
        }
        let readable_handler = context
            .get_readable_handler(&user_id)
            .ok_or_else(field_error_callback(&span, "Unauthorized MFA reset"))?;
        let user_is_admin = readable_handler
            .get_user_groups(&user_id)
            .instrument(span.clone())
            .await?
            .iter()
            .any(|g| g.display_name == "lldap_admin".into());
        let handler = context
            .get_mfa_reset_handler(&user_id, user_is_admin)
            .ok_or_else(field_error_callback(&span, "Unauthorized MFA reset"))?;
        handler.reset_user_mfa(&user_id).instrument(span).await?;
        Ok(Success::new())
    }

    async fn reset_own_mfa(context: &Context<Handler>, code: String) -> FieldResult<Success> {
        let span = debug_span!("[GraphQL mutation] reset_own_mfa");
        let user_id = context.validation_result.user.clone();
        // The code is deliberately not logged.
        span.in_scope(|| {
            debug!(?user_id);
        });
        match context.mfa_policy {
            MfaPolicy::Disabled => {
                span.in_scope(|| debug!("MFA is disabled by the server configuration"));
                return Err("MFA is disabled by the server configuration".into());
            }
            MfaPolicy::Always => {
                span.in_scope(|| debug!("MFA is required by the server configuration"));
                return Err("MFA is required by the server configuration".into());
            }
            MfaPolicy::Enrolled => {}
        }
        context
            .get_mfa_self_handler()
            .reset_own_mfa(&user_id, &code)
            .instrument(span)
            .await?;
        Ok(Success::new())
    }

    async fn start_mfa_enrollment(
        context: &Context<Handler>,
        current_code: Option<String>,
    ) -> FieldResult<MfaEnrollmentStart> {
        let span = debug_span!("[GraphQL mutation] start_mfa_enrollment");
        let user_id = context.validation_result.user.clone();
        // The code is deliberately not logged.
        span.in_scope(|| {
            debug!(?user_id);
        });
        if context.mfa_policy == MfaPolicy::Disabled {
            span.in_scope(|| debug!("MFA is disabled by the server configuration"));
            return Err("MFA is disabled by the server configuration".into());
        }
        let start = context
            .get_mfa_self_handler()
            .start_totp_enrollment(&user_id, current_code)
            .instrument(span)
            .await?;
        Ok(start.into())
    }

    async fn finish_mfa_enrollment(
        context: &Context<Handler>,
        state: String,
        code: String,
    ) -> FieldResult<Success> {
        let span = debug_span!("[GraphQL mutation] finish_mfa_enrollment");
        let user_id = context.validation_result.user.clone();
        // The sealed state and the code are deliberately not logged.
        span.in_scope(|| {
            debug!(?user_id);
        });
        if context.mfa_policy == MfaPolicy::Disabled {
            span.in_scope(|| debug!("MFA is disabled by the server configuration"));
            return Err("MFA is disabled by the server configuration".into());
        }
        context
            .get_mfa_self_handler()
            .finish_totp_enrollment(&user_id, &state, &code)
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
        check_mfa_enrollment(context, &span).await?;
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
        check_mfa_enrollment(context, &span).await?;
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
        check_mfa_enrollment(context, &span).await?;
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
        check_mfa_enrollment(context, &span).await?;
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
        check_mfa_enrollment(context, &span).await?;
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
        check_mfa_enrollment(context, &span).await?;
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
        check_mfa_enrollment(context, &span).await?;
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
        check_mfa_enrollment(context, &span).await?;
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
#[cfg(test)]
mod tests {
    use super::*;
    use crate::query::Query;
    use chrono::TimeZone;
    use juniper::{
        DefaultScalarValue, EmptySubscription, GraphQLType, InputValue, RootNode, Variables,
        execute, graphql_value,
    };
    use lldap_auth::access_control::{Permission, ValidationResults};
    use lldap_domain::types::{
        AttributeName, AttributeType, GroupDetails, MFA_TYPE_TOTP, TotpEnrollmentStart, User,
    };
    use lldap_test_utils::MockTestBackendHandler;
    use mockall::predicate::eq;
    use pretty_assertions::assert_eq;
    use std::collections::HashSet;

    fn mutation_schema<C, Q, M>(
        query_root: Q,
        mutation_root: M,
    ) -> RootNode<Q, M, EmptySubscription<C>>
    where
        Q: GraphQLType<DefaultScalarValue, Context = C, TypeInfo = ()>,
        M: GraphQLType<DefaultScalarValue, Context = C, TypeInfo = ()>,
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
                assert!(
                    errors
                        .iter()
                        .all(|e| e.error().message() == expected_error_msg)
                );
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
                assert!(
                    errors
                        .iter()
                        .all(|e| e.error().message() == expected_error_msg)
                );
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

    const RESET_QUERY: &str = r#"mutation { resetUserMfa(userId: "bob") { ok } }"#;
    const START_QUERY: &str = r#"mutation { startMfaEnrollment { state } }"#;
    const FINISH_QUERY: &str =
        r#"mutation { finishMfaEnrollment(state: "sealed-state", code: "123456") { ok } }"#;
    const RESET_OWN_QUERY: &str = r#"mutation { resetOwnMfa(code: "123456") { ok } }"#;

    fn expect_target_in_admin_group(mock: &mut MockTestBackendHandler, target_is_admin: bool) {
        let mut groups = HashSet::new();
        if target_is_admin {
            groups.insert(GroupDetails {
                group_id: GroupId(1),
                display_name: "lldap_admin".into(),
                creation_date: chrono::Utc.timestamp_opt(0, 0).unwrap().naive_utc(),
                uuid: lldap_domain::types::Uuid::from_name_and_date(
                    "lldap_admin",
                    &chrono::Utc.timestamp_opt(0, 0).unwrap().naive_utc(),
                ),
                attributes: Vec::new(),
                modified_date: chrono::Utc.timestamp_opt(0, 0).unwrap().naive_utc(),
            });
        }
        mock.expect_get_user_groups()
            .with(eq(UserId::new("bob")))
            .return_once(|_| Ok(groups));
    }

    // What check_mfa_enrollment reads to decide whether "bob" is enrolled.
    fn expect_bob_with_mfa(mock: &mut MockTestBackendHandler, mfa_type: Option<&'static str>) {
        mock.expect_get_user_details()
            .with(eq(UserId::new("bob")))
            .returning(move |_| {
                let epoch = chrono::Utc.timestamp_opt(0, 0).unwrap().naive_utc();
                Ok(User {
                    user_id: UserId::new("bob"),
                    email: "bob@bobbers.on".into(),
                    display_name: None,
                    creation_date: epoch,
                    modified_date: epoch,
                    password_modified_date: epoch,
                    uuid: lldap_domain::types::Uuid::from_name_and_date("bob", &epoch),
                    attributes: Vec::new(),
                    mfa_type: mfa_type.map(str::to_owned),
                })
            });
        mock.expect_get_user_groups()
            .with(eq(UserId::new("bob")))
            .returning(|_| Ok(HashSet::new()));
    }

    fn expect_enrollment_start(
        mock: &mut MockTestBackendHandler,
        current_code: Option<&'static str>,
    ) {
        mock.expect_start_totp_enrollment()
            .withf(move |user_id, code| {
                user_id == &UserId::new("bob") && code.as_deref() == current_code
            })
            .return_once(|_, _| {
                Ok(TotpEnrollmentStart {
                    otpauth_uri: "otpauth://totp/LLDAP:bob".to_string(),
                    secret_base32: "ABC234".to_string(),
                    state: "sealed-state".to_string(),
                })
            });
    }

    fn mfa_context(
        mock: MockTestBackendHandler,
        user: &str,
        permission: Permission,
        policy: MfaPolicy,
    ) -> Context<MockTestBackendHandler> {
        Context::<MockTestBackendHandler>::new_for_tests_with_policy(
            mock,
            ValidationResults {
                user: UserId::new(user),
                permission,
            },
            policy,
        )
    }

    async fn assert_gql_error(
        context: &Context<MockTestBackendHandler>,
        query: &str,
        message: &str,
    ) {
        let schema = mutation_schema(
            Query::<MockTestBackendHandler>::new(),
            Mutation::<MockTestBackendHandler>::new(),
        );
        let (response, errors) = execute(query, None, &schema, &Variables::new(), context)
            .await
            .unwrap();
        assert!(response.is_null());
        assert!(!errors.is_empty());
        assert!(errors.iter().all(|e| e.error().message() == message));
    }

    async fn assert_gql_ok(
        context: &Context<MockTestBackendHandler>,
        query: &str,
        expected: juniper::Value,
    ) {
        let schema = mutation_schema(
            Query::<MockTestBackendHandler>::new(),
            Mutation::<MockTestBackendHandler>::new(),
        );
        assert_eq!(
            execute(query, None, &schema, &Variables::new(), context).await,
            Ok((expected, vec![]))
        );
    }

    #[tokio::test]
    async fn test_reset_user_mfa_authorization() {
        for permission in [Permission::Admin, Permission::PasswordManager] {
            let mut mock = MockTestBackendHandler::new();
            expect_target_in_admin_group(&mut mock, false);
            mock.expect_reset_user_mfa()
                .with(eq(UserId::new("bob")))
                .return_once(|_| Ok(()));
            let context = mfa_context(mock, "manager", permission, MfaPolicy::Disabled);
            assert_gql_ok(
                &context,
                RESET_QUERY,
                graphql_value!({"resetUserMfa": {"ok": true}}),
            )
            .await;
        }

        let mut mock = MockTestBackendHandler::new();
        expect_target_in_admin_group(&mut mock, true);
        let context = mfa_context(
            mock,
            "manager",
            Permission::PasswordManager,
            MfaPolicy::Disabled,
        );
        assert_gql_error(&context, RESET_QUERY, "Unauthorized MFA reset").await;

        for permission in [Permission::Regular, Permission::PasswordManager] {
            let mut mock = MockTestBackendHandler::new();
            expect_target_in_admin_group(&mut mock, false);
            let context = mfa_context(mock, "bob", permission, MfaPolicy::Disabled);
            assert_gql_error(&context, RESET_QUERY, "Unauthorized MFA reset").await;
        }
    }

    #[tokio::test]
    async fn test_mfa_enrollment() {
        const START_WITH_CODE: &str = r#"mutation { startMfaEnrollment(
            currentCode: "654321") { otpauthUri secretBase32 state } }"#;
        let mut mock = MockTestBackendHandler::new();
        expect_enrollment_start(&mut mock, Some("654321"));
        mock.expect_finish_totp_enrollment()
            .withf(|user_id, state, code| {
                user_id == &UserId::new("bob") && state == "sealed-state" && code == "123456"
            })
            .return_once(|_, _, _| Ok(()));
        let context = mfa_context(mock, "bob", Permission::Regular, MfaPolicy::Enrolled);
        assert_gql_ok(
            &context,
            START_WITH_CODE,
            graphql_value!({"startMfaEnrollment": {
                "otpauthUri": "otpauth://totp/LLDAP:bob",
                "secretBase32": "ABC234",
                "state": "sealed-state"
            }}),
        )
        .await;
        assert_gql_ok(
            &context,
            FINISH_QUERY,
            graphql_value!({"finishMfaEnrollment": {"ok": true}}),
        )
        .await;
    }

    #[tokio::test]
    async fn test_reset_user_mfa_self_refused_under_always() {
        // Cased differently from the session user: UserId compares case-insensitively.
        const SELF_QUERY: &str = r#"mutation { resetUserMfa(userId: "Bob") { ok } }"#;
        let mut mock = MockTestBackendHandler::new();
        expect_bob_with_mfa(&mut mock, Some(MFA_TYPE_TOTP));
        // No expect_reset_user_mfa: reaching the handler must fail the mock.
        let context = mfa_context(mock, "bob", Permission::Admin, MfaPolicy::Always);
        assert_gql_error(
            &context,
            SELF_QUERY,
            "Cannot reset your own MFA when it is required by the server configuration",
        )
        .await;
    }

    #[tokio::test]
    async fn test_reset_own_mfa() {
        let mut mock = MockTestBackendHandler::new();
        mock.expect_reset_own_mfa()
            .withf(|user_id, code| user_id == &UserId::new("bob") && code == "123456")
            .return_once(|_, _| Ok(()));
        let context = mfa_context(mock, "bob", Permission::Regular, MfaPolicy::Enrolled);
        assert_gql_ok(
            &context,
            RESET_OWN_QUERY,
            graphql_value!({"resetOwnMfa": {"ok": true}}),
        )
        .await;

        let context = mfa_context(
            MockTestBackendHandler::new(),
            "bob",
            Permission::Regular,
            MfaPolicy::Always,
        );
        assert_gql_error(
            &context,
            RESET_OWN_QUERY,
            "MFA is required by the server configuration",
        )
        .await;
    }

    #[tokio::test]
    async fn test_mfa_mutations_gated_when_disabled() {
        let mut mock = MockTestBackendHandler::new();
        expect_target_in_admin_group(&mut mock, false);
        mock.expect_reset_user_mfa()
            .with(eq(UserId::new("bob")))
            .return_once(|_| Ok(()));
        let context = mfa_context(mock, "admin", Permission::Admin, MfaPolicy::Disabled);
        for query in [START_QUERY, FINISH_QUERY, RESET_OWN_QUERY] {
            assert_gql_error(
                &context,
                query,
                "MFA is disabled by the server configuration",
            )
            .await;
        }
        assert_gql_ok(
            &context,
            RESET_QUERY,
            graphql_value!({"resetUserMfa": {"ok": true}}),
        )
        .await;
    }

    #[tokio::test]
    async fn test_mutations_gated_until_enrolled_under_always() {
        const UPDATE_QUERY: &str = r#"mutation { updateUser(user: { id: "bob" }) { ok } }"#;
        const USERS_QUERY: &str = r#"{ users { id } }"#;
        const GATE_ERROR: &str =
            "MFA enrollment required: enroll through the web interface or contact an administrator";
        let mut mock = MockTestBackendHandler::new();
        expect_bob_with_mfa(&mut mock, None);
        expect_enrollment_start(&mut mock, None);
        mock.expect_finish_totp_enrollment()
            .withf(|user_id, state, code| {
                user_id == &UserId::new("bob") && state == "sealed-state" && code == "123456"
            })
            .return_once(|_, _, _| Ok(()));
        let context = mfa_context(mock, "bob", Permission::Regular, MfaPolicy::Always);
        for query in [UPDATE_QUERY, USERS_QUERY] {
            assert_gql_error(&context, query, GATE_ERROR).await;
        }
        // Both halves of enrollment stay exempt, or an unenrolled user could never enroll.
        assert_gql_ok(
            &context,
            START_QUERY,
            graphql_value!({"startMfaEnrollment": {"state": "sealed-state"}}),
        )
        .await;
        assert_gql_ok(
            &context,
            FINISH_QUERY,
            graphql_value!({"finishMfaEnrollment": {"ok": true}}),
        )
        .await;
    }
}
