use crate::{
    core::{
        error::{LdapError, LdapResult},
        utils::{
            LdapInfo, UserFieldType, UserOrGroupName, get_user_or_group_id_from_distinguished_name,
            map_user_field,
        },
    },
    handler::make_add_response,
};
use ldap3_proto::proto::{
    LdapAddRequest, LdapAttribute, LdapOp, LdapPartialAttribute, LdapResultCode,
};
use lldap_access_control::{AdminBackendHandler, UserReadableBackendHandler};
use lldap_domain::{
    deserialize,
    public_schema::PublicSchema,
    requests::{CreateGroupRequest, CreateUserRequest},
    types::{Attribute, AttributeName, AttributeType, Email, GroupName, UserId},
};
use lldap_domain_model::model::UserColumn;
use std::collections::HashMap;
use tracing::instrument;

fn attribute_to_bytes(mut attr: LdapPartialAttribute) -> (String, Vec<Vec<u8>>) {
    attr.atype.make_ascii_lowercase();
    (attr.atype, attr.vals)
}

fn decode_attribute_values(name: &str, values: &[Vec<u8>]) -> LdapResult<Vec<String>> {
    values
        .iter()
        .map(|value| {
            std::str::from_utf8(value)
                .map_err(|e| LdapError {
                    code: LdapResultCode::ConstraintViolation,
                    message: format!(
                        "Attribute {name} value is invalid UTF-8: {e:#?} (value {value:?})"
                    ),
                })
                .map(str::to_owned)
        })
        .collect()
}

fn validate_attribute_arity(name: &str, value_count: usize, is_list: bool) -> LdapResult<()> {
    if value_count == 0 {
        return Err(LdapError {
            code: LdapResultCode::ConstraintViolation,
            message: format!("Missing value for attribute {name}"),
        });
    }
    if !is_list && value_count != 1 {
        return Err(LdapError {
            code: LdapResultCode::ConstraintViolation,
            message: format!("Expected a single value for attribute {name}"),
        });
    }
    Ok(())
}

fn undefined_attribute_type(name: &str) -> LdapError {
    LdapError {
        code: LdapResultCode::UndefinedAttributeType,
        message: format!("Undefined attribute type {name}"),
    }
}

fn make_encoded_attribute(
    name: AttributeName,
    typ: AttributeType,
    is_list: bool,
    values: &[String],
) -> LdapResult<Attribute> {
    validate_attribute_arity(name.as_str(), values.len(), is_list)?;
    Ok(Attribute {
        name,
        value: deserialize::deserialize_attribute_value(values, typ, is_list).map_err(|e| {
            LdapError {
                code: LdapResultCode::ConstraintViolation,
                message: format!("Invalid attribute value: {e}"),
            }
        })?,
    })
}

fn schema_attribute_type(
    schema: &PublicSchema,
    attribute_name: &AttributeName,
    ldap_attribute_name: &str,
) -> LdapResult<(AttributeType, bool)> {
    schema
        .get_schema()
        .user_attributes
        .get_attribute_type(attribute_name)
        .ok_or_else(|| undefined_attribute_type(ldap_attribute_name))
}

fn single_primary_field_value(
    schema: &PublicSchema,
    ldap_attribute_name: &str,
    schema_attribute_name: &str,
    raw_values: &[Vec<u8>],
) -> LdapResult<String> {
    let (_, is_list) = schema_attribute_type(
        schema,
        &AttributeName::from(schema_attribute_name),
        ldap_attribute_name,
    )?;
    validate_attribute_arity(ldap_attribute_name, raw_values.len(), is_list)?;
    let values = decode_attribute_values(ldap_attribute_name, raw_values)?;
    Ok(values[0].clone())
}

#[instrument(skip_all, level = "debug")]
pub(crate) async fn create_user_or_group(
    backend_handler: &impl AdminBackendHandler,
    ldap_info: &LdapInfo,
    request: LdapAddRequest,
) -> LdapResult<Vec<LdapOp>> {
    let base_dn_str = &ldap_info.base_dn_str;
    match get_user_or_group_id_from_distinguished_name(&request.dn, &ldap_info.base_dn) {
        UserOrGroupName::User(user_id) => {
            create_user(backend_handler, user_id, request.attributes).await
        }
        UserOrGroupName::Group(group_name) => {
            create_group(backend_handler, group_name, request.attributes).await
        }
        err => Err(err.into_ldap_error(
            &request.dn,
            format!(r#""uid=id,ou=people,{base_dn_str}" or "uid=id,ou=groups,{base_dn_str}""#),
        )),
    }
}

#[instrument(skip_all, level = "debug")]
async fn create_user(
    backend_handler: &impl AdminBackendHandler,
    user_id: UserId,
    attributes: Vec<LdapAttribute>,
) -> LdapResult<Vec<LdapOp>> {
    let schema = UserReadableBackendHandler::get_schema(backend_handler)
        .await
        .map_err(|e| LdapError {
            code: LdapResultCode::OperationsError,
            message: format!("Unable to get schema: {e:#}"),
        })?;
    let raw_ldap_attributes: HashMap<String, Vec<Vec<u8>>> =
        attributes.into_iter().map(attribute_to_bytes).collect();
    let mut new_user_attributes: Vec<Attribute> = Vec::new();
    let mut mail = None;
    let mut email = None;
    let mut display_name = None;
    for (ldap_attribute_name, raw_values) in raw_ldap_attributes {
        if ldap_attribute_name.eq_ignore_ascii_case("objectclass") {
            continue;
        }
        let attribute_name = AttributeName::from(ldap_attribute_name.as_str());
        match map_user_field(&attribute_name, &schema) {
            UserFieldType::PrimaryField(UserColumn::Email) => {
                let value =
                    single_primary_field_value(&schema, &ldap_attribute_name, "mail", &raw_values)?;
                if ldap_attribute_name == "mail" {
                    mail = Some(value);
                } else if email.is_none() {
                    email = Some(value);
                }
            }
            UserFieldType::PrimaryField(UserColumn::DisplayName) => {
                let value = single_primary_field_value(
                    &schema,
                    &ldap_attribute_name,
                    "display_name",
                    &raw_values,
                )?;
                if ldap_attribute_name == "cn" || display_name.is_none() {
                    display_name = Some(value);
                }
            }
            UserFieldType::PrimaryField(UserColumn::UserId) => {
                single_primary_field_value(&schema, &ldap_attribute_name, "user_id", &raw_values)?;
            }
            UserFieldType::Attribute(attribute_name, _, _) => {
                let (typ, is_list) =
                    schema_attribute_type(&schema, &attribute_name, &ldap_attribute_name)?;
                validate_attribute_arity(&ldap_attribute_name, raw_values.len(), is_list)?;
                let values = decode_attribute_values(&ldap_attribute_name, &raw_values)?;
                new_user_attributes.push(make_encoded_attribute(
                    attribute_name,
                    typ,
                    is_list,
                    &values,
                )?);
            }
            UserFieldType::NoMatch
            | UserFieldType::ObjectClass
            | UserFieldType::MemberOf
            | UserFieldType::Dn
            | UserFieldType::EntryDn
            | UserFieldType::PrimaryField(_) => {
                return Err(undefined_attribute_type(&ldap_attribute_name));
            }
        }
    }
    backend_handler
        .create_user(CreateUserRequest {
            user_id,
            email: Email::from(mail.or(email).unwrap_or_default()),
            display_name,
            attributes: new_user_attributes,
        })
        .await
        .map_err(|e| LdapError {
            code: LdapResultCode::OperationsError,
            message: format!("Could not create user: {e:#?}"),
        })?;
    Ok(vec![make_add_response(
        LdapResultCode::Success,
        String::new(),
    )])
}

#[instrument(skip_all, level = "debug")]
async fn create_group(
    backend_handler: &impl AdminBackendHandler,
    group_name: GroupName,
    _attributes: Vec<LdapAttribute>,
) -> LdapResult<Vec<LdapOp>> {
    backend_handler
        .create_group(CreateGroupRequest {
            display_name: group_name,
            attributes: Vec::new(),
        })
        .await
        .map_err(|e| LdapError {
            code: LdapResultCode::OperationsError,
            message: format!("Could not create group: {e:#?}"),
        })?;
    Ok(vec![make_add_response(
        LdapResultCode::Success,
        String::new(),
    )])
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::handler::tests::setup_bound_admin_handler;
    use lldap_domain::schema::{AttributeList, AttributeSchema, Schema};
    use lldap_domain::types::*;
    use lldap_test_utils::MockTestBackendHandler;
    use mockall::predicate::eq;
    use pretty_assertions::assert_eq;

    fn user_attribute_schema(
        name: &str,
        attribute_type: AttributeType,
        is_list: bool,
    ) -> AttributeSchema {
        AttributeSchema {
            name: name.into(),
            attribute_type,
            is_list,
            is_visible: true,
            is_editable: true,
            is_hardcoded: false,
            is_readonly: false,
        }
    }

    fn schema_with_user_attributes(attributes: Vec<AttributeSchema>) -> Schema {
        Schema {
            user_attributes: AttributeList { attributes },
            group_attributes: AttributeList {
                attributes: Vec::new(),
            },
            extra_user_object_classes: Vec::new(),
            extra_group_object_classes: Vec::new(),
        }
    }

    #[tokio::test]
    async fn test_create_user() {
        let mut mock = MockTestBackendHandler::new();
        mock.expect_create_user()
            .with(eq(CreateUserRequest {
                user_id: UserId::new("bob"),
                email: "".into(),
                display_name: Some("Bob".to_string()),
                ..Default::default()
            }))
            .times(1)
            .return_once(|_| Ok(()));
        let ldap_handler = setup_bound_admin_handler(mock).await;
        let request = LdapAddRequest {
            dn: "uid=bob,ou=people,dc=example,dc=com".to_owned(),
            attributes: vec![LdapPartialAttribute {
                atype: "cn".to_owned(),
                vals: vec![b"Bob".to_vec()],
            }],
        };
        assert_eq!(
            ldap_handler.create_user_or_group(request).await,
            Ok(vec![make_add_response(
                LdapResultCode::Success,
                String::new()
            )])
        );
    }

    #[tokio::test]
    async fn test_create_user_with_schema_attributes() {
        let mut mock = MockTestBackendHandler::new();
        mock.expect_get_schema().times(1).returning(|| {
            Ok(schema_with_user_attributes(vec![
                user_attribute_schema("first_name", AttributeType::String, false),
                user_attribute_schema("nicknames", AttributeType::String, true),
            ]))
        });
        mock.expect_create_user()
            .withf(|request| {
                let first_name = Attribute {
                    name: AttributeName::from("first_name"),
                    value: "Robert".to_string().into(),
                };
                let nicknames = Attribute {
                    name: AttributeName::from("nicknames"),
                    value: vec!["Bobby".to_string(), "Rob".to_string()].into(),
                };
                request.user_id == UserId::new("bob")
                    && request.email == Email::from("bob@example.com")
                    && request.display_name == Some("Bob".to_string())
                    && request.attributes.len() == 2
                    && request.attributes.contains(&first_name)
                    && request.attributes.contains(&nicknames)
            })
            .times(1)
            .return_once(|_| Ok(()));
        assert_eq!(
            create_user(
                &mock,
                UserId::new("bob"),
                vec![
                    LdapPartialAttribute {
                        atype: "cn".to_owned(),
                        vals: vec![b"Bob".to_vec()],
                    },
                    LdapPartialAttribute {
                        atype: "mail".to_owned(),
                        vals: vec![b"bob@example.com".to_vec()],
                    },
                    LdapPartialAttribute {
                        atype: "givenName".to_owned(),
                        vals: vec![b"Robert".to_vec()],
                    },
                    LdapPartialAttribute {
                        atype: "nicknames".to_owned(),
                        vals: vec![b"Bobby".to_vec(), b"Rob".to_vec()],
                    },
                ],
            )
            .await,
            Ok(vec![make_add_response(
                LdapResultCode::Success,
                String::new()
            )])
        );
    }

    #[tokio::test]
    async fn test_create_user_rejects_undefined_attribute() {
        let mut mock = MockTestBackendHandler::new();
        mock.expect_get_schema()
            .times(1)
            .returning(|| Ok(schema_with_user_attributes(Vec::new())));
        let err = create_user(
            &mock,
            UserId::new("bob"),
            vec![LdapPartialAttribute {
                atype: "undefined_attribute".to_owned(),
                vals: vec![vec![0xff]],
            }],
        )
        .await
        .unwrap_err();
        assert_eq!(err.code, LdapResultCode::UndefinedAttributeType);
    }

    #[tokio::test]
    async fn test_create_user_rejects_wrong_schema_attribute_arity() {
        let mut mock = MockTestBackendHandler::new();
        mock.expect_get_schema().times(1).returning(|| {
            Ok(schema_with_user_attributes(vec![user_attribute_schema(
                "first_name",
                AttributeType::String,
                false,
            )]))
        });
        let err = create_user(
            &mock,
            UserId::new("bob"),
            vec![LdapPartialAttribute {
                atype: "givenName".to_owned(),
                vals: vec![b"Robert".to_vec(), b"Bob".to_vec()],
            }],
        )
        .await
        .unwrap_err();
        assert_eq!(err.code, LdapResultCode::ConstraintViolation);
    }

    #[tokio::test]
    async fn test_create_group() {
        let mut mock = MockTestBackendHandler::new();
        mock.expect_create_group()
            .with(eq(CreateGroupRequest {
                display_name: GroupName::new("bob"),
                ..Default::default()
            }))
            .times(1)
            .return_once(|_| Ok(GroupId(5)));
        let ldap_handler = setup_bound_admin_handler(mock).await;
        let request = LdapAddRequest {
            dn: "uid=bob,ou=groups,dc=example,dc=com".to_owned(),
            attributes: vec![LdapPartialAttribute {
                atype: "cn".to_owned(),
                vals: vec![b"Bobby".to_vec()],
            }],
        };
        assert_eq!(
            ldap_handler.create_user_or_group(request).await,
            Ok(vec![make_add_response(
                LdapResultCode::Success,
                String::new()
            )])
        );
    }

    #[tokio::test]
    async fn test_create_user_multiple_object_class() {
        let mut mock = MockTestBackendHandler::new();
        mock.expect_create_user()
            .with(eq(CreateUserRequest {
                user_id: UserId::new("bob"),
                email: "".into(),
                display_name: Some("Bob".to_string()),
                ..Default::default()
            }))
            .times(1)
            .return_once(|_| Ok(()));
        let ldap_handler = setup_bound_admin_handler(mock).await;
        let request = LdapAddRequest {
            dn: "uid=bob,ou=people,dc=example,dc=com".to_owned(),
            attributes: vec![
                LdapPartialAttribute {
                    atype: "cn".to_owned(),
                    vals: vec![b"Bob".to_vec()],
                },
                LdapPartialAttribute {
                    atype: "objectClass".to_owned(),
                    vals: vec![
                        b"top".to_vec(),
                        b"person".to_vec(),
                        b"inetOrgPerson".to_vec(),
                    ],
                },
            ],
        };
        assert_eq!(
            ldap_handler.create_user_or_group(request).await,
            Ok(vec![make_add_response(
                LdapResultCode::Success,
                String::new()
            )])
        );
    }
}
