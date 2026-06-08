use crate::{
    core::{
        error::{LdapError, LdapResult},
        utils::{LdapInfo, UserOrGroupName, get_user_or_group_id_from_distinguished_name},
    },
    handler::make_add_response,
};
use ldap3_proto::proto::{
    LdapAddRequest, LdapAttribute, LdapOp, LdapPartialAttribute, LdapResultCode,
};
use lldap_access_control::AdminBackendHandler;
use lldap_domain::{
    deserialize,
    requests::{CreateGroupRequest, CreateUserRequest},
    types::{Attribute, AttributeName, AttributeType, Email, GroupName, UserId},
};
use lldap_domain_handlers::handler::ReadSchemaBackendHandler;
use std::collections::HashMap;
use tracing::instrument;

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
    fn parse_attribute(mut attr: LdapPartialAttribute) -> (String, Vec<Vec<u8>>) {
        attr.atype.make_ascii_lowercase();
        (attr.atype, attr.vals)
    }
    let attributes: HashMap<String, Vec<Vec<u8>>> = attributes
        .into_iter()
        .filter(|a| !a.atype.eq_ignore_ascii_case("objectclass"))
        .map(parse_attribute)
        .collect();
    fn decode_attribute_value(val: &[u8]) -> LdapResult<String> {
        std::str::from_utf8(val)
            .map_err(|e| LdapError {
                code: LdapResultCode::ConstraintViolation,
                message: format!("Attribute value is invalid UTF-8: {e:#?} (value {val:?})"),
            })
            .map(str::to_owned)
    }
    fn decode_attribute_values(vals: &[Vec<u8>]) -> LdapResult<Vec<String>> {
        vals.iter()
            .map(Vec::as_slice)
            .map(decode_attribute_value)
            .collect()
    }
    let get_attribute = |name| {
        attributes.get(name).map(|vals| {
            if vals.len() > 1 {
                Err(LdapError {
                    code: LdapResultCode::ConstraintViolation,
                    message: format!("Expected a single value for attribute {name}"),
                })
            } else {
                vals.first()
                    .map(Vec::as_slice)
                    .ok_or_else(|| LdapError {
                        code: LdapResultCode::ConstraintViolation,
                        message: format!("Missing value for attribute {name}"),
                    })
                    .and_then(decode_attribute_value)
            }
        })
    };
    let make_encoded_attribute =
        |name: &str, typ: AttributeType, is_list: bool, value: Vec<String>| {
            Ok(Attribute {
                name: AttributeName::from(name),
                value: deserialize::deserialize_attribute_value(&value, typ, is_list).map_err(
                    |e| LdapError {
                        code: LdapResultCode::ConstraintViolation,
                        message: format!("Invalid attribute value: {e}"),
                    },
                )?,
            })
        };
    let make_single_encoded_attribute = |name: &str, typ: AttributeType, value: String| {
        Ok(Attribute {
            name: AttributeName::from(name),
            value: deserialize::deserialize_attribute_value(&[value], typ, false).map_err(|e| {
                LdapError {
                    code: LdapResultCode::ConstraintViolation,
                    message: format!("Invalid attribute value: {e}"),
                }
            })?,
        })
    };
    let mut new_user_attributes: Vec<Attribute> = Vec::new();
    if let Some(first_name) = get_attribute("givenname").transpose()? {
        new_user_attributes.push(make_single_encoded_attribute(
            "first_name",
            AttributeType::String,
            first_name,
        )?);
    }
    if let Some(last_name) = get_attribute("sn").transpose()? {
        new_user_attributes.push(make_single_encoded_attribute(
            "last_name",
            AttributeType::String,
            last_name,
        )?);
    }
    if let Some(avatar) = get_attribute("avatar").transpose()? {
        new_user_attributes.push(make_single_encoded_attribute(
            "avatar",
            AttributeType::JpegPhoto,
            avatar,
        )?);
    }
    let schema = ReadSchemaBackendHandler::get_schema(backend_handler)
        .await
        .map_err(|e| LdapError {
            code: LdapResultCode::OperationsError,
            message: format!("Unable to get schema: {e:#}"),
        })?;
    let consumed_attribute_names = ["givenname", "sn", "avatar", "cn", "mail", "email"];
    for attribute_schema in schema
        .user_attributes
        .attributes
        .iter()
        .filter(|attribute_schema| !attribute_schema.is_hardcoded)
    {
        let Some((_, values)) = attributes.iter().find(|(attribute_name, _)| {
            !consumed_attribute_names
                .iter()
                .any(|consumed| attribute_name.eq_ignore_ascii_case(consumed))
                && attribute_schema
                    .name
                    .as_str()
                    .eq_ignore_ascii_case(attribute_name)
        }) else {
            continue;
        };
        new_user_attributes.push(make_encoded_attribute(
            attribute_schema.name.as_str(),
            attribute_schema.attribute_type,
            attribute_schema.is_list,
            decode_attribute_values(values)?,
        )?);
    }
    backend_handler
        .create_user(CreateUserRequest {
            user_id,
            email: Email::from(
                get_attribute("mail")
                    .or_else(|| get_attribute("email"))
                    .transpose()?
                    .unwrap_or_default(),
            ),
            display_name: get_attribute("cn").transpose()?,
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
    use lldap_domain::{
        schema::{AttributeList, AttributeSchema, Schema},
        types::*,
    };
    use lldap_test_utils::MockTestBackendHandler;
    use mockall::predicate::eq;
    use pretty_assertions::assert_eq;

    fn custom_user_attribute(
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
    async fn test_create_user_with_custom_attribute() {
        let mut mock = MockTestBackendHandler::new();
        mock.expect_get_schema().times(1).return_once(|| {
            Ok(schema_with_user_attributes(vec![
                custom_user_attribute("entitlement", AttributeType::String, false),
                custom_user_attribute("employee_number", AttributeType::Integer, false),
            ]))
        });
        mock.expect_create_user()
            .with(eq(CreateUserRequest {
                user_id: UserId::new("bob"),
                email: "".into(),
                display_name: Some("Bob".to_string()),
                attributes: vec![
                    Attribute {
                        name: "entitlement".into(),
                        value: "admin".to_string().into(),
                    },
                    Attribute {
                        name: "employee_number".into(),
                        value: 42_i64.into(),
                    },
                ],
            }))
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
                        atype: "Entitlement".to_owned(),
                        vals: vec![b"admin".to_vec()],
                    },
                    LdapPartialAttribute {
                        atype: "Employee_Number".to_owned(),
                        vals: vec![b"42".to_vec()],
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
    async fn test_create_user_with_list_custom_attribute() {
        let mut mock = MockTestBackendHandler::new();
        mock.expect_get_schema().times(1).return_once(|| {
            Ok(schema_with_user_attributes(vec![custom_user_attribute(
                "projects",
                AttributeType::String,
                true,
            )]))
        });
        mock.expect_create_user()
            .with(eq(CreateUserRequest {
                user_id: UserId::new("bob"),
                email: "".into(),
                display_name: None,
                attributes: vec![Attribute {
                    name: "projects".into(),
                    value: vec!["alpha".to_string(), "beta".to_string()].into(),
                }],
            }))
            .times(1)
            .return_once(|_| Ok(()));
        assert_eq!(
            create_user(
                &mock,
                UserId::new("bob"),
                vec![LdapPartialAttribute {
                    atype: "projects".to_owned(),
                    vals: vec![b"alpha".to_vec(), b"beta".to_vec()],
                }],
            )
            .await,
            Ok(vec![make_add_response(
                LdapResultCode::Success,
                String::new()
            )])
        );
    }

    #[tokio::test]
    async fn test_create_user_rejects_invalid_typed_custom_attribute() {
        let mut mock = MockTestBackendHandler::new();
        mock.expect_get_schema().times(1).return_once(|| {
            Ok(schema_with_user_attributes(vec![custom_user_attribute(
                "employee_number",
                AttributeType::Integer,
                false,
            )]))
        });
        let err = create_user(
            &mock,
            UserId::new("bob"),
            vec![LdapPartialAttribute {
                atype: "employee_number".to_owned(),
                vals: vec![b"not-a-number".to_vec()],
            }],
        )
        .await
        .unwrap_err();
        assert_eq!(err.code, LdapResultCode::ConstraintViolation);
        assert!(err.message.contains("Invalid attribute value"));
    }

    #[tokio::test]
    async fn test_create_user_ignores_unknown_attribute() {
        let mut mock = MockTestBackendHandler::new();
        mock.expect_get_schema()
            .times(1)
            .return_once(|| Ok(schema_with_user_attributes(Vec::new())));
        mock.expect_create_user()
            .with(eq(CreateUserRequest {
                user_id: UserId::new("bob"),
                email: "".into(),
                display_name: None,
                attributes: Vec::new(),
            }))
            .times(1)
            .return_once(|_| Ok(()));
        assert_eq!(
            create_user(
                &mock,
                UserId::new("bob"),
                vec![LdapPartialAttribute {
                    atype: "unknown".to_owned(),
                    vals: vec![b"ignored".to_vec(), b"also ignored".to_vec()],
                }],
            )
            .await,
            Ok(vec![make_add_response(
                LdapResultCode::Success,
                String::new()
            )])
        );
    }

    #[tokio::test]
    async fn test_create_user_builtin_attributes_are_not_custom_attributes() {
        let avatar = JpegPhoto::for_tests();
        let avatar_value = String::from(&avatar);
        let mut mock = MockTestBackendHandler::new();
        mock.expect_get_schema().times(1).return_once(|| {
            Ok(schema_with_user_attributes(vec![
                custom_user_attribute("givenname", AttributeType::String, false),
                custom_user_attribute("sn", AttributeType::String, false),
                custom_user_attribute("avatar", AttributeType::String, false),
                custom_user_attribute("cn", AttributeType::String, false),
                custom_user_attribute("mail", AttributeType::String, false),
                custom_user_attribute("email", AttributeType::String, false),
            ]))
        });
        mock.expect_create_user()
            .with(eq(CreateUserRequest {
                user_id: UserId::new("bob"),
                email: "bob@example.com".into(),
                display_name: Some("Bob".to_string()),
                attributes: vec![
                    Attribute {
                        name: "first_name".into(),
                        value: "Bob".to_string().into(),
                    },
                    Attribute {
                        name: "last_name".into(),
                        value: "Roberts".to_string().into(),
                    },
                    Attribute {
                        name: "avatar".into(),
                        value: avatar.into(),
                    },
                ],
            }))
            .times(1)
            .return_once(|_| Ok(()));
        assert_eq!(
            create_user(
                &mock,
                UserId::new("bob"),
                vec![
                    LdapPartialAttribute {
                        atype: "givenname".to_owned(),
                        vals: vec![b"Bob".to_vec()],
                    },
                    LdapPartialAttribute {
                        atype: "sn".to_owned(),
                        vals: vec![b"Roberts".to_vec()],
                    },
                    LdapPartialAttribute {
                        atype: "avatar".to_owned(),
                        vals: vec![avatar_value.into_bytes()],
                    },
                    LdapPartialAttribute {
                        atype: "cn".to_owned(),
                        vals: vec![b"Bob".to_vec()],
                    },
                    LdapPartialAttribute {
                        atype: "mail".to_owned(),
                        vals: vec![b"bob@example.com".to_vec()],
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
