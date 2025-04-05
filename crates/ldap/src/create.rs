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
            format!(
                r#""uid=id,ou=people,{}" or "uid=id,ou=groups,{}""#,
                base_dn_str, base_dn_str
            ),
        )),
    }
}

#[instrument(skip_all, level = "debug")]
async fn create_user(
    backend_handler: &impl AdminBackendHandler,
    user_id: UserId,
    attributes: Vec<LdapAttribute>,
) -> LdapResult<Vec<LdapOp>> {
    fn parse_attribute(mut attr: LdapPartialAttribute) -> LdapResult<(String, Vec<u8>)> {
        if attr.vals.len() > 1 {
            Err(LdapError {
                code: LdapResultCode::ConstraintViolation,
                message: format!("Expected a single value for attribute {}", attr.atype),
            })
        } else {
            attr.atype.make_ascii_lowercase();
            match attr.vals.pop() {
                Some(val) => Ok((attr.atype, val)),
                None => Err(LdapError {
                    code: LdapResultCode::ConstraintViolation,
                    message: format!("Missing value for attribute {}", attr.atype),
                }),
            }
        }
    }
    let attributes: HashMap<String, Vec<u8>> = attributes
        .into_iter()
        .filter(|a| !a.atype.eq_ignore_ascii_case("objectclass"))
        .map(parse_attribute)
        .collect::<LdapResult<_>>()?;
    fn decode_attribute_value(val: &[u8]) -> LdapResult<String> {
        std::str::from_utf8(val)
            .map_err(|e| LdapError {
                code: LdapResultCode::ConstraintViolation,
                message: format!(
                    "Attribute value is invalid UTF-8: {:#?} (value {:?})",
                    e, val
                ),
            })
            .map(str::to_owned)
    }
    let get_attribute = |name| {
        attributes
            .get(name)
            .map(Vec::as_slice)
            .map(decode_attribute_value)
    };
    let make_encoded_attribute = |name: &str, typ: AttributeType, value: String| {
        Ok(Attribute {
            name: AttributeName::from(name),
            value: deserialize::deserialize_attribute_value(&[value], typ, false).map_err(|e| {
                LdapError {
                    code: LdapResultCode::ConstraintViolation,
                    message: format!("Invalid attribute value: {}", e),
                }
            })?,
        })
    };
    let mut new_user_attributes: Vec<Attribute> = Vec::new();
    if let Some(first_name) = get_attribute("givenname").transpose()? {
        new_user_attributes.push(make_encoded_attribute(
            "first_name",
            AttributeType::String,
            first_name,
        )?);
    }
    if let Some(last_name) = get_attribute("sn").transpose()? {
        new_user_attributes.push(make_encoded_attribute(
            "last_name",
            AttributeType::String,
            last_name,
        )?);
    }
    if let Some(avatar) = get_attribute("avatar").transpose()? {
        new_user_attributes.push(make_encoded_attribute(
            "avatar",
            AttributeType::JpegPhoto,
            avatar,
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
            message: format!("Could not create user: {:#?}", e),
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
            message: format!("Could not create group: {:#?}", e),
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
    use lldap_domain::types::*;
    use lldap_test_utils::MockTestBackendHandler;
    use mockall::predicate::eq;
    use pretty_assertions::assert_eq;
    

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
