use crate::{
    domain::{
        deserialize,
        ldap::{
            error::{LdapError, LdapResult},
            utils::{
                LdapInfo, UserOrGroupName, get_user_id_from_distinguished_name,
                get_user_or_group_id_from_distinguished_name, parse_distinguished_name,
            },
        },
        opaque_handler::OpaqueHandler,
    },
    infra::{
        access_control::{
            AccessControlledBackendHandler, AdminBackendHandler, UserReadableBackendHandler,
        },
        ldap::{
            password::{self, do_password_modification},
            search::{
                self, is_root_dse_request, make_search_error, make_search_request,
                make_search_success, root_dse_response,
            },
        },
    },
};
use ldap3_proto::proto::{
    LdapAddRequest, LdapAttribute, LdapBindRequest, LdapBindResponse, LdapCompareRequest,
    LdapExtendedRequest, LdapExtendedResponse, LdapFilter, LdapModify, LdapModifyRequest,
    LdapModifyType, LdapOp, LdapPartialAttribute, LdapPasswordModifyRequest,
    LdapResult as LdapResultOp, LdapResultCode, LdapSearchRequest, OID_PASSWORD_MODIFY, OID_WHOAMI,
};
use lldap_auth::access_control::ValidationResults;
use lldap_domain::{
    requests::{CreateGroupRequest, CreateUserRequest},
    types::{Attribute, AttributeName, AttributeType, Email, GroupName, UserId},
};
use lldap_domain_handlers::handler::{BackendHandler, LoginHandler};
use std::collections::HashMap;
use tracing::{debug, instrument};

fn make_add_error(code: LdapResultCode, message: String) -> LdapOp {
    LdapOp::AddResponse(LdapResultOp {
        code,
        matcheddn: "".to_string(),
        message,
        referral: vec![],
    })
}

pub(crate) fn make_extended_response(code: LdapResultCode, message: String) -> LdapOp {
    LdapOp::ExtendedResponse(LdapExtendedResponse {
        res: LdapResultOp {
            code,
            matcheddn: "".to_string(),
            message,
            referral: vec![],
        },
        name: None,
        value: None,
    })
}

pub(crate) fn make_modify_response(code: LdapResultCode, message: String) -> LdapOp {
    LdapOp::ModifyResponse(LdapResultOp {
        code,
        matcheddn: "".to_string(),
        message,
        referral: vec![],
    })
}

pub struct LdapHandler<Backend> {
    user_info: Option<ValidationResults>,
    backend_handler: AccessControlledBackendHandler<Backend>,
    ldap_info: LdapInfo,
    session_uuid: uuid::Uuid,
}

impl<Backend> LdapHandler<Backend> {
    pub fn session_uuid(&self) -> &uuid::Uuid {
        &self.session_uuid
    }
}

impl<Backend: LoginHandler> LdapHandler<Backend> {
    pub fn get_login_handler(&self) -> &(impl LoginHandler + use<Backend>) {
        self.backend_handler.unsafe_get_handler()
    }
}

impl<Backend: OpaqueHandler> LdapHandler<Backend> {
    pub fn get_opaque_handler(&self) -> &(impl OpaqueHandler + use<Backend>) {
        self.backend_handler.unsafe_get_handler()
    }
}

impl<Backend: BackendHandler + LoginHandler + OpaqueHandler> LdapHandler<Backend> {
    pub fn new(
        backend_handler: AccessControlledBackendHandler<Backend>,
        mut ldap_base_dn: String,
        ignored_user_attributes: Vec<AttributeName>,
        ignored_group_attributes: Vec<AttributeName>,
        session_uuid: uuid::Uuid,
    ) -> Self {
        ldap_base_dn.make_ascii_lowercase();
        Self {
            user_info: None,
            backend_handler,
            ldap_info: LdapInfo {
                base_dn: parse_distinguished_name(&ldap_base_dn).unwrap_or_else(|_| {
                    panic!(
                        "Invalid value for ldap_base_dn in configuration: {}",
                        ldap_base_dn
                    )
                }),
                base_dn_str: ldap_base_dn,
                ignored_user_attributes,
                ignored_group_attributes,
            },
            session_uuid,
        }
    }

    #[cfg(test)]
    pub fn new_for_tests(backend_handler: Backend, ldap_base_dn: &str) -> Self {
        Self::new(
            AccessControlledBackendHandler::new(backend_handler),
            ldap_base_dn.to_string(),
            vec![],
            vec![],
            uuid::Uuid::parse_str("550e8400-e29b-41d4-a716-446655440000").unwrap(),
        )
    }

    pub async fn do_search_or_dse(
        &mut self,
        request: &LdapSearchRequest,
    ) -> LdapResult<Vec<LdapOp>> {
        if is_root_dse_request(request) {
            debug!("rootDSE request");
            return Ok(vec![
                root_dse_response(&self.ldap_info.base_dn_str),
                make_search_success(),
            ]);
        }
        self.do_search(request).await
    }

    #[instrument(skip_all, level = "debug")]
    async fn do_search(&self, request: &LdapSearchRequest) -> LdapResult<Vec<LdapOp>> {
        let user_info = self.user_info.as_ref().ok_or_else(|| LdapError {
            code: LdapResultCode::InsufficentAccessRights,
            message: "No user currently bound".to_string(),
        })?;
        let backend_handler = self
            .backend_handler
            .get_user_restricted_lister_handler(user_info);
        search::do_search(&backend_handler, &self.ldap_info, request).await
    }

    #[instrument(skip_all, level = "debug", fields(dn = %request.dn))]
    pub async fn do_bind(&mut self, request: &LdapBindRequest) -> Vec<LdapOp> {
        let (code, message) =
            match password::do_bind(&self.ldap_info, request, self.get_login_handler()).await {
                Ok(user_id) => {
                    self.user_info = self
                        .backend_handler
                        .get_permissions_for_user(user_id)
                        .await
                        .ok();
                    debug!("Success!");
                    (LdapResultCode::Success, "".to_string())
                }
                Err(err) => (err.code, err.message),
            };
        vec![LdapOp::BindResponse(LdapBindResponse {
            res: LdapResultOp {
                code,
                matcheddn: "".to_string(),
                message,
                referral: vec![],
            },
            saslcreds: None,
        })]
    }

    #[instrument(skip_all, level = "debug")]
    async fn do_extended_request(&mut self, request: &LdapExtendedRequest) -> Vec<LdapOp> {
        match request.name.as_str() {
            OID_PASSWORD_MODIFY => match LdapPasswordModifyRequest::try_from(request) {
                Ok(password_request) => {
                    let credentials = match self.user_info.as_ref() {
                        Some(user_id) => user_id,
                        None => {
                            return vec![make_extended_response(
                                LdapResultCode::InsufficentAccessRights,
                                "No user currently bound".to_string(),
                            )];
                        }
                    };
                    do_password_modification(
                        credentials,
                        &self.ldap_info,
                        &self.backend_handler,
                        self.get_opaque_handler(),
                        &password_request,
                    )
                    .await
                    .unwrap_or_else(|e: LdapError| vec![make_extended_response(e.code, e.message)])
                }
                Err(e) => vec![make_extended_response(
                    LdapResultCode::ProtocolError,
                    format!("Error while parsing password modify request: {:#?}", e),
                )],
            },
            OID_WHOAMI => {
                let authz_id = self
                    .user_info
                    .as_ref()
                    .map(|user_info| {
                        format!(
                            "dn:uid={},ou=people,{}",
                            user_info.user.as_str(),
                            self.ldap_info.base_dn_str
                        )
                    })
                    .unwrap_or_default();
                vec![make_extended_response(LdapResultCode::Success, authz_id)]
            }
            _ => vec![make_extended_response(
                LdapResultCode::UnwillingToPerform,
                format!("Unsupported extended operation: {}", &request.name),
            )],
        }
    }

    async fn handle_modify_change(
        &mut self,
        user_id: UserId,
        credentials: &ValidationResults,
        user_is_admin: bool,
        change: &LdapModify,
    ) -> LdapResult<()> {
        if !change
            .modification
            .atype
            .eq_ignore_ascii_case("userpassword")
            || change.operation != LdapModifyType::Replace
        {
            return Err(LdapError {
                code: LdapResultCode::UnwillingToPerform,
                message: format!(
                    r#"Unsupported operation: `{:?}` for `{}`"#,
                    change.operation, change.modification.atype
                ),
            });
        }
        if !credentials.can_change_password(&user_id, user_is_admin) {
            return Err(LdapError {
                code: LdapResultCode::InsufficentAccessRights,
                message: format!(
                    r#"User `{}` cannot modify the password of user `{}`"#,
                    &credentials.user, &user_id
                ),
            });
        }
        if let [value] = &change.modification.vals.as_slice() {
            password::change_password(self.get_opaque_handler(), user_id, value)
                .await
                .map_err(|e| LdapError {
                    code: LdapResultCode::Other,
                    message: format!("Error while changing the password: {:#?}", e),
                })?;
        } else {
            return Err(LdapError {
                code: LdapResultCode::InvalidAttributeSyntax,
                message: format!(
                    r#"Wrong number of values for password attribute: {}"#,
                    change.modification.vals.len()
                ),
            });
        }
        Ok(())
    }

    async fn handle_modify_request(
        &mut self,
        request: &LdapModifyRequest,
    ) -> LdapResult<Vec<LdapOp>> {
        let credentials = self
            .user_info
            .as_ref()
            .ok_or_else(|| LdapError {
                code: LdapResultCode::InsufficentAccessRights,
                message: "No user currently bound".to_string(),
            })?
            .clone();
        match get_user_id_from_distinguished_name(
            &request.dn,
            &self.ldap_info.base_dn,
            &self.ldap_info.base_dn_str,
        ) {
            Ok(uid) => {
                let user_is_admin = self
                    .backend_handler
                    .get_readable_handler(&credentials, &uid)
                    .expect("Unexpected permission error")
                    .get_user_groups(&uid)
                    .await
                    .map_err(|e| LdapError {
                        code: LdapResultCode::OperationsError,
                        message: format!("Internal error while requesting user's groups: {:#?}", e),
                    })?
                    .iter()
                    .any(|g| g.display_name == "lldap_admin".into());
                for change in &request.changes {
                    self.handle_modify_change(uid.clone(), &credentials, user_is_admin, change)
                        .await?
                }
                Ok(vec![make_modify_response(
                    LdapResultCode::Success,
                    String::new(),
                )])
            }
            Err(e) => Err(LdapError {
                code: LdapResultCode::InvalidDNSyntax,
                message: format!("Invalid username: {}", e),
            }),
        }
    }

    #[instrument(skip_all, level = "debug", fields(dn = %request.dn))]
    async fn do_modify_request(&mut self, request: &LdapModifyRequest) -> Vec<LdapOp> {
        self.handle_modify_request(request)
            .await
            .unwrap_or_else(|e: LdapError| vec![make_modify_response(e.code, e.message)])
    }

    #[instrument(skip_all, level = "debug")]
    async fn do_create_user_or_group(&self, request: LdapAddRequest) -> LdapResult<Vec<LdapOp>> {
        let backend_handler = self
            .user_info
            .as_ref()
            .and_then(|u| self.backend_handler.get_admin_handler(u))
            .ok_or_else(|| LdapError {
                code: LdapResultCode::InsufficentAccessRights,
                message: "Unauthorized write".to_string(),
            })?;
        let base_dn_str = &self.ldap_info.base_dn_str;
        match get_user_or_group_id_from_distinguished_name(&request.dn, &self.ldap_info.base_dn) {
            UserOrGroupName::User(user_id) => {
                self.do_create_user(backend_handler, user_id, request.attributes)
                    .await
            }
            UserOrGroupName::Group(group_name) => {
                self.do_create_group(backend_handler, group_name, request.attributes)
                    .await
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
    async fn do_create_user(
        &self,
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
                value: deserialize::deserialize_attribute_value(&[value], typ, false).map_err(
                    |e| LdapError {
                        code: LdapResultCode::ConstraintViolation,
                        message: format!("Invalid attribute value: {}", e),
                    },
                )?,
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
        Ok(vec![make_add_error(LdapResultCode::Success, String::new())])
    }

    #[instrument(skip_all, level = "debug")]
    async fn do_create_group(
        &self,
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
        Ok(vec![make_add_error(LdapResultCode::Success, String::new())])
    }

    #[instrument(skip_all, level = "debug")]
    pub async fn do_compare(&mut self, request: LdapCompareRequest) -> LdapResult<Vec<LdapOp>> {
        let req = make_search_request::<String>(
            &self.ldap_info.base_dn_str,
            LdapFilter::Equality("dn".to_string(), request.dn.to_string()),
            vec![request.atype.clone()],
        );
        let entries = self.do_search(&req).await?;
        if entries.len() > 2 {
            // SearchResultEntry + SearchResultDone
            return Err(LdapError {
                code: LdapResultCode::OperationsError,
                message: "Too many search results".to_string(),
            });
        }
        let requested_attribute = AttributeName::from(&request.atype);
        match entries.first() {
            Some(LdapOp::SearchResultEntry(entry)) => {
                let available = entry.attributes.iter().any(|attr| {
                    AttributeName::from(&attr.atype) == requested_attribute
                        && attr.vals.contains(&request.val)
                });
                Ok(vec![LdapOp::CompareResult(LdapResultOp {
                    code: if available {
                        LdapResultCode::CompareTrue
                    } else {
                        LdapResultCode::CompareFalse
                    },
                    matcheddn: request.dn,
                    message: "".to_string(),
                    referral: vec![],
                })])
            }
            Some(LdapOp::SearchResultDone(_)) => Ok(vec![LdapOp::CompareResult(LdapResultOp {
                code: LdapResultCode::NoSuchObject,
                matcheddn: self.ldap_info.base_dn_str.clone(),
                message: "".to_string(),
                referral: vec![],
            })]),
            None => Err(LdapError {
                code: LdapResultCode::OperationsError,
                message: "Search request returned nothing".to_string(),
            }),
            _ => Err(LdapError {
                code: LdapResultCode::OperationsError,
                message: "Unexpected results from search".to_string(),
            }),
        }
    }

    pub async fn handle_ldap_message(&mut self, ldap_op: LdapOp) -> Option<Vec<LdapOp>> {
        Some(match ldap_op {
            LdapOp::BindRequest(request) => self.do_bind(&request).await,
            LdapOp::SearchRequest(request) => self
                .do_search_or_dse(&request)
                .await
                .unwrap_or_else(|e: LdapError| vec![make_search_error(e.code, e.message)]),
            LdapOp::UnbindRequest => {
                debug!(
                    "Unbind request for {}",
                    self.user_info
                        .as_ref()
                        .map(|u| u.user.as_str())
                        .unwrap_or("<not bound>"),
                );
                self.user_info = None;
                // No need to notify on unbind (per rfc4511)
                return None;
            }
            LdapOp::ModifyRequest(request) => self.do_modify_request(&request).await,
            LdapOp::ExtendedRequest(request) => self.do_extended_request(&request).await,
            LdapOp::AddRequest(request) => self
                .do_create_user_or_group(request)
                .await
                .unwrap_or_else(|e: LdapError| vec![make_add_error(e.code, e.message)]),
            LdapOp::CompareRequest(request) => self
                .do_compare(request)
                .await
                .unwrap_or_else(|e: LdapError| vec![make_search_error(e.code, e.message)]),
            op => vec![make_extended_response(
                LdapResultCode::UnwillingToPerform,
                format!("Unsupported operation: {:#?}", op),
            )],
        })
    }
}

#[cfg(test)]
pub mod tests {
    use super::*;
    use crate::infra::{
        ldap::password::tests::make_bind_success,
        test_utils::{MockTestBackendHandler, setup_default_schema},
    };
    use chrono::TimeZone;
    use ldap3_proto::proto::{LdapBindCred, LdapWhoamiRequest};
    use lldap_domain::{types::*, uuid};
    use lldap_domain_handlers::handler::*;
    use mockall::predicate::eq;
    use pretty_assertions::assert_eq;
    use std::collections::HashSet;
    use tokio;

    pub fn make_user_search_request<S: Into<String>>(
        filter: LdapFilter,
        attrs: Vec<S>,
    ) -> LdapSearchRequest {
        make_search_request::<S>("ou=people,Dc=example,dc=com", filter, attrs)
    }

    pub fn make_group_search_request<S: Into<String>>(
        filter: LdapFilter,
        attrs: Vec<S>,
    ) -> LdapSearchRequest {
        make_search_request::<S>("ou=groups,dc=example,dc=com", filter, attrs)
    }

    pub async fn setup_bound_handler_with_group(
        mut mock: MockTestBackendHandler,
        group: &str,
    ) -> LdapHandler<MockTestBackendHandler> {
        mock.expect_bind()
            .with(eq(BindRequest {
                name: UserId::new("test"),
                password: "pass".to_string(),
            }))
            .return_once(|_| Ok(()));
        let group = group.to_string();
        mock.expect_get_user_groups()
            .with(eq(UserId::new("test")))
            .return_once(|_| {
                let mut set = HashSet::new();
                set.insert(GroupDetails {
                    group_id: GroupId(42),
                    display_name: group.into(),
                    creation_date: chrono::Utc.timestamp_opt(42, 42).unwrap().naive_utc(),
                    uuid: uuid!("a1a2a3a4b1b2c1c2d1d2d3d4d5d6d7d8"),
                    attributes: Vec::new(),
                });
                Ok(set)
            });
        setup_default_schema(&mut mock);
        let mut ldap_handler = LdapHandler::new_for_tests(mock, "dc=Example,dc=com");
        let request = LdapBindRequest {
            dn: "uid=test,ou=people,dc=example,dc=coM".to_string(),
            cred: LdapBindCred::Simple("pass".to_string()),
        };
        assert_eq!(ldap_handler.do_bind(&request).await, make_bind_success());
        ldap_handler
    }

    pub async fn setup_bound_readonly_handler(
        mock: MockTestBackendHandler,
    ) -> LdapHandler<MockTestBackendHandler> {
        setup_bound_handler_with_group(mock, "lldap_strict_readonly").await
    }

    pub async fn setup_bound_password_manager_handler(
        mock: MockTestBackendHandler,
    ) -> LdapHandler<MockTestBackendHandler> {
        setup_bound_handler_with_group(mock, "lldap_password_manager").await
    }

    pub async fn setup_bound_admin_handler(
        mock: MockTestBackendHandler,
    ) -> LdapHandler<MockTestBackendHandler> {
        setup_bound_handler_with_group(mock, "lldap_admin").await
    }

    #[tokio::test]
    async fn test_whoami_empty() {
        let mut ldap_handler =
            LdapHandler::new_for_tests(MockTestBackendHandler::new(), "dc=example,dc=com");
        let request = LdapOp::ExtendedRequest(LdapWhoamiRequest {}.into());
        assert_eq!(
            ldap_handler.handle_ldap_message(request).await,
            Some(vec![make_extended_response(
                LdapResultCode::Success,
                "".to_string(),
            )])
        );
    }

    #[tokio::test]
    async fn test_whoami_bound() {
        let mock = MockTestBackendHandler::new();
        let mut ldap_handler = setup_bound_admin_handler(mock).await;
        let request = LdapOp::ExtendedRequest(LdapWhoamiRequest {}.into());
        assert_eq!(
            ldap_handler.handle_ldap_message(request).await,
            Some(vec![make_extended_response(
                LdapResultCode::Success,
                "dn:uid=test,ou=people,dc=example,dc=com".to_string(),
            )])
        );
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
            ldap_handler.do_create_user_or_group(request).await,
            Ok(vec![make_add_error(LdapResultCode::Success, String::new())])
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
            ldap_handler.do_create_user_or_group(request).await,
            Ok(vec![make_add_error(LdapResultCode::Success, String::new())])
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
            ldap_handler.do_create_user_or_group(request).await,
            Ok(vec![make_add_error(LdapResultCode::Success, String::new())])
        );
    }

    #[tokio::test]
    async fn test_compare_user() {
        let mut mock = MockTestBackendHandler::new();
        mock.expect_list_users().returning(|f, g| {
            assert_eq!(f, Some(UserRequestFilter::UserId(UserId::new("bob"))));
            assert!(!g);
            Ok(vec![UserAndGroups {
                user: User {
                    user_id: UserId::new("bob"),
                    email: "bob@bobmail.bob".into(),
                    ..Default::default()
                },
                groups: None,
            }])
        });
        mock.expect_list_groups().returning(|_| Ok(vec![]));
        let mut ldap_handler = setup_bound_admin_handler(mock).await;
        let dn = "uid=bob,ou=people,dc=example,dc=com";
        let request = LdapCompareRequest {
            dn: dn.to_string(),
            atype: "uid".to_owned(),
            val: b"bob".to_vec(),
        };
        assert_eq!(
            ldap_handler.do_compare(request).await,
            Ok(vec![LdapOp::CompareResult(LdapResultOp {
                code: LdapResultCode::CompareTrue,
                matcheddn: dn.to_string(),
                message: "".to_string(),
                referral: vec![],
            })])
        );
        // Non-canonical attribute.
        let request = LdapCompareRequest {
            dn: dn.to_string(),
            atype: "eMail".to_owned(),
            val: b"bob@bobmail.bob".to_vec(),
        };
        assert_eq!(
            ldap_handler.do_compare(request).await,
            Ok(vec![LdapOp::CompareResult(LdapResultOp {
                code: LdapResultCode::CompareTrue,
                matcheddn: dn.to_string(),
                message: "".to_string(),
                referral: vec![],
            })])
        );
    }

    #[tokio::test]
    async fn test_compare_group() {
        let mut mock = MockTestBackendHandler::new();
        mock.expect_list_users().returning(|_, _| Ok(vec![]));
        mock.expect_list_groups().returning(|f| {
            assert_eq!(f, Some(GroupRequestFilter::DisplayName("group".into())));
            Ok(vec![Group {
                id: GroupId(1),
                display_name: "group".into(),
                creation_date: chrono::Utc.timestamp_opt(42, 42).unwrap().naive_utc(),
                users: vec![UserId::new("bob")],
                uuid: uuid!("04ac75e0-2900-3e21-926c-2f732c26b3fc"),
                attributes: Vec::new(),
            }])
        });
        let mut ldap_handler = setup_bound_admin_handler(mock).await;
        let dn = "uid=group,ou=groups,dc=example,dc=com";
        let request = LdapCompareRequest {
            dn: dn.to_string(),
            atype: "uid".to_owned(),
            val: b"group".to_vec(),
        };
        assert_eq!(
            ldap_handler.do_compare(request).await,
            Ok(vec![LdapOp::CompareResult(LdapResultOp {
                code: LdapResultCode::CompareTrue,
                matcheddn: dn.to_string(),
                message: "".to_string(),
                referral: vec![],
            })])
        );
    }

    #[tokio::test]
    async fn test_compare_not_found() {
        let mut mock = MockTestBackendHandler::new();
        mock.expect_list_users().returning(|f, g| {
            assert_eq!(f, Some(UserRequestFilter::UserId(UserId::new("bob"))));
            assert!(!g);
            Ok(vec![])
        });
        mock.expect_list_groups().returning(|_| Ok(vec![]));
        let mut ldap_handler = setup_bound_admin_handler(mock).await;
        let dn = "uid=bob,ou=people,dc=example,dc=com";
        let request = LdapCompareRequest {
            dn: dn.to_string(),
            atype: "uid".to_owned(),
            val: b"bob".to_vec(),
        };
        assert_eq!(
            ldap_handler.do_compare(request).await,
            Ok(vec![LdapOp::CompareResult(LdapResultOp {
                code: LdapResultCode::NoSuchObject,
                matcheddn: "dc=example,dc=com".to_owned(),
                message: "".to_string(),
                referral: vec![],
            })])
        );
    }

    #[tokio::test]
    async fn test_compare_no_match() {
        let mut mock = MockTestBackendHandler::new();
        mock.expect_list_users().returning(|f, g| {
            assert_eq!(f, Some(UserRequestFilter::UserId(UserId::new("bob"))));
            assert!(!g);
            Ok(vec![UserAndGroups {
                user: User {
                    user_id: UserId::new("bob"),
                    email: "bob@bobmail.bob".into(),
                    ..Default::default()
                },
                groups: None,
            }])
        });
        mock.expect_list_groups().returning(|_| Ok(vec![]));
        let mut ldap_handler = setup_bound_admin_handler(mock).await;
        let dn = "uid=bob,ou=people,dc=example,dc=com";
        let request = LdapCompareRequest {
            dn: dn.to_string(),
            atype: "mail".to_owned(),
            val: b"bob@bob".to_vec(),
        };
        assert_eq!(
            ldap_handler.do_compare(request).await,
            Ok(vec![LdapOp::CompareResult(LdapResultOp {
                code: LdapResultCode::CompareFalse,
                matcheddn: dn.to_string(),
                message: "".to_string(),
                referral: vec![],
            })])
        );
    }

    #[tokio::test]
    async fn test_compare_group_member() {
        let mut mock = MockTestBackendHandler::new();
        mock.expect_list_users().returning(|_, _| Ok(vec![]));
        mock.expect_list_groups().returning(|f| {
            assert_eq!(f, Some(GroupRequestFilter::DisplayName("group".into())));
            Ok(vec![Group {
                id: GroupId(1),
                display_name: "group".into(),
                creation_date: chrono::Utc.timestamp_opt(42, 42).unwrap().naive_utc(),
                users: vec![UserId::new("bob")],
                uuid: uuid!("04ac75e0-2900-3e21-926c-2f732c26b3fc"),
                attributes: Vec::new(),
            }])
        });
        let mut ldap_handler = setup_bound_admin_handler(mock).await;
        let dn = "uid=group,ou=groups,dc=example,dc=com";
        let request = LdapCompareRequest {
            dn: dn.to_string(),
            atype: "uniqueMember".to_owned(),
            val: b"uid=bob,ou=people,dc=example,dc=com".to_vec(),
        };
        assert_eq!(
            ldap_handler.do_compare(request).await,
            Ok(vec![LdapOp::CompareResult(LdapResultOp {
                code: LdapResultCode::CompareTrue,
                matcheddn: dn.to_owned(),
                message: "".to_string(),
                referral: vec![],
            })])
        );
    }
}
