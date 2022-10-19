use crate::{
    domain::{
        handler::{BackendHandler, BindRequest, LoginHandler, UserId},
        ldap::{
            error::{LdapError, LdapResult},
            group::get_groups_list,
            user::get_user_list,
            utils::{
                get_user_id_from_distinguished_name, is_subtree, parse_distinguished_name, LdapInfo,
            },
        },
        opaque_handler::OpaqueHandler,
    },
    infra::auth_service::{Permission, ValidationResults},
};
use anyhow::Result;
use ldap3_proto::proto::{
    LdapBindCred, LdapBindRequest, LdapBindResponse, LdapExtendedRequest, LdapExtendedResponse,
    LdapFilter, LdapOp, LdapPartialAttribute, LdapPasswordModifyRequest,
    LdapResult as LdapResultOp, LdapResultCode, LdapSearchRequest, LdapSearchResultEntry,
    LdapSearchScope,
};
use tracing::{debug, instrument, warn};

#[derive(Debug, PartialEq, Eq, Clone)]
struct LdapDn(String);

#[derive(Debug)]
enum SearchScope {
    Global,
    Users,
    Groups,
    User(LdapFilter),
    Group(LdapFilter),
    Unknown,
    Invalid,
}

fn get_search_scope(base_dn: &[(String, String)], dn_parts: &[(String, String)]) -> SearchScope {
    let base_dn_len = base_dn.len();
    if !is_subtree(dn_parts, base_dn) {
        SearchScope::Invalid
    } else if dn_parts.len() == base_dn_len {
        SearchScope::Global
    } else if dn_parts.len() == base_dn_len + 1
        && dn_parts[0] == ("ou".to_string(), "people".to_string())
    {
        SearchScope::Users
    } else if dn_parts.len() == base_dn_len + 1
        && dn_parts[0] == ("ou".to_string(), "groups".to_string())
    {
        SearchScope::Groups
    } else if dn_parts.len() == base_dn_len + 2
        && dn_parts[1] == ("ou".to_string(), "people".to_string())
    {
        SearchScope::User(LdapFilter::Equality(
            dn_parts[0].0.clone(),
            dn_parts[0].1.clone(),
        ))
    } else if dn_parts.len() == base_dn_len + 2
        && dn_parts[1] == ("ou".to_string(), "groups".to_string())
    {
        SearchScope::Group(LdapFilter::Equality(
            dn_parts[0].0.clone(),
            dn_parts[0].1.clone(),
        ))
    } else {
        SearchScope::Unknown
    }
}

fn make_search_success() -> LdapOp {
    make_search_error(LdapResultCode::Success, "".to_string())
}

fn make_search_error(code: LdapResultCode, message: String) -> LdapOp {
    LdapOp::SearchResultDone(LdapResultOp {
        code,
        matcheddn: "".to_string(),
        message,
        referral: vec![],
    })
}

fn make_extended_response(code: LdapResultCode, message: String) -> LdapOp {
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

fn root_dse_response(base_dn: &str) -> LdapOp {
    LdapOp::SearchResultEntry(LdapSearchResultEntry {
        dn: "".to_string(),
        attributes: vec![
            LdapPartialAttribute {
                atype: "objectClass".to_string(),
                vals: vec![b"top".to_vec()],
            },
            LdapPartialAttribute {
                atype: "vendorName".to_string(),
                vals: vec![b"LLDAP".to_vec()],
            },
            LdapPartialAttribute {
                atype: "vendorVersion".to_string(),
                vals: vec![concat!("lldap_", env!("CARGO_PKG_VERSION"))
                    .to_string()
                    .into_bytes()],
            },
            LdapPartialAttribute {
                atype: "supportedLDAPVersion".to_string(),
                vals: vec![b"3".to_vec()],
            },
            LdapPartialAttribute {
                atype: "supportedExtension".to_string(),
                // Password modification extension.
                vals: vec![b"1.3.6.1.4.1.4203.1.11.1".to_vec()],
            },
            LdapPartialAttribute {
                atype: "supportedControl".to_string(),
                vals: vec![],
            },
            LdapPartialAttribute {
                atype: "supportedFeatures".to_string(),
                // Attribute "+"
                vals: vec![b"1.3.6.1.4.1.4203.1.5.1".to_vec()],
            },
            LdapPartialAttribute {
                atype: "defaultNamingContext".to_string(),
                vals: vec![base_dn.to_string().into_bytes()],
            },
            LdapPartialAttribute {
                atype: "namingContexts".to_string(),
                vals: vec![base_dn.to_string().into_bytes()],
            },
            LdapPartialAttribute {
                atype: "isGlobalCatalogReady".to_string(),
                vals: vec![b"false".to_vec()],
            },
        ],
    })
}

pub struct LdapHandler<Backend: BackendHandler + LoginHandler + OpaqueHandler> {
    user_info: Option<ValidationResults>,
    backend_handler: Backend,
    ldap_info: LdapInfo,
}

impl<Backend: BackendHandler + LoginHandler + OpaqueHandler> LdapHandler<Backend> {
    pub fn new(
        backend_handler: Backend,
        mut ldap_base_dn: String,
        ignored_user_attributes: Vec<String>,
        ignored_group_attributes: Vec<String>,
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
        }
    }

    #[instrument(skip_all, level = "debug")]
    pub async fn do_bind(&mut self, request: &LdapBindRequest) -> (LdapResultCode, String) {
        debug!("DN: {}", &request.dn);
        let user_id = match get_user_id_from_distinguished_name(
            &request.dn.to_ascii_lowercase(),
            &self.ldap_info.base_dn,
            &self.ldap_info.base_dn_str,
        ) {
            Ok(s) => s,
            Err(e) => return (LdapResultCode::NamingViolation, e.to_string()),
        };
        let LdapBindCred::Simple(password) = &request.cred;
        match self
            .backend_handler
            .bind(BindRequest {
                name: user_id.clone(),
                password: password.clone(),
            })
            .await
        {
            Ok(()) => {
                let user_groups = self.backend_handler.get_user_groups(&user_id).await;
                let is_in_group = |name| {
                    user_groups
                        .as_ref()
                        .map(|groups| groups.iter().any(|g| g.display_name == name))
                        .unwrap_or(false)
                };
                self.user_info = Some(ValidationResults {
                    user: user_id,
                    permission: if is_in_group("lldap_admin") {
                        Permission::Admin
                    } else if is_in_group("lldap_password_manager") {
                        Permission::PasswordManager
                    } else if is_in_group("lldap_strict_readonly") {
                        Permission::Readonly
                    } else {
                        Permission::Regular
                    },
                });
                debug!("Success!");
                (LdapResultCode::Success, "".to_string())
            }
            Err(_) => (LdapResultCode::InvalidCredentials, "".to_string()),
        }
    }

    async fn change_password(&mut self, user: &UserId, password: &str) -> Result<()> {
        use lldap_auth::*;
        let mut rng = rand::rngs::OsRng;
        let registration_start_request =
            opaque::client::registration::start_registration(password, &mut rng)?;
        let req = registration::ClientRegistrationStartRequest {
            username: user.to_string(),
            registration_start_request: registration_start_request.message,
        };
        let registration_start_response = self.backend_handler.registration_start(req).await?;
        let registration_finish = opaque::client::registration::finish_registration(
            registration_start_request.state,
            registration_start_response.registration_response,
            &mut rng,
        )?;
        let req = registration::ClientRegistrationFinishRequest {
            server_data: registration_start_response.server_data,
            registration_upload: registration_finish.message,
        };
        self.backend_handler.registration_finish(req).await?;
        Ok(())
    }

    async fn do_password_modification(
        &mut self,
        request: &LdapPasswordModifyRequest,
    ) -> LdapResult<Vec<LdapOp>> {
        let credentials = self.user_info.as_ref().ok_or_else(|| LdapError {
            code: LdapResultCode::InsufficentAccessRights,
            message: "No user currently bound".to_string(),
        })?;
        match (&request.user_identity, &request.new_password) {
            (Some(user), Some(password)) => {
                match get_user_id_from_distinguished_name(
                    user,
                    &self.ldap_info.base_dn,
                    &self.ldap_info.base_dn_str,
                ) {
                    Ok(uid) => {
                        let user_is_admin = self
                            .backend_handler
                            .get_user_groups(&uid)
                            .await
                            .map_err(|e| LdapError {
                                code: LdapResultCode::OperationsError,
                                message: format!(
                                    "Internal error while requesting user's groups: {:#?}",
                                    e
                                ),
                            })?
                            .iter()
                            .any(|g| g.display_name == "lldap_admin");
                        if !credentials.can_change_password(&uid, user_is_admin) {
                            Err(LdapError {
                                code: LdapResultCode::InsufficentAccessRights,
                                message: format!(
                                    r#"User `{}` cannot modify the password of user `{}`"#,
                                    &credentials.user, &uid
                                ),
                            })
                        } else if let Err(e) = self.change_password(&uid, password).await {
                            Err(LdapError {
                                code: LdapResultCode::Other,
                                message: format!("Error while changing the password: {:#?}", e),
                            })
                        } else {
                            Ok(vec![make_extended_response(
                                LdapResultCode::Success,
                                "".to_string(),
                            )])
                        }
                    }
                    Err(e) => Err(LdapError {
                        code: LdapResultCode::InvalidDNSyntax,
                        message: format!("Invalid username: {}", e),
                    }),
                }
            }
            _ => Err(LdapError {
                code: LdapResultCode::ConstraintViolation,
                message: "Missing either user_id or password".to_string(),
            }),
        }
    }

    async fn do_extended_request(&mut self, request: &LdapExtendedRequest) -> Vec<LdapOp> {
        match LdapPasswordModifyRequest::try_from(request) {
            Ok(password_request) => self
                .do_password_modification(&password_request)
                .await
                .unwrap_or_else(|e: LdapError| vec![make_extended_response(e.code, e.message)]),
            Err(_) => vec![make_extended_response(
                LdapResultCode::UnwillingToPerform,
                format!("Unsupported extended operation: {}", &request.name),
            )],
        }
    }

    pub async fn do_search_or_dse(
        &mut self,
        request: &LdapSearchRequest,
    ) -> LdapResult<Vec<LdapOp>> {
        if request.base.is_empty() && request.scope == LdapSearchScope::Base {
            if let LdapFilter::Present(attribute) = &request.filter {
                if attribute.to_ascii_lowercase() == "objectclass" {
                    debug!("rootDSE request");
                    return Ok(vec![
                        root_dse_response(&self.ldap_info.base_dn_str),
                        make_search_success(),
                    ]);
                }
            }
        }
        let user_info = self.user_info.as_ref().ok_or_else(|| LdapError {
            code: LdapResultCode::InsufficentAccessRights,
            message: "No user currently bound".to_string(),
        })?;
        let user_filter = if user_info.is_admin_or_readonly() {
            None
        } else {
            Some(user_info.user.clone())
        };
        self.do_search(request, user_filter).await
    }

    #[instrument(skip_all, level = "debug")]
    pub async fn do_search(
        &mut self,
        request: &LdapSearchRequest,
        user_filter: Option<UserId>,
    ) -> LdapResult<Vec<LdapOp>> {
        let user_filter = user_filter.as_ref();
        let dn_parts = parse_distinguished_name(&request.base.to_ascii_lowercase())?;
        let scope = get_search_scope(&self.ldap_info.base_dn, &dn_parts);
        debug!(?request.base, ?scope);
        // Disambiguate the lifetimes.
        fn cast<T, R, B: 'a, 'a>(x: T) -> T
        where
            T: Fn(&'a mut B, &'a LdapFilter) -> R + 'a,
        {
            x
        }

        let get_user_list = cast(|backend_handler: &mut Backend, filter: &LdapFilter| async {
            get_user_list(
                &self.ldap_info,
                filter,
                &request.attrs,
                &request.base,
                &user_filter,
                backend_handler,
            )
            .await
        });
        let get_group_list = cast(|backend_handler: &mut Backend, filter: &LdapFilter| async {
            get_groups_list(
                &self.ldap_info,
                filter,
                &request.attrs,
                &request.base,
                &user_filter,
                backend_handler,
            )
            .await
        });
        let mut results: Vec<_> = match scope {
            SearchScope::Global => {
                let mut results = Vec::new();
                results.extend(get_user_list(&mut self.backend_handler, &request.filter).await?);
                results.extend(get_group_list(&mut self.backend_handler, &request.filter).await?);
                results
            }
            SearchScope::Users => get_user_list(&mut self.backend_handler, &request.filter).await?,
            SearchScope::Groups => {
                get_group_list(&mut self.backend_handler, &request.filter).await?
            }
            SearchScope::User(filter) => {
                let filter = LdapFilter::And(vec![request.filter.clone(), filter]);
                get_user_list(&mut self.backend_handler, &filter).await?
            }
            SearchScope::Group(filter) => {
                let filter = LdapFilter::And(vec![request.filter.clone(), filter]);
                get_group_list(&mut self.backend_handler, &filter).await?
            }
            SearchScope::Unknown => {
                warn!(
                    r#"The requested search tree "{}" matches neither the user subtree "ou=people,{}" nor the group subtree "ou=groups,{}""#,
                    &request.base, &self.ldap_info.base_dn_str, &self.ldap_info.base_dn_str
                );
                Vec::new()
            }
            SearchScope::Invalid => {
                // Search path is not in our tree, just return an empty success.
                warn!(
                    "The specified search tree {:?} is not under the common subtree {:?}",
                    &dn_parts, &self.ldap_info.base_dn
                );
                Vec::new()
            }
        };
        if results.is_empty() || matches!(results[results.len() - 1], LdapOp::SearchResultEntry(_))
        {
            results.push(make_search_success());
        }
        Ok(results)
    }

    pub async fn handle_ldap_message(&mut self, ldap_op: LdapOp) -> Option<Vec<LdapOp>> {
        Some(match ldap_op {
            LdapOp::BindRequest(request) => {
                let (code, message) = self.do_bind(&request).await;
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
            LdapOp::SearchRequest(request) => self
                .do_search_or_dse(&request)
                .await
                .unwrap_or_else(|e: LdapError| vec![make_search_error(e.code, e.message)]),
            LdapOp::UnbindRequest => {
                self.user_info = None;
                // No need to notify on unbind (per rfc4511)
                return None;
            }
            LdapOp::ExtendedRequest(request) => self.do_extended_request(&request).await,
            op => vec![make_extended_response(
                LdapResultCode::UnwillingToPerform,
                format!("Unsupported operation: {:#?}", op),
            )],
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        domain::{error::Result, handler::*, opaque_handler::*, sql_tables::UserColumn},
        uuid,
    };
    use async_trait::async_trait;
    use chrono::TimeZone;
    use ldap3_proto::proto::{LdapDerefAliases, LdapSearchScope};
    use mockall::predicate::eq;
    use std::collections::HashSet;
    use tokio;

    mockall::mock! {
        pub TestBackendHandler{}
        impl Clone for TestBackendHandler {
            fn clone(&self) -> Self;
        }
        #[async_trait]
        impl LoginHandler for TestBackendHandler {
            async fn bind(&self, request: BindRequest) -> Result<()>;
        }
        #[async_trait]
        impl GroupBackendHandler for TestBackendHandler {
            async fn list_groups(&self, filters: Option<GroupRequestFilter>) -> Result<Vec<Group>>;
            async fn get_group_details(&self, group_id: GroupId) -> Result<GroupDetails>;
            async fn update_group(&self, request: UpdateGroupRequest) -> Result<()>;
            async fn create_group(&self, group_name: &str) -> Result<GroupId>;
            async fn delete_group(&self, group_id: GroupId) -> Result<()>;
        }
        #[async_trait]
        impl UserBackendHandler for TestBackendHandler {
            async fn list_users(&self, filters: Option<UserRequestFilter>, get_groups: bool) -> Result<Vec<UserAndGroups>>;
            async fn get_user_details(&self, user_id: &UserId) -> Result<User>;
            async fn create_user(&self, request: CreateUserRequest) -> Result<()>;
            async fn update_user(&self, request: UpdateUserRequest) -> Result<()>;
            async fn delete_user(&self, user_id: &UserId) -> Result<()>;
            async fn get_user_groups(&self, user_id: &UserId) -> Result<HashSet<GroupDetails>>;
            async fn add_user_to_group(&self, user_id: &UserId, group_id: GroupId) -> Result<()>;
            async fn remove_user_from_group(&self, user_id: &UserId, group_id: GroupId) -> Result<()>;
        }
        #[async_trait]
        impl BackendHandler for TestBackendHandler {}
        #[async_trait]
        impl OpaqueHandler for TestBackendHandler {
            async fn login_start(
                &self,
                request: login::ClientLoginStartRequest
            ) -> Result<login::ServerLoginStartResponse>;
            async fn login_finish(&self, request: login::ClientLoginFinishRequest) -> Result<UserId>;
            async fn registration_start(
                &self,
                request: registration::ClientRegistrationStartRequest
            ) -> Result<registration::ServerRegistrationStartResponse>;
            async fn registration_finish(
                &self,
                request: registration::ClientRegistrationFinishRequest
            ) -> Result<()>;
        }
    }

    fn make_search_request<S: Into<String>>(
        base: &str,
        filter: LdapFilter,
        attrs: Vec<S>,
    ) -> LdapSearchRequest {
        LdapSearchRequest {
            base: base.to_string(),
            scope: LdapSearchScope::Base,
            aliases: LdapDerefAliases::Never,
            sizelimit: 0,
            timelimit: 0,
            typesonly: false,
            filter,
            attrs: attrs.into_iter().map(Into::into).collect(),
        }
    }

    fn make_user_search_request<S: Into<String>>(
        filter: LdapFilter,
        attrs: Vec<S>,
    ) -> LdapSearchRequest {
        make_search_request::<S>("ou=people,Dc=example,dc=com", filter, attrs)
    }

    async fn setup_bound_handler_with_group(
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
                    display_name: group,
                    creation_date: chrono::Utc.timestamp(42, 42),
                    uuid: uuid!("a1a2a3a4b1b2c1c2d1d2d3d4d5d6d7d8"),
                });
                Ok(set)
            });
        let mut ldap_handler =
            LdapHandler::new(mock, "dc=Example,dc=com".to_string(), vec![], vec![]);
        let request = LdapBindRequest {
            dn: "uid=test,ou=people,dc=example,dc=coM".to_string(),
            cred: LdapBindCred::Simple("pass".to_string()),
        };
        assert_eq!(
            ldap_handler.do_bind(&request).await.0,
            LdapResultCode::Success
        );
        ldap_handler
    }

    async fn setup_bound_readonly_handler(
        mock: MockTestBackendHandler,
    ) -> LdapHandler<MockTestBackendHandler> {
        setup_bound_handler_with_group(mock, "lldap_strict_readonly").await
    }

    async fn setup_bound_password_manager_handler(
        mock: MockTestBackendHandler,
    ) -> LdapHandler<MockTestBackendHandler> {
        setup_bound_handler_with_group(mock, "lldap_password_manager").await
    }

    async fn setup_bound_admin_handler(
        mock: MockTestBackendHandler,
    ) -> LdapHandler<MockTestBackendHandler> {
        setup_bound_handler_with_group(mock, "lldap_admin").await
    }

    #[tokio::test]
    async fn test_bind() {
        let mut mock = MockTestBackendHandler::new();
        mock.expect_bind()
            .with(eq(crate::domain::handler::BindRequest {
                name: UserId::new("bob"),
                password: "pass".to_string(),
            }))
            .times(1)
            .return_once(|_| Ok(()));
        mock.expect_get_user_groups()
            .with(eq(UserId::new("bob")))
            .return_once(|_| Ok(HashSet::new()));
        let mut ldap_handler =
            LdapHandler::new(mock, "dc=eXample,dc=com".to_string(), vec![], vec![]);

        let request = LdapOp::BindRequest(LdapBindRequest {
            dn: "uid=bob,ou=people,dc=example,dc=com".to_string(),
            cred: LdapBindCred::Simple("pass".to_string()),
        });
        assert_eq!(
            ldap_handler.handle_ldap_message(request).await,
            Some(vec![LdapOp::BindResponse(LdapBindResponse {
                res: LdapResultOp {
                    code: LdapResultCode::Success,
                    matcheddn: "".to_string(),
                    message: "".to_string(),
                    referral: vec![],
                },
                saslcreds: None,
            })]),
        );
    }

    #[tokio::test]
    async fn test_admin_bind() {
        let mut mock = MockTestBackendHandler::new();
        mock.expect_bind()
            .with(eq(crate::domain::handler::BindRequest {
                name: UserId::new("test"),
                password: "pass".to_string(),
            }))
            .times(1)
            .return_once(|_| Ok(()));
        mock.expect_get_user_groups()
            .with(eq(UserId::new("test")))
            .return_once(|_| {
                let mut set = HashSet::new();
                set.insert(GroupDetails {
                    group_id: GroupId(42),
                    display_name: "lldap_admin".to_string(),
                    creation_date: chrono::Utc.timestamp(42, 42),
                    uuid: uuid!("a1a2a3a4b1b2c1c2d1d2d3d4d5d6d7d8"),
                });
                Ok(set)
            });
        let mut ldap_handler =
            LdapHandler::new(mock, "dc=example,dc=com".to_string(), vec![], vec![]);

        let request = LdapBindRequest {
            dn: "uid=test,ou=people,dc=example,dc=com".to_string(),
            cred: LdapBindCred::Simple("pass".to_string()),
        };
        assert_eq!(
            ldap_handler.do_bind(&request).await.0,
            LdapResultCode::Success
        );
    }

    #[tokio::test]
    async fn test_search_regular_user() {
        let mut mock = MockTestBackendHandler::new();
        mock.expect_list_users()
            .with(
                eq(Some(UserRequestFilter::And(vec![
                    UserRequestFilter::And(vec![]),
                    UserRequestFilter::UserId(UserId::new("test")),
                ]))),
                eq(false),
            )
            .times(1)
            .return_once(|_, _| {
                Ok(vec![UserAndGroups {
                    user: User {
                        user_id: UserId::new("test"),
                        ..Default::default()
                    },
                    groups: None,
                }])
            });
        let mut ldap_handler = setup_bound_handler_with_group(mock, "regular").await;

        let request =
            make_user_search_request::<String>(LdapFilter::And(vec![]), vec!["1.1".to_string()]);
        assert_eq!(
            ldap_handler.do_search_or_dse(&request).await,
            Ok(vec![
                LdapOp::SearchResultEntry(LdapSearchResultEntry {
                    dn: "uid=test,ou=people,dc=example,dc=com".to_string(),
                    attributes: vec![],
                }),
                make_search_success()
            ]),
        );
    }

    #[tokio::test]
    async fn test_search_readonly_user() {
        let mut mock = MockTestBackendHandler::new();
        mock.expect_list_users()
            .with(eq(Some(UserRequestFilter::And(vec![]))), eq(false))
            .times(1)
            .return_once(|_, _| Ok(vec![]));
        let mut ldap_handler = setup_bound_readonly_handler(mock).await;

        let request =
            make_user_search_request::<String>(LdapFilter::And(vec![]), vec!["1.1".to_string()]);
        assert_eq!(
            ldap_handler.do_search_or_dse(&request).await,
            Ok(vec![make_search_success()]),
        );
    }

    #[tokio::test]
    async fn test_search_member_of() {
        let mut mock = MockTestBackendHandler::new();
        mock.expect_list_users()
            .with(eq(Some(UserRequestFilter::And(vec![]))), eq(true))
            .times(1)
            .return_once(|_, _| {
                Ok(vec![UserAndGroups {
                    user: User {
                        user_id: UserId::new("bob"),
                        ..Default::default()
                    },
                    groups: Some(vec![GroupDetails {
                        group_id: GroupId(42),
                        display_name: "rockstars".to_string(),
                        creation_date: chrono::Utc.timestamp(42, 42),
                        uuid: uuid!("a1a2a3a4b1b2c1c2d1d2d3d4d5d6d7d8"),
                    }]),
                }])
            });
        let mut ldap_handler = setup_bound_readonly_handler(mock).await;

        let request = make_user_search_request::<String>(
            LdapFilter::And(vec![]),
            vec!["memberOf".to_string()],
        );
        assert_eq!(
            ldap_handler.do_search_or_dse(&request).await,
            Ok(vec![
                LdapOp::SearchResultEntry(LdapSearchResultEntry {
                    dn: "uid=bob,ou=people,dc=example,dc=com".to_string(),
                    attributes: vec![LdapPartialAttribute {
                        atype: "memberOf".to_string(),
                        vals: vec![b"uid=rockstars,ou=groups,dc=example,dc=com".to_vec()]
                    }],
                }),
                make_search_success(),
            ]),
        );
    }

    #[tokio::test]
    async fn test_search_user_as_scope() {
        let mut mock = MockTestBackendHandler::new();
        mock.expect_list_users()
            .with(
                eq(Some(UserRequestFilter::And(vec![
                    UserRequestFilter::And(vec![]),
                    UserRequestFilter::UserId(UserId::new("bob")),
                ]))),
                eq(false),
            )
            .times(1)
            .return_once(|_, _| Ok(vec![]));
        let mut ldap_handler = setup_bound_readonly_handler(mock).await;

        let request = LdapSearchRequest {
            base: "uid=bob,ou=people,Dc=example,dc=com".to_string(),
            scope: LdapSearchScope::Base,
            aliases: LdapDerefAliases::Never,
            sizelimit: 0,
            timelimit: 0,
            typesonly: false,
            filter: LdapFilter::And(vec![]),
            attrs: vec!["1.1".to_string()],
        };
        assert_eq!(
            ldap_handler.do_search_or_dse(&request).await,
            Ok(vec![make_search_success()]),
        );
    }

    #[tokio::test]
    async fn test_bind_invalid_dn() {
        let mock = MockTestBackendHandler::new();
        let mut ldap_handler =
            LdapHandler::new(mock, "dc=example,dc=com".to_string(), vec![], vec![]);

        let request = LdapBindRequest {
            dn: "cn=bob,dc=example,dc=com".to_string(),
            cred: LdapBindCred::Simple("pass".to_string()),
        };
        assert_eq!(
            ldap_handler.do_bind(&request).await.0,
            LdapResultCode::NamingViolation,
        );
        let request = LdapBindRequest {
            dn: "uid=bob,dc=example,dc=com".to_string(),
            cred: LdapBindCred::Simple("pass".to_string()),
        };
        assert_eq!(
            ldap_handler.do_bind(&request).await.0,
            LdapResultCode::NamingViolation,
        );
        let request = LdapBindRequest {
            dn: "uid=bob,ou=groups,dc=example,dc=com".to_string(),
            cred: LdapBindCred::Simple("pass".to_string()),
        };
        assert_eq!(
            ldap_handler.do_bind(&request).await.0,
            LdapResultCode::NamingViolation,
        );
        let request = LdapBindRequest {
            dn: "uid=bob,ou=people,dc=example,dc=fr".to_string(),
            cred: LdapBindCred::Simple("pass".to_string()),
        };
        assert_eq!(
            ldap_handler.do_bind(&request).await.0,
            LdapResultCode::NamingViolation,
        );
        let request = LdapBindRequest {
            dn: "uid=bob=test,ou=people,dc=example,dc=com".to_string(),
            cred: LdapBindCred::Simple("pass".to_string()),
        };
        assert_eq!(
            ldap_handler.do_bind(&request).await.0,
            LdapResultCode::NamingViolation,
        );
    }

    #[test]
    fn test_is_subtree() {
        let subtree1 = &[
            ("ou".to_string(), "people".to_string()),
            ("dc".to_string(), "example".to_string()),
            ("dc".to_string(), "com".to_string()),
        ];
        let root = &[
            ("dc".to_string(), "example".to_string()),
            ("dc".to_string(), "com".to_string()),
        ];
        assert!(is_subtree(subtree1, root));
        assert!(!is_subtree(&[], root));
    }

    #[test]
    fn test_parse_distinguished_name() {
        let parsed_dn = &[
            ("ou".to_string(), "people".to_string()),
            ("dc".to_string(), "example".to_string()),
            ("dc".to_string(), "com".to_string()),
        ];
        assert_eq!(
            parse_distinguished_name("ou=people,dc=example,dc=com").expect("parsing failed"),
            parsed_dn
        );
        assert_eq!(
            parse_distinguished_name(" ou  = people , dc = example , dc =  com ")
                .expect("parsing failed"),
            parsed_dn
        );
    }

    #[tokio::test]
    async fn test_search_users() {
        use chrono::prelude::*;
        let mut mock = MockTestBackendHandler::new();
        mock.expect_list_users().times(1).return_once(|_, _| {
            Ok(vec![
                UserAndGroups {
                    user: User {
                        user_id: UserId::new("bob_1"),
                        email: "bob@bobmail.bob".to_string(),
                        display_name: "Bôb Böbberson".to_string(),
                        first_name: "Bôb".to_string(),
                        last_name: "Böbberson".to_string(),
                        uuid: uuid!("698e1d5f-7a40-3151-8745-b9b8a37839da"),
                        ..Default::default()
                    },
                    groups: None,
                },
                UserAndGroups {
                    user: User {
                        user_id: UserId::new("jim"),
                        email: "jim@cricket.jim".to_string(),
                        display_name: "Jimminy Cricket".to_string(),
                        first_name: "Jim".to_string(),
                        last_name: "Cricket".to_string(),
                        avatar: JpegPhoto::for_tests(),
                        uuid: uuid!("04ac75e0-2900-3e21-926c-2f732c26b3fc"),
                        creation_date: Utc.ymd(2014, 7, 8).and_hms(9, 10, 11),
                    },
                    groups: None,
                },
            ])
        });
        let mut ldap_handler = setup_bound_admin_handler(mock).await;
        let request = make_user_search_request(
            LdapFilter::And(vec![]),
            vec![
                "objectClass",
                "dn",
                "uid",
                "mail",
                "givenName",
                "sn",
                "cn",
                "createTimestamp",
                "entryUuid",
                "jpegPhoto",
            ],
        );
        assert_eq!(
            ldap_handler.do_search_or_dse(&request).await,
            Ok(vec![
                LdapOp::SearchResultEntry(LdapSearchResultEntry {
                    dn: "uid=bob_1,ou=people,dc=example,dc=com".to_string(),
                    attributes: vec![
                        LdapPartialAttribute {
                            atype: "objectClass".to_string(),
                            vals: vec![
                                b"inetOrgPerson".to_vec(),
                                b"posixAccount".to_vec(),
                                b"mailAccount".to_vec(),
                                b"person".to_vec()
                            ]
                        },
                        LdapPartialAttribute {
                            atype: "uid".to_string(),
                            vals: vec![b"bob_1".to_vec()]
                        },
                        LdapPartialAttribute {
                            atype: "mail".to_string(),
                            vals: vec![b"bob@bobmail.bob".to_vec()]
                        },
                        LdapPartialAttribute {
                            atype: "givenName".to_string(),
                            vals: vec!["Bôb".to_string().into_bytes()]
                        },
                        LdapPartialAttribute {
                            atype: "sn".to_string(),
                            vals: vec!["Böbberson".to_string().into_bytes()]
                        },
                        LdapPartialAttribute {
                            atype: "cn".to_string(),
                            vals: vec!["Bôb Böbberson".to_string().into_bytes()]
                        },
                        LdapPartialAttribute {
                            atype: "createTimestamp".to_string(),
                            vals: vec![b"1970-01-01T00:00:00+00:00".to_vec()]
                        },
                        LdapPartialAttribute {
                            atype: "entryUuid".to_string(),
                            vals: vec![b"698e1d5f-7a40-3151-8745-b9b8a37839da".to_vec()]
                        },
                    ],
                }),
                LdapOp::SearchResultEntry(LdapSearchResultEntry {
                    dn: "uid=jim,ou=people,dc=example,dc=com".to_string(),
                    attributes: vec![
                        LdapPartialAttribute {
                            atype: "objectClass".to_string(),
                            vals: vec![
                                b"inetOrgPerson".to_vec(),
                                b"posixAccount".to_vec(),
                                b"mailAccount".to_vec(),
                                b"person".to_vec()
                            ]
                        },
                        LdapPartialAttribute {
                            atype: "uid".to_string(),
                            vals: vec![b"jim".to_vec()]
                        },
                        LdapPartialAttribute {
                            atype: "mail".to_string(),
                            vals: vec![b"jim@cricket.jim".to_vec()]
                        },
                        LdapPartialAttribute {
                            atype: "givenName".to_string(),
                            vals: vec![b"Jim".to_vec()]
                        },
                        LdapPartialAttribute {
                            atype: "sn".to_string(),
                            vals: vec![b"Cricket".to_vec()]
                        },
                        LdapPartialAttribute {
                            atype: "cn".to_string(),
                            vals: vec![b"Jimminy Cricket".to_vec()]
                        },
                        LdapPartialAttribute {
                            atype: "createTimestamp".to_string(),
                            vals: vec![b"2014-07-08T09:10:11+00:00".to_vec()]
                        },
                        LdapPartialAttribute {
                            atype: "entryUuid".to_string(),
                            vals: vec![b"04ac75e0-2900-3e21-926c-2f732c26b3fc".to_vec()]
                        },
                        LdapPartialAttribute {
                            atype: "jpegPhoto".to_string(),
                            vals: vec![JpegPhoto::for_tests().into_bytes()]
                        },
                    ],
                }),
                make_search_success(),
            ])
        );
    }

    #[tokio::test]
    async fn test_search_groups() {
        let mut mock = MockTestBackendHandler::new();
        mock.expect_list_groups()
            .with(eq(Some(GroupRequestFilter::And(vec![]))))
            .times(1)
            .return_once(|_| {
                Ok(vec![
                    Group {
                        id: GroupId(1),
                        display_name: "group_1".to_string(),
                        creation_date: chrono::Utc.timestamp(42, 42),
                        users: vec![UserId::new("bob"), UserId::new("john")],
                        uuid: uuid!("04ac75e0-2900-3e21-926c-2f732c26b3fc"),
                    },
                    Group {
                        id: GroupId(3),
                        display_name: "BestGroup".to_string(),
                        creation_date: chrono::Utc.timestamp(42, 42),
                        users: vec![UserId::new("john")],
                        uuid: uuid!("04ac75e0-2900-3e21-926c-2f732c26b3fc"),
                    },
                ])
            });
        let mut ldap_handler = setup_bound_admin_handler(mock).await;
        let request = make_search_request(
            "ou=groups,dc=example,dc=cOm",
            LdapFilter::And(vec![]),
            vec!["objectClass", "dn", "cn", "uniqueMember", "entryUuid"],
        );
        assert_eq!(
            ldap_handler.do_search_or_dse(&request).await,
            Ok(vec![
                LdapOp::SearchResultEntry(LdapSearchResultEntry {
                    dn: "cn=group_1,ou=groups,dc=example,dc=com".to_string(),
                    attributes: vec![
                        LdapPartialAttribute {
                            atype: "objectClass".to_string(),
                            vals: vec![b"groupOfUniqueNames".to_vec(),]
                        },
                        LdapPartialAttribute {
                            atype: "cn".to_string(),
                            vals: vec![b"group_1".to_vec()]
                        },
                        LdapPartialAttribute {
                            atype: "uniqueMember".to_string(),
                            vals: vec![
                                b"uid=bob,ou=people,dc=example,dc=com".to_vec(),
                                b"uid=john,ou=people,dc=example,dc=com".to_vec(),
                            ]
                        },
                        LdapPartialAttribute {
                            atype: "entryUuid".to_string(),
                            vals: vec![b"04ac75e0-2900-3e21-926c-2f732c26b3fc".to_vec()],
                        },
                    ],
                }),
                LdapOp::SearchResultEntry(LdapSearchResultEntry {
                    dn: "cn=BestGroup,ou=groups,dc=example,dc=com".to_string(),
                    attributes: vec![
                        LdapPartialAttribute {
                            atype: "objectClass".to_string(),
                            vals: vec![b"groupOfUniqueNames".to_vec(),]
                        },
                        LdapPartialAttribute {
                            atype: "cn".to_string(),
                            vals: vec![b"BestGroup".to_vec()]
                        },
                        LdapPartialAttribute {
                            atype: "uniqueMember".to_string(),
                            vals: vec![b"uid=john,ou=people,dc=example,dc=com".to_vec()]
                        },
                        LdapPartialAttribute {
                            atype: "entryUuid".to_string(),
                            vals: vec![b"04ac75e0-2900-3e21-926c-2f732c26b3fc".to_vec()],
                        },
                    ],
                }),
                make_search_success(),
            ])
        );
    }

    #[tokio::test]
    async fn test_search_groups_filter() {
        let mut mock = MockTestBackendHandler::new();
        mock.expect_list_groups()
            .with(eq(Some(GroupRequestFilter::And(vec![
                GroupRequestFilter::DisplayName("group_1".to_string()),
                GroupRequestFilter::Member(UserId::new("bob")),
                GroupRequestFilter::And(vec![]),
                GroupRequestFilter::And(vec![]),
                GroupRequestFilter::And(vec![]),
                GroupRequestFilter::And(vec![]),
                GroupRequestFilter::Not(Box::new(GroupRequestFilter::Not(Box::new(
                    GroupRequestFilter::And(vec![]),
                )))),
                GroupRequestFilter::Not(Box::new(GroupRequestFilter::And(vec![]))),
            ]))))
            .times(1)
            .return_once(|_| {
                Ok(vec![Group {
                    display_name: "group_1".to_string(),
                    id: GroupId(1),
                    creation_date: chrono::Utc.timestamp(42, 42),
                    users: vec![],
                    uuid: uuid!("04ac75e0-2900-3e21-926c-2f732c26b3fc"),
                }])
            });
        let mut ldap_handler = setup_bound_admin_handler(mock).await;
        let request = make_search_request(
            "ou=groups,dc=example,dc=com",
            LdapFilter::And(vec![
                LdapFilter::Equality("cN".to_string(), "Group_1".to_string()),
                LdapFilter::Equality(
                    "uniqueMember".to_string(),
                    "uid=bob,ou=peopLe,Dc=eXample,dc=com".to_string(),
                ),
                LdapFilter::Equality("obJEctclass".to_string(), "groupofUniqueNames".to_string()),
                LdapFilter::Equality("objectclass".to_string(), "groupOfNames".to_string()),
                LdapFilter::Present("objectclass".to_string()),
                LdapFilter::Present("dn".to_string()),
                LdapFilter::Not(Box::new(LdapFilter::Present(
                    "random_attribUte".to_string(),
                ))),
                LdapFilter::Equality("unknown_attribute".to_string(), "randomValue".to_string()),
            ]),
            vec!["1.1"],
        );
        assert_eq!(
            ldap_handler.do_search_or_dse(&request).await,
            Ok(vec![
                LdapOp::SearchResultEntry(LdapSearchResultEntry {
                    dn: "cn=group_1,ou=groups,dc=example,dc=com".to_string(),
                    attributes: vec![],
                }),
                make_search_success(),
            ])
        );
    }

    #[tokio::test]
    async fn test_search_groups_filter_2() {
        let mut mock = MockTestBackendHandler::new();
        mock.expect_list_groups()
            .with(eq(Some(GroupRequestFilter::Or(vec![
                GroupRequestFilter::Not(Box::new(GroupRequestFilter::DisplayName(
                    "group_2".to_string(),
                ))),
            ]))))
            .times(1)
            .return_once(|_| {
                Ok(vec![Group {
                    display_name: "group_1".to_string(),
                    id: GroupId(1),
                    creation_date: chrono::Utc.timestamp(42, 42),
                    users: vec![],
                    uuid: uuid!("04ac75e0-2900-3e21-926c-2f732c26b3fc"),
                }])
            });
        let mut ldap_handler = setup_bound_admin_handler(mock).await;
        let request = make_search_request(
            "ou=groups,dc=example,dc=com",
            LdapFilter::Or(vec![LdapFilter::Not(Box::new(LdapFilter::Equality(
                "displayname".to_string(),
                "group_2".to_string(),
            )))]),
            vec!["cn"],
        );
        assert_eq!(
            ldap_handler.do_search_or_dse(&request).await,
            Ok(vec![
                LdapOp::SearchResultEntry(LdapSearchResultEntry {
                    dn: "cn=group_1,ou=groups,dc=example,dc=com".to_string(),
                    attributes: vec![LdapPartialAttribute {
                        atype: "cn".to_string(),
                        vals: vec![b"group_1".to_vec()]
                    },],
                }),
                make_search_success(),
            ])
        );
    }

    #[tokio::test]
    async fn test_search_group_as_scope() {
        let mut mock = MockTestBackendHandler::new();
        mock.expect_list_groups()
            .with(eq(Some(GroupRequestFilter::And(vec![
                GroupRequestFilter::And(vec![]),
                GroupRequestFilter::DisplayName("rockstars".to_string()),
            ]))))
            .times(1)
            .return_once(|_| Ok(vec![]));
        let mut ldap_handler = setup_bound_readonly_handler(mock).await;

        let request = LdapSearchRequest {
            base: "uid=rockstars,ou=groups,Dc=example,dc=com".to_string(),
            scope: LdapSearchScope::Base,
            aliases: LdapDerefAliases::Never,
            sizelimit: 0,
            timelimit: 0,
            typesonly: false,
            filter: LdapFilter::And(vec![]),
            attrs: vec!["1.1".to_string()],
        };
        assert_eq!(
            ldap_handler.do_search_or_dse(&request).await,
            Ok(vec![make_search_success()]),
        );
    }

    #[tokio::test]
    async fn test_search_groups_error() {
        let mut mock = MockTestBackendHandler::new();
        mock.expect_list_groups()
            .with(eq(Some(GroupRequestFilter::Or(vec![
                GroupRequestFilter::Not(Box::new(GroupRequestFilter::DisplayName(
                    "group_2".to_string(),
                ))),
            ]))))
            .times(1)
            .return_once(|_| {
                Err(crate::domain::error::DomainError::InternalError(
                    "Error getting groups".to_string(),
                ))
            });
        let mut ldap_handler = setup_bound_admin_handler(mock).await;
        let request = make_search_request(
            "ou=groups,dc=example,dc=com",
            LdapFilter::Or(vec![LdapFilter::Not(Box::new(LdapFilter::Equality(
                "displayname".to_string(),
                "group_2".to_string(),
            )))]),
            vec!["cn"],
        );
        assert_eq!(
            ldap_handler.do_search_or_dse(&request).await,
            Err(LdapError{
                code: LdapResultCode::Other,
                message: r#"Error while listing groups "ou=groups,dc=example,dc=com": Internal error: `Error getting groups`"#.to_string()
            })
        );
    }

    #[tokio::test]
    async fn test_search_groups_filter_error() {
        let mut ldap_handler = setup_bound_admin_handler(MockTestBackendHandler::new()).await;
        let request = make_search_request(
            "ou=groups,dc=example,dc=com",
            LdapFilter::And(vec![LdapFilter::Substring(
                "whatever".to_string(),
                ldap3_proto::proto::LdapSubstringFilter::default(),
            )]),
            vec!["cn"],
        );
        assert_eq!(
            ldap_handler.do_search_or_dse(&request).await,
            Err(LdapError{
                code: LdapResultCode::UnwillingToPerform,
                message: r#"Unsupported group filter: Substring("whatever", LdapSubstringFilter { initial: None, any: [], final_: None })"#
                    .to_string()
            })
        );
    }

    #[tokio::test]
    async fn test_search_filters() {
        let mut mock = MockTestBackendHandler::new();
        mock.expect_list_users()
            .with(
                eq(Some(UserRequestFilter::And(vec![UserRequestFilter::Or(
                    vec![
                        UserRequestFilter::Not(Box::new(UserRequestFilter::UserId(UserId::new(
                            "bob",
                        )))),
                        UserRequestFilter::And(vec![]),
                        UserRequestFilter::Not(Box::new(UserRequestFilter::And(vec![]))),
                        UserRequestFilter::And(vec![]),
                        UserRequestFilter::And(vec![]),
                        UserRequestFilter::Not(Box::new(UserRequestFilter::And(vec![]))),
                        UserRequestFilter::Not(Box::new(UserRequestFilter::And(vec![]))),
                    ],
                )]))),
                eq(false),
            )
            .times(1)
            .return_once(|_, _| Ok(vec![]));
        let mut ldap_handler = setup_bound_admin_handler(mock).await;
        let request = make_user_search_request(
            LdapFilter::And(vec![LdapFilter::Or(vec![
                LdapFilter::Not(Box::new(LdapFilter::Equality(
                    "uid".to_string(),
                    "bob".to_string(),
                ))),
                LdapFilter::Equality("objectclass".to_string(), "persOn".to_string()),
                LdapFilter::Equality("objectclass".to_string(), "other".to_string()),
                LdapFilter::Present("objectClass".to_string()),
                LdapFilter::Present("uid".to_string()),
                LdapFilter::Present("unknown".to_string()),
                LdapFilter::Equality("unknown_attribute".to_string(), "randomValue".to_string()),
            ])]),
            vec!["objectClass"],
        );
        assert_eq!(
            ldap_handler.do_search_or_dse(&request).await,
            Ok(vec![make_search_success()])
        );
    }

    #[tokio::test]
    async fn test_search_member_of_filter() {
        let mut mock = MockTestBackendHandler::new();
        mock.expect_list_users()
            .with(
                eq(Some(UserRequestFilter::MemberOf("group_1".to_string()))),
                eq(false),
            )
            .times(1)
            .return_once(|_, _| Ok(vec![]));
        let mut ldap_handler = setup_bound_admin_handler(mock).await;
        let request = make_user_search_request(
            LdapFilter::Equality(
                "memberOf".to_string(),
                "cn=group_1, ou=groups, dc=example,dc=com".to_string(),
            ),
            vec!["objectClass"],
        );
        assert_eq!(
            ldap_handler.do_search_or_dse(&request).await,
            Ok(vec![make_search_success()])
        );
        let request = make_user_search_request(
            LdapFilter::Equality("memberOf".to_string(), "group_1".to_string()),
            vec!["objectClass"],
        );
        assert_eq!(
            ldap_handler.do_search_or_dse(&request).await,
            Err(LdapError {
                code: LdapResultCode::InvalidDNSyntax,
                message: "Missing DN value".to_string()
            })
        );
        let request = make_user_search_request(
            LdapFilter::Equality(
                "memberOf".to_string(),
                "cn=mygroup,dc=example,dc=com".to_string(),
            ),
            vec!["objectClass"],
        );
        assert_eq!(
            ldap_handler.do_search_or_dse(&request).await,
            Err(LdapError{
                code: LdapResultCode::InvalidDNSyntax,
                message: r#"Unexpected DN format. Got "cn=mygroup,dc=example,dc=com", expected: "uid=id,ou=groups,dc=example,dc=com""#.to_string()
            })
        );
    }

    #[tokio::test]
    async fn test_search_filters_lowercase() {
        let mut mock = MockTestBackendHandler::new();
        mock.expect_list_users()
            .with(
                eq(Some(UserRequestFilter::And(vec![UserRequestFilter::Or(
                    vec![UserRequestFilter::Not(Box::new(
                        UserRequestFilter::Equality(UserColumn::FirstName, "bob".to_string()),
                    ))],
                )]))),
                eq(false),
            )
            .times(1)
            .return_once(|_, _| {
                Ok(vec![UserAndGroups {
                    user: User {
                        user_id: UserId::new("bob_1"),
                        ..Default::default()
                    },
                    groups: None,
                }])
            });
        let mut ldap_handler = setup_bound_admin_handler(mock).await;
        let request = make_user_search_request(
            LdapFilter::And(vec![LdapFilter::Or(vec![LdapFilter::Not(Box::new(
                LdapFilter::Equality("givenname".to_string(), "bob".to_string()),
            ))])]),
            vec!["objectclass"],
        );
        assert_eq!(
            ldap_handler.do_search_or_dse(&request).await,
            Ok(vec![
                LdapOp::SearchResultEntry(LdapSearchResultEntry {
                    dn: "uid=bob_1,ou=people,dc=example,dc=com".to_string(),
                    attributes: vec![LdapPartialAttribute {
                        atype: "objectclass".to_string(),
                        vals: vec![
                            b"inetOrgPerson".to_vec(),
                            b"posixAccount".to_vec(),
                            b"mailAccount".to_vec(),
                            b"person".to_vec()
                        ]
                    },]
                }),
                make_search_success()
            ])
        );
    }

    #[tokio::test]
    async fn test_search_both() {
        let mut mock = MockTestBackendHandler::new();
        mock.expect_list_users().times(1).return_once(|_, _| {
            Ok(vec![UserAndGroups {
                user: User {
                    user_id: UserId::new("bob_1"),
                    email: "bob@bobmail.bob".to_string(),
                    display_name: "Bôb Böbberson".to_string(),
                    first_name: "Bôb".to_string(),
                    last_name: "Böbberson".to_string(),
                    ..Default::default()
                },
                groups: None,
            }])
        });
        mock.expect_list_groups()
            .with(eq(Some(GroupRequestFilter::And(vec![]))))
            .times(1)
            .return_once(|_| {
                Ok(vec![Group {
                    id: GroupId(1),
                    display_name: "group_1".to_string(),
                    creation_date: chrono::Utc.timestamp(42, 42),
                    users: vec![UserId::new("bob"), UserId::new("john")],
                    uuid: uuid!("04ac75e0-2900-3e21-926c-2f732c26b3fc"),
                }])
            });
        let mut ldap_handler = setup_bound_admin_handler(mock).await;
        let request = make_search_request(
            "dc=example,dc=com",
            LdapFilter::And(vec![]),
            vec!["objectClass", "dn", "cn"],
        );
        assert_eq!(
            ldap_handler.do_search_or_dse(&request).await,
            Ok(vec![
                LdapOp::SearchResultEntry(LdapSearchResultEntry {
                    dn: "uid=bob_1,ou=people,dc=example,dc=com".to_string(),
                    attributes: vec![
                        LdapPartialAttribute {
                            atype: "objectClass".to_string(),
                            vals: vec![
                                b"inetOrgPerson".to_vec(),
                                b"posixAccount".to_vec(),
                                b"mailAccount".to_vec(),
                                b"person".to_vec()
                            ]
                        },
                        LdapPartialAttribute {
                            atype: "cn".to_string(),
                            vals: vec!["Bôb Böbberson".to_string().into_bytes()]
                        },
                    ],
                }),
                LdapOp::SearchResultEntry(LdapSearchResultEntry {
                    dn: "cn=group_1,ou=groups,dc=example,dc=com".to_string(),
                    attributes: vec![
                        LdapPartialAttribute {
                            atype: "objectClass".to_string(),
                            vals: vec![b"groupOfUniqueNames".to_vec(),]
                        },
                        LdapPartialAttribute {
                            atype: "cn".to_string(),
                            vals: vec![b"group_1".to_vec()]
                        },
                    ],
                }),
                make_search_success(),
            ])
        );
    }

    #[tokio::test]
    async fn test_search_wildcards() {
        let mut mock = MockTestBackendHandler::new();

        mock.expect_list_users().returning(|_, _| {
            Ok(vec![UserAndGroups {
                user: User {
                    user_id: UserId::new("bob_1"),
                    email: "bob@bobmail.bob".to_string(),
                    display_name: "Bôb Böbberson".to_string(),
                    last_name: "Böbberson".to_string(),
                    avatar: JpegPhoto::for_tests(),
                    uuid: uuid!("b4ac75e0-2900-3e21-926c-2f732c26b3fc"),
                    ..Default::default()
                },
                groups: None,
            }])
        });
        mock.expect_list_groups()
            .with(eq(Some(GroupRequestFilter::And(vec![]))))
            .returning(|_| {
                Ok(vec![Group {
                    id: GroupId(1),
                    display_name: "group_1".to_string(),
                    creation_date: chrono::Utc.timestamp(42, 42),
                    users: vec![UserId::new("bob"), UserId::new("john")],
                    uuid: uuid!("04ac75e0-2900-3e21-926c-2f732c26b3fc"),
                }])
            });
        let mut ldap_handler = setup_bound_admin_handler(mock).await;

        // Test simple wildcard
        let request =
            make_search_request("dc=example,dc=com", LdapFilter::And(vec![]), vec!["*", "+"]);

        // all: "objectclass", "dn", "uid", "mail", "givenname", "sn", "cn"
        // Operational: "createtimestamp"

        let expected_result = Ok(vec![
            LdapOp::SearchResultEntry(LdapSearchResultEntry {
                dn: "uid=bob_1,ou=people,dc=example,dc=com".to_string(),
                attributes: vec![
                    LdapPartialAttribute {
                        atype: "objectclass".to_string(),
                        vals: vec![
                            b"inetOrgPerson".to_vec(),
                            b"posixAccount".to_vec(),
                            b"mailAccount".to_vec(),
                            b"person".to_vec(),
                        ],
                    },
                    LdapPartialAttribute {
                        atype: "uid".to_string(),
                        vals: vec![b"bob_1".to_vec()],
                    },
                    LdapPartialAttribute {
                        atype: "mail".to_string(),
                        vals: vec![b"bob@bobmail.bob".to_vec()],
                    },
                    LdapPartialAttribute {
                        atype: "sn".to_string(),
                        vals: vec!["Böbberson".to_string().into_bytes()],
                    },
                    LdapPartialAttribute {
                        atype: "cn".to_string(),
                        vals: vec!["Bôb Böbberson".to_string().into_bytes()],
                    },
                    LdapPartialAttribute {
                        atype: "jpegPhoto".to_string(),
                        vals: vec![JpegPhoto::for_tests().into_bytes()],
                    },
                    LdapPartialAttribute {
                        atype: "createtimestamp".to_string(),
                        vals: vec![chrono::Utc.timestamp(0, 0).to_rfc3339().into_bytes()],
                    },
                    LdapPartialAttribute {
                        atype: "entryuuid".to_string(),
                        vals: vec![b"b4ac75e0-2900-3e21-926c-2f732c26b3fc".to_vec()],
                    },
                ],
            }),
            // "objectclass", "dn", "uid", "cn", "member", "uniquemember"
            LdapOp::SearchResultEntry(LdapSearchResultEntry {
                dn: "cn=group_1,ou=groups,dc=example,dc=com".to_string(),
                attributes: vec![
                    LdapPartialAttribute {
                        atype: "objectclass".to_string(),
                        vals: vec![b"groupOfUniqueNames".to_vec()],
                    },
                    // UID
                    LdapPartialAttribute {
                        atype: "uid".to_string(),
                        vals: vec![b"group_1".to_vec()],
                    },
                    LdapPartialAttribute {
                        atype: "cn".to_string(),
                        vals: vec![b"group_1".to_vec()],
                    },
                    //member / uniquemember : "uid={},ou=people,{}"
                    LdapPartialAttribute {
                        atype: "member".to_string(),
                        vals: vec![
                            b"uid=bob,ou=people,dc=example,dc=com".to_vec(),
                            b"uid=john,ou=people,dc=example,dc=com".to_vec(),
                        ],
                    },
                    LdapPartialAttribute {
                        atype: "uniquemember".to_string(),
                        vals: vec![
                            b"uid=bob,ou=people,dc=example,dc=com".to_vec(),
                            b"uid=john,ou=people,dc=example,dc=com".to_vec(),
                        ],
                    },
                    LdapPartialAttribute {
                        atype: "entryuuid".to_string(),
                        vals: vec![b"04ac75e0-2900-3e21-926c-2f732c26b3fc".to_vec()],
                    },
                ],
            }),
            make_search_success(),
        ]);

        assert_eq!(
            ldap_handler.do_search_or_dse(&request).await,
            expected_result
        );

        let request2 = make_search_request(
            "dc=example,dc=com",
            LdapFilter::And(vec![]),
            vec!["objectclass", "obJEctclaSS", "dn", "*", "*"],
        );

        assert_eq!(
            ldap_handler.do_search_or_dse(&request2).await,
            expected_result
        );

        let request3 = make_search_request(
            "dc=example,dc=com",
            LdapFilter::And(vec![]),
            vec!["*", "+", "+"],
        );

        assert_eq!(
            ldap_handler.do_search_or_dse(&request3).await,
            expected_result
        );

        let request4 =
            make_search_request("dc=example,dc=com", LdapFilter::And(vec![]), vec![""; 0]);

        assert_eq!(
            ldap_handler.do_search_or_dse(&request4).await,
            expected_result
        );

        let request5 = make_search_request(
            "dc=example,dc=com",
            LdapFilter::And(vec![]),
            vec!["objectclass", "dn", "uid", "*"],
        );

        assert_eq!(
            ldap_handler.do_search_or_dse(&request5).await,
            expected_result
        );
    }

    #[tokio::test]
    async fn test_search_wrong_base() {
        let mut ldap_handler = setup_bound_admin_handler(MockTestBackendHandler::new()).await;
        let request = make_search_request(
            "ou=users,dc=example,dc=com",
            LdapFilter::And(vec![]),
            vec!["objectClass"],
        );
        assert_eq!(
            ldap_handler.do_search_or_dse(&request).await,
            Ok(vec![make_search_success()])
        );
    }

    #[tokio::test]
    async fn test_search_unsupported_filters() {
        let mut ldap_handler = setup_bound_admin_handler(MockTestBackendHandler::new()).await;
        let request = make_user_search_request(
            LdapFilter::Substring(
                "uid".to_string(),
                ldap3_proto::proto::LdapSubstringFilter::default(),
            ),
            vec!["objectClass"],
        );
        assert_eq!(
            ldap_handler.do_search_or_dse(&request).await,
            Err(LdapError{
                code: LdapResultCode::UnwillingToPerform,
                message: r#"Unsupported user filter: Substring("uid", LdapSubstringFilter { initial: None, any: [], final_: None })"#.to_string()
            })
        );
    }

    #[tokio::test]
    async fn test_password_change() {
        let mut mock = MockTestBackendHandler::new();
        mock.expect_get_user_groups()
            .with(eq(UserId::new("bob")))
            .returning(|_| Ok(HashSet::new()));
        use lldap_auth::*;
        let mut rng = rand::rngs::OsRng;
        let registration_start_request =
            opaque::client::registration::start_registration("password", &mut rng).unwrap();
        let request = registration::ClientRegistrationStartRequest {
            username: "bob".to_string(),
            registration_start_request: registration_start_request.message,
        };
        let start_response = opaque::server::registration::start_registration(
            &opaque::server::ServerSetup::new(&mut rng),
            request.registration_start_request,
            &request.username,
        )
        .unwrap();
        mock.expect_registration_start().times(1).return_once(|_| {
            Ok(registration::ServerRegistrationStartResponse {
                server_data: "".to_string(),
                registration_response: start_response.message,
            })
        });
        mock.expect_registration_finish()
            .times(1)
            .return_once(|_| Ok(()));
        let mut ldap_handler = setup_bound_admin_handler(mock).await;
        let request = LdapOp::ExtendedRequest(
            LdapPasswordModifyRequest {
                user_identity: Some("uid=bob,ou=people,dc=example,dc=com".to_string()),
                old_password: None,
                new_password: Some("password".to_string()),
            }
            .into(),
        );
        assert_eq!(
            ldap_handler.handle_ldap_message(request).await,
            Some(vec![make_extended_response(
                LdapResultCode::Success,
                "".to_string(),
            )])
        );
    }

    #[tokio::test]
    async fn test_password_change_password_manager() {
        let mut mock = MockTestBackendHandler::new();
        mock.expect_get_user_groups()
            .with(eq(UserId::new("bob")))
            .returning(|_| Ok(HashSet::new()));
        use lldap_auth::*;
        let mut rng = rand::rngs::OsRng;
        let registration_start_request =
            opaque::client::registration::start_registration("password", &mut rng).unwrap();
        let request = registration::ClientRegistrationStartRequest {
            username: "bob".to_string(),
            registration_start_request: registration_start_request.message,
        };
        let start_response = opaque::server::registration::start_registration(
            &opaque::server::ServerSetup::new(&mut rng),
            request.registration_start_request,
            &request.username,
        )
        .unwrap();
        mock.expect_registration_start().times(1).return_once(|_| {
            Ok(registration::ServerRegistrationStartResponse {
                server_data: "".to_string(),
                registration_response: start_response.message,
            })
        });
        mock.expect_registration_finish()
            .times(1)
            .return_once(|_| Ok(()));
        let mut ldap_handler = setup_bound_password_manager_handler(mock).await;
        let request = LdapOp::ExtendedRequest(
            LdapPasswordModifyRequest {
                user_identity: Some("uid=bob,ou=people,dc=example,dc=com".to_string()),
                old_password: None,
                new_password: Some("password".to_string()),
            }
            .into(),
        );
        assert_eq!(
            ldap_handler.handle_ldap_message(request).await,
            Some(vec![make_extended_response(
                LdapResultCode::Success,
                "".to_string(),
            )])
        );
    }

    #[tokio::test]
    async fn test_password_change_errors() {
        let mut mock = MockTestBackendHandler::new();
        mock.expect_get_user_groups()
            .with(eq(UserId::new("bob")))
            .returning(|_| Ok(HashSet::new()));
        let mut ldap_handler = setup_bound_admin_handler(mock).await;
        let request = LdapOp::ExtendedRequest(
            LdapPasswordModifyRequest {
                user_identity: None,
                old_password: None,
                new_password: None,
            }
            .into(),
        );
        assert_eq!(
            ldap_handler.handle_ldap_message(request).await,
            Some(vec![make_extended_response(
                LdapResultCode::ConstraintViolation,
                "Missing either user_id or password".to_string(),
            )])
        );
        let request = LdapOp::ExtendedRequest(
            LdapPasswordModifyRequest {
                user_identity: Some("uid=bob,ou=groups,ou=people,dc=example,dc=com".to_string()),
                old_password: None,
                new_password: Some("password".to_string()),
            }
            .into(),
        );
        assert_eq!(
            ldap_handler.handle_ldap_message(request).await,
            Some(vec![make_extended_response(
                LdapResultCode::InvalidDNSyntax,
                r#"Invalid username: Unexpected DN format. Got "uid=bob,ou=groups,ou=people,dc=example,dc=com", expected: "uid=id,ou=people,dc=example,dc=com""#.to_string(),
            )])
        );
        let request = LdapOp::ExtendedRequest(LdapExtendedRequest {
            name: "test".to_string(),
            value: None,
        });
        assert_eq!(
            ldap_handler.handle_ldap_message(request).await,
            Some(vec![make_extended_response(
                LdapResultCode::UnwillingToPerform,
                "Unsupported extended operation: test".to_string(),
            )])
        );
    }

    #[tokio::test]
    async fn test_password_change_unauthorized_password_manager() {
        let mut mock = MockTestBackendHandler::new();
        let mut groups = HashSet::new();
        groups.insert(GroupDetails {
            group_id: GroupId(0),
            display_name: "lldap_admin".to_string(),
            creation_date: chrono::Utc.timestamp(42, 42),
            uuid: uuid!("a1a2a3a4b1b2c1c2d1d2d3d4d5d6d7d8"),
        });
        mock.expect_get_user_groups()
            .with(eq(UserId::new("bob")))
            .times(1)
            .return_once(|_| Ok(groups));
        let mut ldap_handler = setup_bound_password_manager_handler(mock).await;
        let request = LdapOp::ExtendedRequest(
            LdapPasswordModifyRequest {
                user_identity: Some("uid=bob,ou=people,dc=example,dc=com".to_string()),
                old_password: Some("pass".to_string()),
                new_password: Some("password".to_string()),
            }
            .into(),
        );
        assert_eq!(
            ldap_handler.handle_ldap_message(request).await,
            Some(vec![make_extended_response(
                LdapResultCode::InsufficentAccessRights,
                "User `test` cannot modify the password of user `bob`".to_string(),
            )])
        );
    }

    #[tokio::test]
    async fn test_password_change_unauthorized_readonly() {
        let mut mock = MockTestBackendHandler::new();
        mock.expect_get_user_groups()
            .with(eq(UserId::new("bob")))
            .times(1)
            .return_once(|_| Ok(HashSet::new()));
        let mut ldap_handler = setup_bound_readonly_handler(mock).await;
        let request = LdapOp::ExtendedRequest(
            LdapPasswordModifyRequest {
                user_identity: Some("uid=bob,ou=people,dc=example,dc=com".to_string()),
                old_password: Some("pass".to_string()),
                new_password: Some("password".to_string()),
            }
            .into(),
        );
        assert_eq!(
            ldap_handler.handle_ldap_message(request).await,
            Some(vec![make_extended_response(
                LdapResultCode::InsufficentAccessRights,
                "User `test` cannot modify the password of user `bob`".to_string(),
            )])
        );
    }

    #[tokio::test]
    async fn test_search_root_dse() {
        let mut ldap_handler = setup_bound_admin_handler(MockTestBackendHandler::new()).await;
        let request = LdapSearchRequest {
            base: "".to_string(),
            scope: LdapSearchScope::Base,
            aliases: LdapDerefAliases::Never,
            sizelimit: 0,
            timelimit: 0,
            typesonly: false,
            filter: LdapFilter::Present("objectClass".to_string()),
            attrs: vec!["supportedExtension".to_string()],
        };
        assert_eq!(
            ldap_handler.do_search_or_dse(&request).await,
            Ok(vec![
                root_dse_response("dc=example,dc=com"),
                make_search_success()
            ])
        );
    }
}
