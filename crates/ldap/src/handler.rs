use crate::{
    compare,
    core::{
        error::{LdapError, LdapResult},
        utils::{LdapInfo, parse_distinguished_name},
    },
    create, delete, modify,
    password::{self, do_password_modification},
    search::{
        self, is_root_dse_request, make_search_error, make_search_request, make_search_success,
        root_dse_response,
    },
};
use ldap3_proto::proto::{
    LdapAddRequest, LdapBindRequest, LdapBindResponse, LdapCompareRequest, LdapExtendedRequest,
    LdapExtendedResponse, LdapFilter, LdapModifyRequest, LdapOp, LdapPasswordModifyRequest,
    LdapResult as LdapResultOp, LdapResultCode, LdapSearchRequest, OID_PASSWORD_MODIFY, OID_WHOAMI,
};
use lldap_access_control::AccessControlledBackendHandler;
use lldap_auth::access_control::ValidationResults;
use lldap_domain::types::AttributeName;
use lldap_domain_handlers::handler::{BackendHandler, LoginHandler};
use lldap_opaque_handler::OpaqueHandler;
use tracing::{debug, instrument};

use super::delete::make_del_response;

pub(crate) fn make_add_response(code: LdapResultCode, message: String) -> LdapOp {
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

enum Credentials<'s> {
    Bound(&'s ValidationResults),
    Unbound(Vec<LdapOp>),
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
                        "Invalid value for ldap_base_dn in configuration: {ldap_base_dn}"
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

    fn get_credentials(&self) -> Credentials<'_> {
        match self.user_info.as_ref() {
            Some(user_info) => Credentials::Bound(user_info),
            None => Credentials::Unbound(vec![make_extended_response(
                LdapResultCode::InsufficentAccessRights,
                "No user currently bound".to_string(),
            )]),
        }
    }

    pub async fn do_search_or_dse(&self, request: &LdapSearchRequest) -> LdapResult<Vec<LdapOp>> {
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
    async fn do_extended_request(&self, request: &LdapExtendedRequest) -> Vec<LdapOp> {
        match request.name.as_str() {
            OID_PASSWORD_MODIFY => match LdapPasswordModifyRequest::try_from(request) {
                Ok(password_request) => {
                    let credentials = match self.get_credentials() {
                        Credentials::Bound(cred) => cred,
                        Credentials::Unbound(err) => return err,
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
                    format!("Error while parsing password modify request: {e:#?}"),
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

    #[instrument(skip_all, level = "debug", fields(dn = %request.dn))]
    pub async fn do_modify_request(&self, request: &LdapModifyRequest) -> Vec<LdapOp> {
        let credentials = match self.get_credentials() {
            Credentials::Bound(cred) => cred,
            Credentials::Unbound(err) => return err,
        };
        modify::handle_modify_request(
            self.get_opaque_handler(),
            |credentials, user_id| {
                self.backend_handler
                    .get_readable_handler(credentials, &user_id)
            },
            &self.ldap_info,
            credentials,
            request,
        )
        .await
        .unwrap_or_else(|e: LdapError| vec![make_modify_response(e.code, e.message)])
    }

    #[instrument(skip_all, level = "debug")]
    pub async fn create_user_or_group(&self, request: LdapAddRequest) -> LdapResult<Vec<LdapOp>> {
        let backend_handler = self
            .user_info
            .as_ref()
            .and_then(|u| self.backend_handler.get_admin_handler(u))
            .ok_or_else(|| LdapError {
                code: LdapResultCode::InsufficentAccessRights,
                message: "Unauthorized write".to_string(),
            })?;
        create::create_user_or_group(backend_handler, &self.ldap_info, request).await
    }

    #[instrument(skip_all, level = "debug")]
    pub async fn delete_user_or_group(&self, request: String) -> LdapResult<Vec<LdapOp>> {
        let backend_handler = self
            .user_info
            .as_ref()
            .and_then(|u| self.backend_handler.get_admin_handler(u))
            .ok_or_else(|| LdapError {
                code: LdapResultCode::InsufficentAccessRights,
                message: "Unauthorized write".to_string(),
            })?;
        delete::delete_user_or_group(backend_handler, &self.ldap_info, request).await
    }

    #[instrument(skip_all, level = "debug")]
    pub async fn do_compare(&self, request: LdapCompareRequest) -> LdapResult<Vec<LdapOp>> {
        let req = make_search_request::<String>(
            &self.ldap_info.base_dn_str,
            LdapFilter::Equality("dn".to_string(), request.dn.to_string()),
            vec![request.atype.clone()],
        );
        compare::compare(
            request,
            self.do_search(&req).await?,
            &self.ldap_info.base_dn_str,
        )
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
                .create_user_or_group(request)
                .await
                .unwrap_or_else(|e: LdapError| vec![make_add_response(e.code, e.message)]),
            LdapOp::DelRequest(request) => self
                .delete_user_or_group(request)
                .await
                .unwrap_or_else(|e: LdapError| vec![make_del_response(e.code, e.message)]),
            LdapOp::CompareRequest(request) => self
                .do_compare(request)
                .await
                .unwrap_or_else(|e: LdapError| vec![make_search_error(e.code, e.message)]),
            op => vec![make_extended_response(
                LdapResultCode::UnwillingToPerform,
                format!("Unsupported operation: {op:#?}"),
            )],
        })
    }
}

#[cfg(test)]
pub mod tests {
    use super::*;
    use crate::password::tests::make_bind_success;
    use chrono::TimeZone;
    use ldap3_proto::proto::{LdapBindCred, LdapWhoamiRequest};
    use lldap_domain::{
        types::{GroupDetails, GroupId, UserId},
        uuid,
    };
    use lldap_domain_handlers::handler::*;
    use lldap_test_utils::{MockTestBackendHandler, setup_default_schema};
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
}
