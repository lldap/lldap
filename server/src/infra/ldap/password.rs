use crate::domain::ldap::{
    error::{LdapError, LdapResult},
    utils::{LdapInfo, get_user_id_from_distinguished_name},
};
use ldap3_proto::proto::{LdapBindCred, LdapBindRequest, LdapResultCode};
use lldap_domain::types::UserId;
use lldap_domain_handlers::handler::{BindRequest, LoginHandler};

pub(crate) async fn do_bind(
    ldap_info: &LdapInfo,
    request: &LdapBindRequest,
    login_handler: &impl LoginHandler,
) -> LdapResult<UserId> {
    if request.dn.is_empty() {
        return Err(LdapError {
            code: LdapResultCode::InappropriateAuthentication,
            message: "Anonymous bind not allowed".to_string(),
        });
    }
    let user_id = match get_user_id_from_distinguished_name(
        &request.dn.to_ascii_lowercase(),
        &ldap_info.base_dn,
        &ldap_info.base_dn_str,
    ) {
        Ok(s) => s,
        Err(e) => {
            return Err(LdapError {
                code: LdapResultCode::NamingViolation,
                message: e.to_string(),
            });
        }
    };
    let password = if let LdapBindCred::Simple(password) = &request.cred {
        password
    } else {
        return Err(LdapError {
            code: LdapResultCode::UnwillingToPerform,
            message: "SASL not supported".to_string(),
        });
    };
    match login_handler
        .bind(BindRequest {
            name: user_id.clone(),
            password: password.clone(),
        })
        .await
    {
        Ok(()) => Ok(user_id),
        Err(_) => Err(LdapError {
            code: LdapResultCode::InvalidCredentials,
            message: "".to_string(),
        }),
    }
}

#[cfg(test)]
pub mod tests {
    use super::*;
    use crate::infra::ldap::handler::LdapHandler;
    use crate::infra::test_utils::MockTestBackendHandler;
    use chrono::TimeZone;
    use ldap3_proto::proto::{LdapBindResponse, LdapOp, LdapResult as LdapResultOp};
    use lldap_domain::{types::*, uuid};
    use mockall::predicate::eq;
    use pretty_assertions::assert_eq;
    use std::collections::HashSet;
    use tokio;

    pub fn make_bind_result(code: LdapResultCode, message: &str) -> Vec<LdapOp> {
        vec![LdapOp::BindResponse(LdapBindResponse {
            res: LdapResultOp {
                code,
                matcheddn: "".to_string(),
                message: message.to_string(),
                referral: vec![],
            },
            saslcreds: None,
        })]
    }

    pub fn make_bind_success() -> Vec<LdapOp> {
        make_bind_result(LdapResultCode::Success, "")
    }

    #[tokio::test]
    async fn test_bind() {
        let mut mock = MockTestBackendHandler::new();
        mock.expect_bind()
            .with(eq(lldap_domain_handlers::handler::BindRequest {
                name: UserId::new("bob"),
                password: "pass".to_string(),
            }))
            .times(1)
            .return_once(|_| Ok(()));
        mock.expect_get_user_groups()
            .with(eq(UserId::new("bob")))
            .return_once(|_| Ok(HashSet::new()));
        let mut ldap_handler = LdapHandler::new_for_tests(mock, "dc=eXample,dc=com");

        let request = LdapOp::BindRequest(LdapBindRequest {
            dn: "uid=bob,ou=people,dc=example,dc=com".to_string(),
            cred: LdapBindCred::Simple("pass".to_string()),
        });
        assert_eq!(
            ldap_handler
                .handle_ldap_message(request)
                .await
                .unwrap(),
            make_bind_success()
        );
    }

    #[tokio::test]
    async fn test_admin_bind() {
        let mut mock = MockTestBackendHandler::new();
        mock.expect_bind()
            .with(eq(lldap_domain_handlers::handler::BindRequest {
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
                    display_name: "lldap_admin".into(),
                    creation_date: chrono::Utc.timestamp_opt(42, 42).unwrap().naive_utc(),
                    uuid: uuid!("a1a2a3a4b1b2c1c2d1d2d3d4d5d6d7d8"),
                    attributes: Vec::new(),
                });
                Ok(set)
            });
        let mut ldap_handler = LdapHandler::new_for_tests(mock, "dc=example,dc=com");

        let request = LdapBindRequest {
            dn: "uid=test,ou=people,dc=example,dc=com".to_string(),
            cred: LdapBindCred::Simple("pass".to_string()),
        };
        assert_eq!(ldap_handler.do_bind(&request).await,
        make_bind_success());
    }

    #[tokio::test]
    async fn test_bind_invalid_dn() {
        let mock = MockTestBackendHandler::new();
        let mut ldap_handler = LdapHandler::new_for_tests(mock, "dc=example,dc=com");

        let request = LdapBindRequest {
            dn: "cn=bob,dc=example,dc=com".to_string(),
            cred: LdapBindCred::Simple("pass".to_string()),
        };
        assert_eq!(
            ldap_handler.do_bind(&request).await,
            make_bind_result(LdapResultCode::NamingViolation, r#"Unexpected DN format. Got "cn=bob,dc=example,dc=com", expected: "uid=id,ou=people,dc=example,dc=com""#),
        );
        let request = LdapBindRequest {
            dn: "uid=bob,dc=example,dc=com".to_string(),
            cred: LdapBindCred::Simple("pass".to_string()),
        };
        assert_eq!(
            ldap_handler.do_bind(&request).await,
            make_bind_result(LdapResultCode::NamingViolation, r#"Unexpected DN format. Got "uid=bob,dc=example,dc=com", expected: "uid=id,ou=people,dc=example,dc=com""#),
        );
        let request = LdapBindRequest {
            dn: "uid=bob,ou=groups,dc=example,dc=com".to_string(),
            cred: LdapBindCred::Simple("pass".to_string()),
        };
        assert_eq!(
            ldap_handler.do_bind(&request).await,
            make_bind_result(LdapResultCode::NamingViolation, r#"Unexpected DN format. Got "uid=bob,ou=groups,dc=example,dc=com", expected: "uid=id,ou=people,dc=example,dc=com""#),
        );
        let request = LdapBindRequest {
            dn: "uid=bob,ou=people,dc=example,dc=fr".to_string(),
            cred: LdapBindCred::Simple("pass".to_string()),
        };
        assert_eq!(
            ldap_handler.do_bind(&request).await,
            make_bind_result(LdapResultCode::NamingViolation, r#"Not a subtree of the base tree"#),
        );
        let request = LdapBindRequest {
            dn: "uid=bob=test,ou=people,dc=example,dc=com".to_string(),
            cred: LdapBindCred::Simple("pass".to_string()),
        };
        assert_eq!(
            ldap_handler.do_bind(&request).await,
            make_bind_result(LdapResultCode::NamingViolation, r#"Too many elements in distinguished name: "uid", "bob", "test""#),
        );
    }
}
