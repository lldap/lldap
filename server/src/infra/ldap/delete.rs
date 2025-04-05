use crate::{
    domain::ldap::{
        error::{LdapError, LdapResult},
        utils::{LdapInfo, UserOrGroupName, get_user_or_group_id_from_distinguished_name},
    },
};
    use lldap_access_control::AdminBackendHandler;
use ldap3_proto::proto::{LdapOp, LdapResult as LdapResultOp, LdapResultCode};
use lldap_domain::types::{GroupName, UserId};
use lldap_domain_handlers::handler::GroupRequestFilter;
use lldap_domain_model::error::DomainError;
use tracing::instrument;

pub(crate) fn make_del_response(code: LdapResultCode, message: String) -> LdapOp {
    LdapOp::DelResponse(LdapResultOp {
        code,
        matcheddn: "".to_string(),
        message,
        referral: vec![],
    })
}

#[instrument(skip_all, level = "debug")]
pub(crate) async fn delete_user_or_group(
    backend_handler: &impl AdminBackendHandler,
    ldap_info: &LdapInfo,
    request: String,
) -> LdapResult<Vec<LdapOp>> {
    let base_dn_str = &ldap_info.base_dn_str;
    match get_user_or_group_id_from_distinguished_name(&request, &ldap_info.base_dn) {
        UserOrGroupName::User(user_id) => delete_user(backend_handler, user_id).await,
        UserOrGroupName::Group(group_name) => delete_group(backend_handler, group_name).await,
        err => Err(err.into_ldap_error(
            &request,
            format!(
                r#""uid=id,ou=people,{}" or "uid=id,ou=groups,{}""#,
                base_dn_str, base_dn_str
            ),
        )),
    }
}

#[instrument(skip_all, level = "debug")]
async fn delete_user(
    backend_handler: &impl AdminBackendHandler,
    user_id: UserId,
) -> LdapResult<Vec<LdapOp>> {
    backend_handler
        .get_user_details(&user_id)
        .await
        .map_err(|err| match err {
            DomainError::EntityNotFound(_) => LdapError {
                code: LdapResultCode::NoSuchObject,
                message: "Could not find user".to_string(),
            },
            e => LdapError {
                code: LdapResultCode::OperationsError,
                message: format!("Error while finding user: {:?}", e),
            },
        })?;
    backend_handler
        .delete_user(&user_id)
        .await
        .map_err(|e| LdapError {
            code: LdapResultCode::OperationsError,
            message: format!("Error while deleting user: {:?}", e),
        })?;
    Ok(vec![make_del_response(
        LdapResultCode::Success,
        String::new(),
    )])
}

#[instrument(skip_all, level = "debug")]
async fn delete_group(
    backend_handler: &impl AdminBackendHandler,
    group_name: GroupName,
) -> LdapResult<Vec<LdapOp>> {
    let groups = backend_handler
        .list_groups(Some(GroupRequestFilter::DisplayName(group_name.clone())))
        .await
        .map_err(|e| LdapError {
            code: LdapResultCode::OperationsError,
            message: format!("Error while finding group: {:?}", e),
        })?;
    let group_id = groups
        .iter()
        .find(|g| g.display_name == group_name)
        .map(|g| g.id)
        .ok_or_else(|| LdapError {
            code: LdapResultCode::NoSuchObject,
            message: "Could not find group".to_string(),
        })?;
    backend_handler
        .delete_group(group_id)
        .await
        .map_err(|e| LdapError {
            code: LdapResultCode::OperationsError,
            message: format!("Error while deleting group: {:?}", e),
        })?;
    Ok(vec![make_del_response(
        LdapResultCode::Success,
        String::new(),
    )])
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::infra::{
        ldap::handler::tests::setup_bound_admin_handler, test_utils::MockTestBackendHandler,
    };
    use chrono::TimeZone;
    use lldap_domain::{
        types::{Group, GroupId, User},
        uuid,
    };
    use lldap_domain_model::error::DomainError;
    use mockall::predicate::eq;
    use pretty_assertions::assert_eq;
    use tokio;

    #[tokio::test]
    async fn test_delete_user() {
        let mut mock = MockTestBackendHandler::new();
        mock.expect_get_user_details()
            .with(eq(UserId::new("bob")))
            .return_once(|_| {
                Ok(User {
                    user_id: UserId::new("bob"),
                    ..Default::default()
                })
            });
        mock.expect_delete_user()
            .with(eq(UserId::new("bob")))
            .times(1)
            .return_once(|_| Ok(()));
        let mut ldap_handler = setup_bound_admin_handler(mock).await;
        let request = LdapOp::DelRequest("uid=bob,ou=people,dc=example,dc=com".to_owned());
        assert_eq!(
            ldap_handler.handle_ldap_message(request).await,
            Some(vec![make_del_response(
                LdapResultCode::Success,
                String::new()
            )])
        );
    }

    #[tokio::test]
    async fn test_delete_group() {
        let mut mock = MockTestBackendHandler::new();
        mock.expect_list_groups()
            .with(eq(Some(GroupRequestFilter::DisplayName(GroupName::from(
                "bob",
            )))))
            .return_once(|_| {
                Ok(vec![Group {
                    id: GroupId(34),
                    display_name: GroupName::from("bob"),
                    creation_date: chrono::Utc.timestamp_opt(42, 42).unwrap().naive_utc(),
                    uuid: uuid!("a1a2a3a4b1b2c1c2d1d2d3d4d5d6d7d8"),
                    users: Vec::new(),
                    attributes: Vec::new(),
                }])
            });
        mock.expect_delete_group()
            .with(eq(GroupId(34)))
            .times(1)
            .return_once(|_| Ok(()));
        let mut ldap_handler = setup_bound_admin_handler(mock).await;
        let request = LdapOp::DelRequest("uid=bob,ou=groups,dc=example,dc=com".to_owned());
        assert_eq!(
            ldap_handler.handle_ldap_message(request).await,
            Some(vec![make_del_response(
                LdapResultCode::Success,
                String::new()
            )])
        );
    }

    #[tokio::test]
    async fn test_delete_user_not_found() {
        let mut mock = MockTestBackendHandler::new();
        mock.expect_get_user_details()
            .with(eq(UserId::new("bob")))
            .return_once(|_| Err(DomainError::EntityNotFound("No such user".to_string())));
        let mut ldap_handler = setup_bound_admin_handler(mock).await;
        let request = LdapOp::DelRequest("uid=bob,ou=people,dc=example,dc=com".to_owned());
        assert_eq!(
            ldap_handler.handle_ldap_message(request).await,
            Some(vec![make_del_response(
                LdapResultCode::NoSuchObject,
                "Could not find user".to_string()
            )])
        );
    }

    #[tokio::test]
    async fn test_delete_user_lookup_error() {
        let mut mock = MockTestBackendHandler::new();
        mock.expect_get_user_details()
            .with(eq(UserId::new("bob")))
            .return_once(|_| Err(DomainError::InternalError("WTF?".to_string())));
        let mut ldap_handler = setup_bound_admin_handler(mock).await;
        let request = LdapOp::DelRequest("uid=bob,ou=people,dc=example,dc=com".to_owned());
        assert_eq!(
            ldap_handler.handle_ldap_message(request).await,
            Some(vec![make_del_response(
                LdapResultCode::OperationsError,
                r#"Error while finding user: InternalError("WTF?")"#.to_string()
            )])
        );
    }

    #[tokio::test]
    async fn test_delete_user_deletion_error() {
        let mut mock = MockTestBackendHandler::new();
        mock.expect_get_user_details()
            .with(eq(UserId::new("bob")))
            .return_once(|_| {
                Ok(User {
                    user_id: UserId::new("bob"),
                    ..Default::default()
                })
            });
        mock.expect_delete_user()
            .with(eq(UserId::new("bob")))
            .times(1)
            .return_once(|_| Err(DomainError::InternalError("WTF?".to_string())));
        let mut ldap_handler = setup_bound_admin_handler(mock).await;
        let request = LdapOp::DelRequest("uid=bob,ou=people,dc=example,dc=com".to_owned());
        assert_eq!(
            ldap_handler.handle_ldap_message(request).await,
            Some(vec![make_del_response(
                LdapResultCode::OperationsError,
                r#"Error while deleting user: InternalError("WTF?")"#.to_string()
            )])
        );
    }

    #[tokio::test]
    async fn test_delete_group_not_found() {
        let mut mock = MockTestBackendHandler::new();
        mock.expect_list_groups()
            .with(eq(Some(GroupRequestFilter::DisplayName(GroupName::from(
                "bob",
            )))))
            .return_once(|_| Ok(vec![]));
        let mut ldap_handler = setup_bound_admin_handler(mock).await;
        let request = LdapOp::DelRequest("uid=bob,ou=groups,dc=example,dc=com".to_owned());
        assert_eq!(
            ldap_handler.handle_ldap_message(request).await,
            Some(vec![make_del_response(
                LdapResultCode::NoSuchObject,
                "Could not find group".to_string()
            )])
        );
    }

    #[tokio::test]
    async fn test_delete_group_lookup_error() {
        let mut mock = MockTestBackendHandler::new();
        mock.expect_list_groups()
            .with(eq(Some(GroupRequestFilter::DisplayName(GroupName::from(
                "bob",
            )))))
            .return_once(|_| Err(DomainError::InternalError("WTF?".to_string())));
        let mut ldap_handler = setup_bound_admin_handler(mock).await;
        let request = LdapOp::DelRequest("uid=bob,ou=groups,dc=example,dc=com".to_owned());
        assert_eq!(
            ldap_handler.handle_ldap_message(request).await,
            Some(vec![make_del_response(
                LdapResultCode::OperationsError,
                r#"Error while finding group: InternalError("WTF?")"#.to_string()
            )])
        );
    }

    #[tokio::test]
    async fn test_delete_group_deletion_error() {
        let mut mock = MockTestBackendHandler::new();
        mock.expect_list_groups()
            .with(eq(Some(GroupRequestFilter::DisplayName(GroupName::from(
                "bob",
            )))))
            .return_once(|_| {
                Ok(vec![Group {
                    id: GroupId(34),
                    display_name: GroupName::from("bob"),
                    creation_date: chrono::Utc.timestamp_opt(42, 42).unwrap().naive_utc(),
                    uuid: uuid!("a1a2a3a4b1b2c1c2d1d2d3d4d5d6d7d8"),
                    users: Vec::new(),
                    attributes: Vec::new(),
                }])
            });
        mock.expect_delete_group()
            .with(eq(GroupId(34)))
            .times(1)
            .return_once(|_| Err(DomainError::InternalError("WTF?".to_string())));
        let mut ldap_handler = setup_bound_admin_handler(mock).await;
        let request = LdapOp::DelRequest("uid=bob,ou=groups,dc=example,dc=com".to_owned());
        assert_eq!(
            ldap_handler.handle_ldap_message(request).await,
            Some(vec![make_del_response(
                LdapResultCode::OperationsError,
                r#"Error while deleting group: InternalError("WTF?")"#.to_string()
            )])
        );
    }
}
