use crate::{
    domain::{
        ldap::{
            error::{LdapError, LdapResult},
            utils::{LdapInfo, get_user_id_from_distinguished_name},
        },
        opaque_handler::OpaqueHandler,
    },
    infra::{
        access_control::UserReadableBackendHandler,
        ldap::{
            handler::make_modify_response,
            password::{self},
        },
    },
};
use ldap3_proto::proto::{LdapModify, LdapModifyRequest, LdapModifyType, LdapOp, LdapResultCode};
use lldap_auth::access_control::ValidationResults;
use lldap_domain::types::UserId;

async fn handle_modify_change(
    opaque_handler: &impl OpaqueHandler,
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
        password::change_password(opaque_handler, user_id, value)
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

pub(crate) async fn handle_modify_request<'cred, UserBackendHandler>(
    opaque_handler: &impl OpaqueHandler,
    get_readable_handler: impl FnOnce(&'cred ValidationResults, UserId) -> &'cred UserBackendHandler,
    ldap_info: &LdapInfo,
    credentials: &'cred ValidationResults,
    request: &LdapModifyRequest,
) -> LdapResult<Vec<LdapOp>>
where
    // Note: ideally, get_readable_handler would take UserId by reference, but I couldn't make the lifetimes work.
    UserBackendHandler: UserReadableBackendHandler + 'cred,
{
    match get_user_id_from_distinguished_name(
        &request.dn,
        &ldap_info.base_dn,
        &ldap_info.base_dn_str,
    ) {
        Ok(uid) => {
            let user_is_admin = get_readable_handler(credentials, uid.clone())
                .get_user_groups(&uid)
                .await
                .map_err(|e| LdapError {
                    code: LdapResultCode::OperationsError,
                    message: format!("Internal error while requesting user's groups: {:#?}", e),
                })?
                .iter()
                .any(|g| g.display_name == "lldap_admin".into());
            for change in &request.changes {
                handle_modify_change(
                    opaque_handler,
                    uid.clone(),
                    credentials,
                    user_is_admin,
                    change,
                )
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
