use crate::domain::{
    handler::{
        BackendHandler, BindRequest, Group, GroupIdAndName, LoginHandler, RequestFilter, User,
    },
    opaque_handler::OpaqueHandler,
};
use anyhow::{bail, Context, Result};
use futures::stream::StreamExt;
use futures_util::TryStreamExt;
use ldap3_server::proto::{
    LdapBindCred, LdapBindRequest, LdapBindResponse, LdapExtendedRequest, LdapExtendedResponse,
    LdapFilter, LdapOp, LdapPartialAttribute, LdapPasswordModifyRequest, LdapResult,
    LdapResultCode, LdapSearchRequest, LdapSearchResultEntry, LdapSearchScope,
};
use log::{debug, warn};
use std::convert::TryFrom;

fn make_dn_pair<I>(mut iter: I) -> Result<(String, String)>
where
    I: Iterator<Item = String>,
{
    let pair = (
        iter.next()
            .ok_or_else(|| anyhow::Error::msg("Empty DN element"))?,
        iter.next()
            .ok_or_else(|| anyhow::Error::msg("Missing DN value"))?,
    );
    if let Some(e) = iter.next() {
        bail!(
            r#"Too many elements in distinguished name: "{:?}", "{:?}", "{:?}""#,
            pair.0,
            pair.1,
            e
        )
    }
    Ok(pair)
}

fn parse_distinguished_name(dn: &str) -> Result<Vec<(String, String)>> {
    dn.split(',')
        .map(|s| make_dn_pair(s.split('=').map(String::from)))
        .collect()
}

fn get_group_id_from_distinguished_name(
    dn: &str,
    base_tree: &[(String, String)],
    base_dn_str: &str,
) -> Result<String> {
    let parts = parse_distinguished_name(dn).context("while parsing a group ID")?;
    if !is_subtree(&parts, base_tree) {
        bail!("Not a subtree of the base tree");
    }
    if parts.len() == base_tree.len() + 2 {
        if parts[1].0 != "ou" || parts[1].1 != "groups" || parts[0].0 != "cn" {
            bail!(
                r#"Unexpected group DN format. Got "{}", expected: "cn=groupname,ou=groups,{}""#,
                dn,
                base_dn_str
            );
        }
        Ok(parts[0].1.to_string())
    } else {
        bail!(
            r#"Unexpected group DN format. Got "{}", expected: "cn=groupname,ou=groups,{}""#,
            dn,
            base_dn_str
        );
    }
}

fn get_user_id_from_distinguished_name(
    dn: &str,
    base_tree: &[(String, String)],
    base_dn_str: &str,
) -> Result<String> {
    let parts = parse_distinguished_name(dn).context("while parsing a user ID")?;
    if !is_subtree(&parts, base_tree) {
        bail!("Not a subtree of the base tree");
    }
    if parts.len() == base_tree.len() + 2 {
        if parts[1].0 != "ou" || parts[1].1 != "people" || parts[0].0 != "cn" {
            bail!(
                r#"Unexpected user DN format. Got "{}", expected: "cn=username,ou=people,{}""#,
                dn,
                base_dn_str
            );
        }
        Ok(parts[0].1.to_string())
    } else {
        bail!(
            r#"Unexpected user DN format. Got "{}", expected: "cn=username,ou=people,{}""#,
            dn,
            base_dn_str
        );
    }
}

fn get_user_attribute(user: &User, attribute: &str, dn: &str) -> Result<Vec<String>> {
    match attribute.to_lowercase().as_str() {
        "objectclass" => Ok(vec![
            "inetOrgPerson".to_string(),
            "posixAccount".to_string(),
            "mailAccount".to_string(),
            "person".to_string(),
        ]),
        "dn" => Ok(vec![dn.to_string()]),
        "uid" => Ok(vec![user.user_id.clone()]),
        "mail" => Ok(vec![user.email.clone()]),
        "givenname" => Ok(vec![user.first_name.clone()]),
        "sn" => Ok(vec![user.last_name.clone()]),
        "cn" | "displayname" => Ok(vec![user.display_name.clone()]),
        "createtimestamp" | "modifytimestamp" => Ok(vec![user.creation_date.to_rfc3339()]),
        _ => bail!("Unsupported user attribute: {}", attribute),
    }
}

fn make_ldap_search_user_result_entry(
    user: User,
    base_dn_str: &str,
    attributes: &[String],
) -> Result<LdapSearchResultEntry> {
    let dn = format!("cn={},ou=people,{}", user.user_id, base_dn_str);
    Ok(LdapSearchResultEntry {
        dn: dn.clone(),
        attributes: attributes
            .iter()
            .map(|a| {
                Ok(LdapPartialAttribute {
                    atype: a.to_string(),
                    vals: get_user_attribute(&user, a, &dn)?,
                })
            })
            .collect::<Result<Vec<LdapPartialAttribute>>>()?,
    })
}

fn get_group_attribute(group: &Group, base_dn_str: &str, attribute: &str) -> Result<Vec<String>> {
    match attribute.to_lowercase().as_str() {
        "objectclass" => Ok(vec!["groupOfUniqueNames".to_string()]),
        "dn" => Ok(vec![format!(
            "cn={},ou=groups,{}",
            group.display_name, base_dn_str
        )]),
        "cn" | "uid" => Ok(vec![group.display_name.clone()]),
        "member" | "uniquemember" => Ok(group
            .users
            .iter()
            .map(|u| format!("cn={},ou=people,{}", u, base_dn_str))
            .collect()),
        _ => bail!("Unsupported group attribute: {}", attribute),
    }
}

fn make_ldap_search_group_result_entry(
    group: Group,
    base_dn_str: &str,
    attributes: &[String],
) -> Result<LdapSearchResultEntry> {
    Ok(LdapSearchResultEntry {
        dn: format!("cn={},ou=groups,{}", group.display_name, base_dn_str),
        attributes: attributes
            .iter()
            .map(|a| {
                Ok(LdapPartialAttribute {
                    atype: a.to_string(),
                    vals: get_group_attribute(&group, base_dn_str, a)?,
                })
            })
            .collect::<Result<Vec<LdapPartialAttribute>>>()?,
    })
}

fn is_subtree(subtree: &[(String, String)], base_tree: &[(String, String)]) -> bool {
    if subtree.len() < base_tree.len() {
        return false;
    }
    let size_diff = subtree.len() - base_tree.len();
    for i in 0..base_tree.len() {
        if subtree[size_diff + i] != base_tree[i] {
            return false;
        }
    }
    true
}

fn map_field(field: &str) -> Result<String> {
    Ok(if field == "uid" {
        "user_id".to_string()
    } else if field == "mail" {
        "email".to_string()
    } else if field == "cn" || field.to_lowercase() == "displayname" {
        "display_name".to_string()
    } else if field.to_lowercase() == "givenname" {
        "first_name".to_string()
    } else if field == "sn" {
        "last_name".to_string()
    } else if field == "avatar" {
        "avatar".to_string()
    } else if field.to_lowercase() == "creationdate"
        || field.to_lowercase() == "createtimestamp"
        || field.to_lowercase() == "modifytimestamp"
    {
        "creation_date".to_string()
    } else {
        bail!("Unknown field: {}", field);
    })
}

fn make_search_success() -> LdapOp {
    make_search_error(LdapResultCode::Success, "".to_string())
}

fn make_search_error(code: LdapResultCode, message: String) -> LdapOp {
    LdapOp::SearchResultDone(LdapResult {
        code,
        matcheddn: "".to_string(),
        message,
        referral: vec![],
    })
}

fn make_extended_response(code: LdapResultCode, message: String) -> LdapOp {
    LdapOp::ExtendedResponse(LdapExtendedResponse {
        res: LdapResult {
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
                vals: vec!["top".to_string()],
            },
            LdapPartialAttribute {
                atype: "vendorName".to_string(),
                vals: vec!["LLDAP".to_string()],
            },
            LdapPartialAttribute {
                atype: "vendorVersion".to_string(),
                vals: vec!["lldap_0.2.0".to_string()],
            },
            LdapPartialAttribute {
                atype: "supportedLDAPVersion".to_string(),
                vals: vec!["3".to_string()],
            },
            LdapPartialAttribute {
                atype: "supportedExtension".to_string(),
                vals: vec!["1.3.6.1.4.1.4203.1.11.1".to_string()],
            },
            LdapPartialAttribute {
                atype: "defaultnamingcontext".to_string(),
                vals: vec![base_dn.to_string()],
            },
        ],
    })
}

pub struct LdapHandler<Backend: BackendHandler + LoginHandler + OpaqueHandler> {
    dn: String,
    backend_handler: Backend,
    pub base_dn: Vec<(String, String)>,
    base_dn_str: String,
    ldap_user_dn: String,
}

impl<Backend: BackendHandler + LoginHandler + OpaqueHandler> LdapHandler<Backend> {
    pub fn new(backend_handler: Backend, ldap_base_dn: String, ldap_user_dn: String) -> Self {
        Self {
            dn: "Unauthenticated".to_string(),
            backend_handler,
            base_dn: parse_distinguished_name(&ldap_base_dn).unwrap_or_else(|_| {
                panic!(
                    "Invalid value for ldap_base_dn in configuration: {}",
                    ldap_base_dn
                )
            }),
            ldap_user_dn: format!("cn={},ou=people,{}", ldap_user_dn, &ldap_base_dn),
            base_dn_str: ldap_base_dn,
        }
    }

    pub async fn do_bind(&mut self, request: &LdapBindRequest) -> (LdapResultCode, String) {
        debug!(r#"Received bind request for "{}""#, &request.dn);
        let user_id = match get_user_id_from_distinguished_name(
            &request.dn,
            &self.base_dn,
            &self.base_dn_str,
        ) {
            Ok(s) => s,
            Err(e) => return (LdapResultCode::NamingViolation, e.to_string()),
        };
        let LdapBindCred::Simple(password) = &request.cred;
        match self
            .backend_handler
            .bind(BindRequest {
                name: user_id,
                password: password.clone(),
            })
            .await
        {
            Ok(()) => {
                self.dn = request.dn.clone();
                (LdapResultCode::Success, "".to_string())
            }
            Err(_) => (LdapResultCode::InvalidCredentials, "".to_string()),
        }
    }

    async fn change_password(&mut self, user: &str, password: &str) -> Result<()> {
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
    ) -> Vec<LdapOp> {
        match (&request.user_identity, &request.new_password) {
            (Some(user), Some(password)) => {
                match get_user_id_from_distinguished_name(user, &self.base_dn, &self.base_dn_str) {
                    Ok(uid) => {
                        if let Err(e) = self.change_password(&uid, password).await {
                            vec![make_extended_response(
                                LdapResultCode::Other,
                                format!("Error while changing the password: {:#?}", e),
                            )]
                        } else {
                            vec![make_extended_response(
                                LdapResultCode::Success,
                                "".to_string(),
                            )]
                        }
                    }
                    Err(e) => vec![make_extended_response(
                        LdapResultCode::InvalidDNSyntax,
                        format!("Invalid username: {} ({:#?})", user, e),
                    )],
                }
            }
            _ => vec![make_extended_response(
                LdapResultCode::ConstraintViolation,
                "Missing either user_id or password".to_string(),
            )],
        }
    }

    async fn do_extended_request(&mut self, request: &LdapExtendedRequest) -> Vec<LdapOp> {
        match LdapPasswordModifyRequest::try_from(request) {
            Ok(password_request) => self.do_password_modification(&password_request).await,
            Err(_) => vec![make_extended_response(
                LdapResultCode::UnwillingToPerform,
                format!("Unsupported extended operation: {}", &request.name),
            )],
        }
    }

    pub async fn do_search(&mut self, request: &LdapSearchRequest) -> Vec<LdapOp> {
        if self.dn != self.ldap_user_dn {
            return vec![make_search_error(
                LdapResultCode::InsufficentAccessRights,
                format!(
                    r#"Current user `{}` is not allowed to query LDAP, expected {}"#,
                    &self.dn, &self.ldap_user_dn
                ),
            )];
        }
        if request.base.is_empty()
            && request.scope == LdapSearchScope::Base
            && request.filter == LdapFilter::Present("objectClass".to_string())
        {
            debug!("Received rootDSE request");
            return vec![root_dse_response(&self.base_dn_str), make_search_success()];
        }
        debug!("Received search request: {:?}", &request);
        let dn_parts = match parse_distinguished_name(&request.base) {
            Ok(dn) => dn,
            Err(_) => {
                return vec![make_search_error(
                    LdapResultCode::OperationsError,
                    format!(r#"Could not parse base DN: "{}""#, request.base),
                )]
            }
        };
        if !is_subtree(&dn_parts, &self.base_dn) {
            // Search path is not in our tree, just return an empty success.
            warn!(
                "The specified search tree {:?} is not under the common subtree {:?}",
                &dn_parts, &self.base_dn
            );
            return vec![make_search_success()];
        }
        let mut results = Vec::new();
        let mut got_match = false;
        if dn_parts.len() == self.base_dn.len()
            || (dn_parts.len() == self.base_dn.len() + 1
                && dn_parts[0] == ("ou".to_string(), "people".to_string()))
        {
            got_match = true;
            results.extend(self.get_user_list(request).await);
        }
        if dn_parts.len() == self.base_dn.len()
            || (dn_parts.len() == self.base_dn.len() + 1
                && dn_parts[0] == ("ou".to_string(), "groups".to_string()))
        {
            got_match = true;
            results.extend(self.get_groups_list(request).await);
        }
        if !got_match {
            warn!(
                r#"The requested search tree "{}" matches neither the user subtree "ou=people,{}" nor the group subtree "ou=groups,{}""#,
                &request.base, &self.base_dn_str, &self.base_dn_str
            );
        }
        if results.is_empty() || matches!(results[results.len() - 1], LdapOp::SearchResultEntry(_))
        {
            results.push(make_search_success());
        }
        results
    }

    async fn get_user_list(&self, request: &LdapSearchRequest) -> Vec<LdapOp> {
        let filters = match self.convert_user_filter(&request.filter) {
            Ok(f) => Some(f),
            Err(e) => {
                return vec![make_search_error(
                    LdapResultCode::UnwillingToPerform,
                    format!("Unsupported user filter: {:#}", e),
                )]
            }
        };
        let users = match self.backend_handler.list_users(filters).await {
            Ok(users) => users,
            Err(e) => {
                return vec![make_search_error(
                    LdapResultCode::Other,
                    format!(r#"Error during searching user "{}": {:#}"#, request.base, e),
                )]
            }
        };

        users
            .into_iter()
            .map(|u| make_ldap_search_user_result_entry(u, &self.base_dn_str, &request.attrs))
            .map(|entry| Ok(LdapOp::SearchResultEntry(entry?)))
            .collect::<Result<Vec<_>>>()
            .unwrap_or_else(|e| {
                vec![make_search_error(
                    LdapResultCode::NoSuchAttribute,
                    e.to_string(),
                )]
            })
    }

    async fn get_groups_list(&self, request: &LdapSearchRequest) -> Vec<LdapOp> {
        let for_user = match self.get_group_filter(&request.filter) {
            Ok(u) => u,
            Err(e) => {
                return vec![make_search_error(
                    LdapResultCode::UnwillingToPerform,
                    format!("Unsupported group filter: {:#}", e),
                )]
            }
        };

        async fn get_users_for_group<Backend: BackendHandler>(
            backend_handler: &Backend,
            g: &GroupIdAndName,
        ) -> Result<Group> {
            let users = backend_handler
                .list_users(Some(RequestFilter::MemberOfId(g.0)))
                .await?;
            Ok(Group {
                id: g.0,
                display_name: g.1.clone(),
                users: users.into_iter().map(|u| u.user_id).collect(),
            })
        }

        let groups: Vec<Group> = if let Some(user) = for_user {
            let groups_without_users = match self.backend_handler.get_user_groups(&user).await {
                Ok(groups) => groups,
                Err(e) => {
                    return vec![make_search_error(
                        LdapResultCode::Other,
                        format!(
                            r#"Error while listing user groups: "{}": {:#}"#,
                            request.base, e
                        ),
                    )]
                }
            };
            match tokio_stream::iter(groups_without_users.iter())
                .then(|g| async move { get_users_for_group::<Backend>(&self.backend_handler, g).await })
                .try_collect::<Vec<Group>>()
                .await
            {
                Ok(groups) => groups,
                Err(e) => {
                    return vec![make_search_error(
                        LdapResultCode::Other,
                        format!(r#"Error while listing user groups: "{}": {:#}"#, request.base, e),
                    )]
                }
            }
        } else {
            match self.backend_handler.list_groups().await {
                Ok(groups) => groups,
                Err(e) => {
                    return vec![make_search_error(
                        LdapResultCode::Other,
                        format!(r#"Error while listing groups "{}": {:#}"#, request.base, e),
                    )]
                }
            }
        };

        groups
            .into_iter()
            .map(|u| make_ldap_search_group_result_entry(u, &self.base_dn_str, &request.attrs))
            .map(|entry| Ok(LdapOp::SearchResultEntry(entry?)))
            .collect::<Result<Vec<_>>>()
            .unwrap_or_else(|e| {
                vec![make_search_error(
                    LdapResultCode::NoSuchAttribute,
                    e.to_string(),
                )]
            })
    }

    pub async fn handle_ldap_message(&mut self, ldap_op: LdapOp) -> Option<Vec<LdapOp>> {
        Some(match ldap_op {
            LdapOp::BindRequest(request) => {
                let (code, message) = self.do_bind(&request).await;
                vec![LdapOp::BindResponse(LdapBindResponse {
                    res: LdapResult {
                        code,
                        matcheddn: "".to_string(),
                        message,
                        referral: vec![],
                    },
                    saslcreds: None,
                })]
            }
            LdapOp::SearchRequest(request) => self.do_search(&request).await,
            LdapOp::UnbindRequest => {
                self.dn = "Unauthenticated".to_string();
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

    fn get_group_filter(&self, filter: &LdapFilter) -> Result<Option<String>> {
        match filter {
            LdapFilter::Equality(field, value) => {
                if field == "member" || field.to_lowercase() == "uniquemember" {
                    let user_name = get_user_id_from_distinguished_name(
                        value,
                        &self.base_dn,
                        &self.base_dn_str,
                    )?;
                    Ok(Some(user_name))
                } else if field.to_lowercase() == "objectclass" && value == "groupOfUniqueNames" {
                    Ok(None)
                } else {
                    bail!("Unsupported group filter: {:?}", filter)
                }
            }
            LdapFilter::And(v) => v
                .iter()
                .fold(Ok(None), |o, f| Ok(o?.xor(self.get_group_filter(f)?))),
            _ => bail!("Unsupported group filter: {:?}", filter),
        }
    }

    fn convert_user_filter(&self, filter: &LdapFilter) -> Result<RequestFilter> {
        match filter {
            LdapFilter::And(filters) => Ok(RequestFilter::And(
                filters
                    .iter()
                    .map(|f| self.convert_user_filter(f))
                    .collect::<Result<_>>()?,
            )),
            LdapFilter::Or(filters) => Ok(RequestFilter::Or(
                filters
                    .iter()
                    .map(|f| self.convert_user_filter(f))
                    .collect::<Result<_>>()?,
            )),
            LdapFilter::Not(filter) => Ok(RequestFilter::Not(Box::new(
                self.convert_user_filter(&*filter)?,
            ))),
            LdapFilter::Equality(field, value) => {
                if field.to_lowercase() == "memberof" {
                    let group_name = get_group_id_from_distinguished_name(
                        value,
                        &self.base_dn,
                        &self.base_dn_str,
                    )?;
                    Ok(RequestFilter::MemberOf(group_name))
                } else if field.to_lowercase() == "objectclass" {
                    if value == "person"
                        || value == "inetOrgPerson"
                        || value == "posixAccount"
                        || value == "mailAccount"
                    {
                        Ok(RequestFilter::And(vec![]))
                    } else {
                        Ok(RequestFilter::Not(Box::new(RequestFilter::And(vec![]))))
                    }
                } else {
                    Ok(RequestFilter::Equality(map_field(field)?, value.clone()))
                }
            }
            LdapFilter::Present(field) => {
                // Check that it's a field we support.
                if field.to_lowercase() == "objectclass" || map_field(field).is_ok() {
                    Ok(RequestFilter::And(vec![]))
                } else {
                    Ok(RequestFilter::Not(Box::new(RequestFilter::And(vec![]))))
                }
            }
            _ => bail!("Unsupported user filter: {:?}", filter),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::{error::Result, handler::*, opaque_handler::*};
    use async_trait::async_trait;
    use ldap3_server::proto::{LdapDerefAliases, LdapSearchScope};
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
        impl BackendHandler for TestBackendHandler {
            async fn list_users(&self, filters: Option<RequestFilter>) -> Result<Vec<User>>;
            async fn list_groups(&self) -> Result<Vec<Group>>;
            async fn get_user_details(&self, user_id: &str) -> Result<User>;
            async fn get_group_details(&self, group_id: GroupId) -> Result<GroupIdAndName>;
            async fn get_user_groups(&self, user: &str) -> Result<HashSet<GroupIdAndName>>;
            async fn create_user(&self, request: CreateUserRequest) -> Result<()>;
            async fn update_user(&self, request: UpdateUserRequest) -> Result<()>;
            async fn update_group(&self, request: UpdateGroupRequest) -> Result<()>;
            async fn delete_user(&self, user_id: &str) -> Result<()>;
            async fn create_group(&self, group_name: &str) -> Result<GroupId>;
            async fn delete_group(&self, group_id: GroupId) -> Result<()>;
            async fn add_user_to_group(&self, user_id: &str, group_id: GroupId) -> Result<()>;
            async fn remove_user_from_group(&self, user_id: &str, group_id: GroupId) -> Result<()>;
        }
        #[async_trait]
        impl OpaqueHandler for TestBackendHandler {
            async fn login_start(
                &self,
                request: login::ClientLoginStartRequest
            ) -> Result<login::ServerLoginStartResponse>;
            async fn login_finish(&self, request: login::ClientLoginFinishRequest) -> Result<String>;
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
        make_search_request::<S>("ou=people,dc=example,dc=com", filter, attrs)
    }

    async fn setup_bound_handler(
        mut mock: MockTestBackendHandler,
    ) -> LdapHandler<MockTestBackendHandler> {
        mock.expect_bind()
            .with(eq(BindRequest {
                name: "test".to_string(),
                password: "pass".to_string(),
            }))
            .return_once(|_| Ok(()));
        let mut ldap_handler =
            LdapHandler::new(mock, "dc=example,dc=com".to_string(), "test".to_string());
        let request = LdapBindRequest {
            dn: "cn=test,ou=people,dc=example,dc=com".to_string(),
            cred: LdapBindCred::Simple("pass".to_string()),
        };
        assert_eq!(
            ldap_handler.do_bind(&request).await.0,
            LdapResultCode::Success
        );
        ldap_handler
    }

    #[tokio::test]
    async fn test_bind() {
        let mut mock = MockTestBackendHandler::new();
        mock.expect_bind()
            .with(eq(crate::domain::handler::BindRequest {
                name: "bob".to_string(),
                password: "pass".to_string(),
            }))
            .times(1)
            .return_once(|_| Ok(()));
        let mut ldap_handler =
            LdapHandler::new(mock, "dc=example,dc=com".to_string(), "test".to_string());

        let request = LdapOp::BindRequest(LdapBindRequest {
            dn: "cn=bob,ou=people,dc=example,dc=com".to_string(),
            cred: LdapBindCred::Simple("pass".to_string()),
        });
        assert_eq!(
            ldap_handler.handle_ldap_message(request).await,
            Some(vec![LdapOp::BindResponse(LdapBindResponse {
                res: LdapResult {
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
                name: "test".to_string(),
                password: "pass".to_string(),
            }))
            .times(1)
            .return_once(|_| Ok(()));
        let mut ldap_handler =
            LdapHandler::new(mock, "dc=example,dc=com".to_string(), "test".to_string());

        let request = LdapBindRequest {
            dn: "cn=test,ou=people,dc=example,dc=com".to_string(),
            cred: LdapBindCred::Simple("pass".to_string()),
        };
        assert_eq!(
            ldap_handler.do_bind(&request).await.0,
            LdapResultCode::Success
        );
    }

    #[tokio::test]
    async fn test_bind_invalid_credentials() {
        let mut mock = MockTestBackendHandler::new();
        mock.expect_bind()
            .with(eq(crate::domain::handler::BindRequest {
                name: "test".to_string(),
                password: "pass".to_string(),
            }))
            .times(1)
            .return_once(|_| Ok(()));
        let mut ldap_handler =
            LdapHandler::new(mock, "dc=example,dc=com".to_string(), "admin".to_string());

        let request = LdapBindRequest {
            dn: "cn=test,ou=people,dc=example,dc=com".to_string(),
            cred: LdapBindCred::Simple("pass".to_string()),
        };
        assert_eq!(
            ldap_handler.do_bind(&request).await.0,
            LdapResultCode::Success
        );

        let request = make_user_search_request::<String>(LdapFilter::And(vec![]), vec![]);
        assert_eq!(
            ldap_handler.do_search(&request).await,
            vec![make_search_error(
                LdapResultCode::InsufficentAccessRights,
                r#"Current user `cn=test,ou=people,dc=example,dc=com` is not allowed to query LDAP, expected cn=admin,ou=people,dc=example,dc=com"#.to_string()
            )]
        );
    }

    #[tokio::test]
    async fn test_bind_invalid_dn() {
        let mock = MockTestBackendHandler::new();
        let mut ldap_handler =
            LdapHandler::new(mock, "dc=example,dc=com".to_string(), "admin".to_string());

        let request = LdapBindRequest {
            dn: "cn=bob,dc=example,dc=com".to_string(),
            cred: LdapBindCred::Simple("pass".to_string()),
        };
        assert_eq!(
            ldap_handler.do_bind(&request).await.0,
            LdapResultCode::NamingViolation,
        );
        let request = LdapBindRequest {
            dn: "cn=bob,ou=groups,dc=example,dc=com".to_string(),
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
    }

    #[tokio::test]
    async fn test_search_users() {
        use chrono::prelude::*;
        let mut mock = MockTestBackendHandler::new();
        mock.expect_list_users().times(1).return_once(|_| {
            Ok(vec![
                User {
                    user_id: "bob_1".to_string(),
                    email: "bob@bobmail.bob".to_string(),
                    display_name: "Bôb Böbberson".to_string(),
                    first_name: "Bôb".to_string(),
                    last_name: "Böbberson".to_string(),
                    ..Default::default()
                },
                User {
                    user_id: "jim".to_string(),
                    email: "jim@cricket.jim".to_string(),
                    display_name: "Jimminy Cricket".to_string(),
                    first_name: "Jim".to_string(),
                    last_name: "Cricket".to_string(),
                    creation_date: Utc.ymd(2014, 7, 8).and_hms(9, 10, 11),
                },
            ])
        });
        let mut ldap_handler = setup_bound_handler(mock).await;
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
            ],
        );
        assert_eq!(
            ldap_handler.do_search(&request).await,
            vec![
                LdapOp::SearchResultEntry(LdapSearchResultEntry {
                    dn: "cn=bob_1,ou=people,dc=example,dc=com".to_string(),
                    attributes: vec![
                        LdapPartialAttribute {
                            atype: "objectClass".to_string(),
                            vals: vec![
                                "inetOrgPerson".to_string(),
                                "posixAccount".to_string(),
                                "mailAccount".to_string(),
                                "person".to_string()
                            ]
                        },
                        LdapPartialAttribute {
                            atype: "dn".to_string(),
                            vals: vec!["cn=bob_1,ou=people,dc=example,dc=com".to_string()]
                        },
                        LdapPartialAttribute {
                            atype: "uid".to_string(),
                            vals: vec!["bob_1".to_string()]
                        },
                        LdapPartialAttribute {
                            atype: "mail".to_string(),
                            vals: vec!["bob@bobmail.bob".to_string()]
                        },
                        LdapPartialAttribute {
                            atype: "givenName".to_string(),
                            vals: vec!["Bôb".to_string()]
                        },
                        LdapPartialAttribute {
                            atype: "sn".to_string(),
                            vals: vec!["Böbberson".to_string()]
                        },
                        LdapPartialAttribute {
                            atype: "cn".to_string(),
                            vals: vec!["Bôb Böbberson".to_string()]
                        },
                        LdapPartialAttribute {
                            atype: "createTimestamp".to_string(),
                            vals: vec!["1970-01-01T00:00:00+00:00".to_string()]
                        }
                    ],
                }),
                LdapOp::SearchResultEntry(LdapSearchResultEntry {
                    dn: "cn=jim,ou=people,dc=example,dc=com".to_string(),
                    attributes: vec![
                        LdapPartialAttribute {
                            atype: "objectClass".to_string(),
                            vals: vec![
                                "inetOrgPerson".to_string(),
                                "posixAccount".to_string(),
                                "mailAccount".to_string(),
                                "person".to_string()
                            ]
                        },
                        LdapPartialAttribute {
                            atype: "dn".to_string(),
                            vals: vec!["cn=jim,ou=people,dc=example,dc=com".to_string()]
                        },
                        LdapPartialAttribute {
                            atype: "uid".to_string(),
                            vals: vec!["jim".to_string()]
                        },
                        LdapPartialAttribute {
                            atype: "mail".to_string(),
                            vals: vec!["jim@cricket.jim".to_string()]
                        },
                        LdapPartialAttribute {
                            atype: "givenName".to_string(),
                            vals: vec!["Jim".to_string()]
                        },
                        LdapPartialAttribute {
                            atype: "sn".to_string(),
                            vals: vec!["Cricket".to_string()]
                        },
                        LdapPartialAttribute {
                            atype: "cn".to_string(),
                            vals: vec!["Jimminy Cricket".to_string()]
                        },
                        LdapPartialAttribute {
                            atype: "createTimestamp".to_string(),
                            vals: vec!["2014-07-08T09:10:11+00:00".to_string()]
                        }
                    ],
                }),
                make_search_success(),
            ]
        );
    }

    #[tokio::test]
    async fn test_search_groups() {
        let mut mock = MockTestBackendHandler::new();
        mock.expect_list_groups().times(1).return_once(|| {
            Ok(vec![
                Group {
                    id: GroupId(1),
                    display_name: "group_1".to_string(),
                    users: vec!["bob".to_string(), "john".to_string()],
                },
                Group {
                    id: GroupId(3),
                    display_name: "bestgroup".to_string(),
                    users: vec!["john".to_string()],
                },
            ])
        });
        let mut ldap_handler = setup_bound_handler(mock).await;
        let request = make_search_request(
            "ou=groups,dc=example,dc=com",
            LdapFilter::And(vec![]),
            vec!["objectClass", "dn", "cn", "uniqueMember"],
        );
        assert_eq!(
            ldap_handler.do_search(&request).await,
            vec![
                LdapOp::SearchResultEntry(LdapSearchResultEntry {
                    dn: "cn=group_1,ou=groups,dc=example,dc=com".to_string(),
                    attributes: vec![
                        LdapPartialAttribute {
                            atype: "objectClass".to_string(),
                            vals: vec!["groupOfUniqueNames".to_string(),]
                        },
                        LdapPartialAttribute {
                            atype: "dn".to_string(),
                            vals: vec!["cn=group_1,ou=groups,dc=example,dc=com".to_string()]
                        },
                        LdapPartialAttribute {
                            atype: "cn".to_string(),
                            vals: vec!["group_1".to_string()]
                        },
                        LdapPartialAttribute {
                            atype: "uniqueMember".to_string(),
                            vals: vec![
                                "cn=bob,ou=people,dc=example,dc=com".to_string(),
                                "cn=john,ou=people,dc=example,dc=com".to_string(),
                            ]
                        },
                    ],
                }),
                LdapOp::SearchResultEntry(LdapSearchResultEntry {
                    dn: "cn=bestgroup,ou=groups,dc=example,dc=com".to_string(),
                    attributes: vec![
                        LdapPartialAttribute {
                            atype: "objectClass".to_string(),
                            vals: vec!["groupOfUniqueNames".to_string(),]
                        },
                        LdapPartialAttribute {
                            atype: "dn".to_string(),
                            vals: vec!["cn=bestgroup,ou=groups,dc=example,dc=com".to_string()]
                        },
                        LdapPartialAttribute {
                            atype: "cn".to_string(),
                            vals: vec!["bestgroup".to_string()]
                        },
                        LdapPartialAttribute {
                            atype: "uniqueMember".to_string(),
                            vals: vec!["cn=john,ou=people,dc=example,dc=com".to_string()]
                        },
                    ],
                }),
                make_search_success(),
            ]
        );
    }

    #[tokio::test]
    async fn test_search_groups_filter() {
        let mut mock = MockTestBackendHandler::new();
        mock.expect_get_user_groups()
            .with(eq("bob"))
            .times(1)
            .return_once(|_| {
                let mut set = HashSet::new();
                set.insert(GroupIdAndName(GroupId(1), "group_1".to_string()));
                Ok(set)
            });
        mock.expect_list_users()
            .with(eq(Some(RequestFilter::MemberOfId(GroupId(1)))))
            .times(1)
            .return_once(|_| {
                Ok(vec![User {
                    user_id: "bob".to_string(),
                    ..Default::default()
                }])
            });
        let mut ldap_handler = setup_bound_handler(mock).await;
        let request = make_search_request(
            "ou=groups,dc=example,dc=com",
            LdapFilter::And(vec![
                LdapFilter::Equality(
                    "uniqueMember".to_string(),
                    "cn=bob,ou=people,dc=example,dc=com".to_string(),
                ),
                LdapFilter::Equality("objectclass".to_string(), "groupOfUniqueNames".to_string()),
            ]),
            vec!["cn"],
        );
        assert_eq!(
            ldap_handler.do_search(&request).await,
            vec![
                LdapOp::SearchResultEntry(LdapSearchResultEntry {
                    dn: "cn=group_1,ou=groups,dc=example,dc=com".to_string(),
                    attributes: vec![LdapPartialAttribute {
                        atype: "cn".to_string(),
                        vals: vec!["group_1".to_string()]
                    },],
                }),
                make_search_success(),
            ]
        );
    }

    #[tokio::test]
    async fn test_search_filters() {
        let mut mock = MockTestBackendHandler::new();
        mock.expect_list_users()
            .with(eq(Some(RequestFilter::And(vec![RequestFilter::Or(vec![
                RequestFilter::Not(Box::new(RequestFilter::Equality(
                    "user_id".to_string(),
                    "bob".to_string(),
                ))),
            ])]))))
            .times(1)
            .return_once(|_| Ok(vec![]));
        let mut ldap_handler = setup_bound_handler(mock).await;
        let request = make_user_search_request(
            LdapFilter::And(vec![LdapFilter::Or(vec![LdapFilter::Not(Box::new(
                LdapFilter::Equality("uid".to_string(), "bob".to_string()),
            ))])]),
            vec!["objectClass"],
        );
        assert_eq!(
            ldap_handler.do_search(&request).await,
            vec![make_search_success()]
        );
    }

    #[tokio::test]
    async fn test_search_filters_lowercase() {
        let mut mock = MockTestBackendHandler::new();
        mock.expect_list_users()
            .with(eq(Some(RequestFilter::And(vec![RequestFilter::Or(vec![
                RequestFilter::Not(Box::new(RequestFilter::Equality(
                    "first_name".to_string(),
                    "bob".to_string(),
                ))),
            ])]))))
            .times(1)
            .return_once(|_| {
                Ok(vec![User {
                    user_id: "bob_1".to_string(),
                    ..Default::default()
                }])
            });
        let mut ldap_handler = setup_bound_handler(mock).await;
        let request = make_user_search_request(
            LdapFilter::And(vec![LdapFilter::Or(vec![LdapFilter::Not(Box::new(
                LdapFilter::Equality("givenname".to_string(), "bob".to_string()),
            ))])]),
            vec!["objectclass"],
        );
        assert_eq!(
            ldap_handler.do_search(&request).await,
            vec![
                LdapOp::SearchResultEntry(LdapSearchResultEntry {
                    dn: "cn=bob_1,ou=people,dc=example,dc=com".to_string(),
                    attributes: vec![LdapPartialAttribute {
                        atype: "objectclass".to_string(),
                        vals: vec![
                            "inetOrgPerson".to_string(),
                            "posixAccount".to_string(),
                            "mailAccount".to_string(),
                            "person".to_string()
                        ]
                    },]
                }),
                make_search_success()
            ]
        );
    }

    #[tokio::test]
    async fn test_search_both() {
        let mut mock = MockTestBackendHandler::new();
        mock.expect_list_users().times(1).return_once(|_| {
            Ok(vec![User {
                user_id: "bob_1".to_string(),
                email: "bob@bobmail.bob".to_string(),
                display_name: "Bôb Böbberson".to_string(),
                first_name: "Bôb".to_string(),
                last_name: "Böbberson".to_string(),
                ..Default::default()
            }])
        });
        mock.expect_list_groups().times(1).return_once(|| {
            Ok(vec![Group {
                id: GroupId(1),
                display_name: "group_1".to_string(),
                users: vec!["bob".to_string(), "john".to_string()],
            }])
        });
        let mut ldap_handler = setup_bound_handler(mock).await;
        let request = make_search_request(
            "dc=example,dc=com",
            LdapFilter::And(vec![]),
            vec!["objectClass", "dn", "cn"],
        );
        assert_eq!(
            ldap_handler.do_search(&request).await,
            vec![
                LdapOp::SearchResultEntry(LdapSearchResultEntry {
                    dn: "cn=bob_1,ou=people,dc=example,dc=com".to_string(),
                    attributes: vec![
                        LdapPartialAttribute {
                            atype: "objectClass".to_string(),
                            vals: vec![
                                "inetOrgPerson".to_string(),
                                "posixAccount".to_string(),
                                "mailAccount".to_string(),
                                "person".to_string()
                            ]
                        },
                        LdapPartialAttribute {
                            atype: "dn".to_string(),
                            vals: vec!["cn=bob_1,ou=people,dc=example,dc=com".to_string()]
                        },
                        LdapPartialAttribute {
                            atype: "cn".to_string(),
                            vals: vec!["Bôb Böbberson".to_string()]
                        },
                    ],
                }),
                LdapOp::SearchResultEntry(LdapSearchResultEntry {
                    dn: "cn=group_1,ou=groups,dc=example,dc=com".to_string(),
                    attributes: vec![
                        LdapPartialAttribute {
                            atype: "objectClass".to_string(),
                            vals: vec!["groupOfUniqueNames".to_string(),]
                        },
                        LdapPartialAttribute {
                            atype: "dn".to_string(),
                            vals: vec!["cn=group_1,ou=groups,dc=example,dc=com".to_string()]
                        },
                        LdapPartialAttribute {
                            atype: "cn".to_string(),
                            vals: vec!["group_1".to_string()]
                        },
                    ],
                }),
                make_search_success(),
            ]
        );
    }

    #[tokio::test]
    async fn test_search_wrong_base() {
        let mut ldap_handler = setup_bound_handler(MockTestBackendHandler::new()).await;
        let request = make_search_request(
            "ou=users,dc=example,dc=com",
            LdapFilter::And(vec![]),
            vec!["objectClass"],
        );
        assert_eq!(
            ldap_handler.do_search(&request).await,
            vec![make_search_success()]
        );
    }

    #[tokio::test]
    async fn test_search_unsupported_filters() {
        let mut ldap_handler = setup_bound_handler(MockTestBackendHandler::new()).await;
        let request = make_user_search_request(
            LdapFilter::Substring(
                "uid".to_string(),
                ldap3_server::proto::LdapSubstringFilter::default(),
            ),
            vec!["objectClass"],
        );
        assert_eq!(
            ldap_handler.do_search(&request).await,
            vec![make_search_error(
                LdapResultCode::UnwillingToPerform,
                "Unsupported user filter: Unsupported user filter: Substring(\"uid\", LdapSubstringFilter { initial: None, any: [], final_: None })".to_string()
            )]
        );
    }

    #[tokio::test]
    async fn test_search_root_dse() {
        let mut ldap_handler = setup_bound_handler(MockTestBackendHandler::new()).await;
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
            ldap_handler.do_search(&request).await,
            vec![
                root_dse_response("dc=example,dc=com"),
                make_search_success()
            ]
        );
    }
}
