use crate::domain::handler::{
    BackendHandler, BindRequest, Group, GroupIdAndName, LoginHandler, RequestFilter, User,
};
use anyhow::{bail, Result};
use futures::stream::StreamExt;
use futures_util::TryStreamExt;
use ldap3_server::proto::{
    LdapBindCred, LdapBindRequest, LdapBindResponse, LdapExtendedResponse, LdapFilter, LdapOp,
    LdapPartialAttribute, LdapResult, LdapResultCode, LdapSearchRequest, LdapSearchResultEntry,
};
use log::*;

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
    let parts = parse_distinguished_name(dn)?;
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
    let parts = parse_distinguished_name(dn)?;
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
    match attribute {
        "objectClass" => Ok(vec![
            "inetOrgPerson".to_string(),
            "posixAccount".to_string(),
            "mailAccount".to_string(),
            "person".to_string(),
        ]),
        "dn" => Ok(vec![dn.to_string()]),
        "uid" => Ok(vec![user.user_id.clone()]),
        "mail" => Ok(vec![user.email.clone()]),
        "givenName" => Ok(vec![user.first_name.clone()]),
        "sn" => Ok(vec![user.last_name.clone()]),
        "cn" => Ok(vec![user.display_name.clone()]),
        "displayName" => Ok(vec![user.display_name.clone()]),
        "supportedExtension" => Ok(vec![]),
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
    match attribute {
        "objectClass" => Ok(vec!["groupOfUniqueNames".to_string()]),
        "cn" => Ok(vec![group.display_name.clone()]),
        "uniqueMember" => Ok(group
            .users
            .iter()
            .map(|u| format!("cn={},ou=people,{}", u, base_dn_str))
            .collect()),
        "supportedExtension" => Ok(vec![]),
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
    } else if field == "cn" || field == "displayName" {
        "display_name".to_string()
    } else if field == "givenName" {
        "first_name".to_string()
    } else if field == "sn" {
        "last_name".to_string()
    } else if field == "avatar" {
        "avatar".to_string()
    } else if field == "creationDate" {
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

pub struct LdapHandler<Backend: BackendHandler + LoginHandler> {
    dn: String,
    backend_handler: Backend,
    pub base_dn: Vec<(String, String)>,
    base_dn_str: String,
    ldap_user_dn: String,
}

impl<Backend: BackendHandler + LoginHandler> LdapHandler<Backend> {
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
        info!(r#"Received bind request for "{}""#, &request.dn);
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

    pub async fn do_search(&mut self, request: &LdapSearchRequest) -> Vec<LdapOp> {
        info!(
            "Received search request with filters: {:?}",
            &request.filter
        );
        if self.dn != self.ldap_user_dn {
            return vec![make_search_error(
                LdapResultCode::InsufficentAccessRights,
                format!(
                    r#"Current user `{}` is not allowed to query LDAP, expected {}"#,
                    &self.dn, &self.ldap_user_dn
                ),
            )];
        }
        let dn_parts = if request.base.is_empty() {
            self.base_dn.clone()
        } else {
            match parse_distinguished_name(&request.base) {
                Ok(dn) => dn,
                Err(_) => {
                    return vec![make_search_error(
                        LdapResultCode::OperationsError,
                        format!(r#"Could not parse base DN: "{}""#, request.base),
                    )]
                }
            }
        };
        if !is_subtree(&dn_parts, &self.base_dn) {
            // Search path is not in our tree, just return an empty success.
            return vec![make_search_success()];
        }
        let mut results = Vec::new();
        if dn_parts.len() == self.base_dn.len()
            || (dn_parts.len() == self.base_dn.len() + 1
                && dn_parts[0] == ("ou".to_string(), "people".to_string()))
        {
            results.extend(self.get_user_list(request).await);
        }
        if dn_parts.len() == self.base_dn.len() + 1
            && dn_parts[0] == ("ou".to_string(), "groups".to_string())
        {
            results.extend(self.get_groups_list(request).await);
        }
        results
    }

    async fn get_user_list(&self, request: &LdapSearchRequest) -> Vec<LdapOp> {
        let filters = match self.convert_user_filter(&request.filter) {
            Ok(f) => Some(f),
            Err(e) => {
                return vec![make_search_error(
                    LdapResultCode::UnwillingToPerform,
                    format!("Unsupported user filter: {}", e),
                )]
            }
        };
        let users = match self.backend_handler.list_users(filters).await {
            Ok(users) => users,
            Err(e) => {
                return vec![make_search_error(
                    LdapResultCode::Other,
                    format!(r#"Error during searching user "{}": {}"#, request.base, e),
                )]
            }
        };

        users
            .into_iter()
            .map(|u| make_ldap_search_user_result_entry(u, &self.base_dn_str, &request.attrs))
            .map(|entry| Ok(LdapOp::SearchResultEntry(entry?)))
            // If the processing succeeds, add a success message at the end.
            .chain(std::iter::once(Ok(make_search_success())))
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
                    format!("Unsupported group filter: {}", e),
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
                            r#"Error while listing user groups: "{}": {}"#,
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
                        format!(r#"Error while listing user groups: "{}": {}"#, request.base, e),
                    )]
                }
            }
        } else {
            match self.backend_handler.list_groups().await {
                Ok(groups) => groups,
                Err(e) => {
                    return vec![make_search_error(
                        LdapResultCode::Other,
                        format!(r#"Error while listing groups "{}": {}"#, request.base, e),
                    )]
                }
            }
        };

        groups
            .into_iter()
            .map(|u| make_ldap_search_group_result_entry(u, &self.base_dn_str, &request.attrs))
            .map(|entry| Ok(LdapOp::SearchResultEntry(entry?)))
            // If the processing succeeds, add a success message at the end.
            .chain(std::iter::once(Ok(make_search_success())))
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
            op => vec![LdapOp::ExtendedResponse(LdapExtendedResponse {
                res: LdapResult {
                    code: LdapResultCode::UnwillingToPerform,
                    matcheddn: "".to_string(),
                    message: format!("Unsupported operation: {:#?}", op),
                    referral: vec![],
                },
                name: None,
                value: None,
            })],
        })
    }

    fn get_group_filter(&self, filter: &LdapFilter) -> Result<Option<String>> {
        match filter {
            LdapFilter::Equality(field, value) => {
                if field == "member" || field == "uniqueMember" {
                    let user_name = get_user_id_from_distinguished_name(
                        value,
                        &self.base_dn,
                        &self.base_dn_str,
                    )?;
                    Ok(Some(user_name))
                } else if field == "objectClass" && value == "groupOfUniqueNames" {
                    Ok(None)
                } else {
                    bail!("Unsupported group filter: {:?}", filter)
                }
            }
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
                if field == "memberOf" {
                    let group_name = get_group_id_from_distinguished_name(
                        value,
                        &self.base_dn,
                        &self.base_dn_str,
                    )?;
                    Ok(RequestFilter::MemberOf(group_name))
                } else if field == "objectClass" {
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
                if field == "objectClass" || map_field(field).is_ok() {
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
    use crate::domain::handler::{BindRequest, MockTestBackendHandler};
    use ldap3_server::proto::{LdapDerefAliases, LdapSearchScope};
    use mockall::predicate::eq;
    use tokio;

    fn make_search_request<S: Into<String>>(
        filter: LdapFilter,
        attrs: Vec<S>,
    ) -> LdapSearchRequest {
        LdapSearchRequest {
            base: "ou=people,dc=example,dc=com".to_string(),
            scope: LdapSearchScope::Base,
            aliases: LdapDerefAliases::Never,
            sizelimit: 0,
            timelimit: 0,
            typesonly: false,
            filter,
            attrs: attrs.into_iter().map(Into::into).collect(),
        }
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

        let request = LdapBindRequest {
            dn: "cn=bob,ou=people,dc=example,dc=com".to_string(),
            cred: LdapBindCred::Simple("pass".to_string()),
        };
        assert_eq!(
            ldap_handler.do_bind(&request).await.0,
            LdapResultCode::Success
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

        let request = make_search_request::<String>(LdapFilter::And(vec![]), vec![]);
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
    async fn test_search() {
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
                    ..Default::default()
                },
            ])
        });
        let mut ldap_handler = setup_bound_handler(mock).await;
        let request = make_search_request(
            LdapFilter::And(vec![]),
            vec!["objectClass", "dn", "uid", "mail", "givenName", "sn", "cn"],
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
                        }
                    ],
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
        let request = make_search_request(
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
    async fn test_search_unsupported_filters() {
        let mut ldap_handler = setup_bound_handler(MockTestBackendHandler::new()).await;
        let request = make_search_request(
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
}
