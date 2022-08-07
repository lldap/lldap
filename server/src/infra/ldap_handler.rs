use crate::{
    domain::{
        handler::{
            BackendHandler, BindRequest, Group, GroupDetails, GroupRequestFilter, LoginHandler,
            User, UserId, UserRequestFilter, Uuid,
        },
        opaque_handler::OpaqueHandler,
    },
    infra::auth_service::{Permission, ValidationResults},
};
use anyhow::{bail, Context, Result};
use itertools::Itertools;
use ldap3_proto::proto::{
    LdapBindCred, LdapBindRequest, LdapBindResponse, LdapExtendedRequest, LdapExtendedResponse,
    LdapFilter, LdapOp, LdapPartialAttribute, LdapPasswordModifyRequest, LdapResult,
    LdapResultCode, LdapSearchRequest, LdapSearchResultEntry, LdapSearchScope,
};
use tracing::{debug, info, instrument, warn};

#[derive(Debug, PartialEq, Eq, Clone)]
struct LdapDn(String);

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
    assert!(dn == dn.to_ascii_lowercase());
    dn.split(',')
        .map(|s| make_dn_pair(s.split('=').map(str::trim).map(String::from)))
        .collect()
}

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
) -> Result<UserId> {
    let parts = parse_distinguished_name(dn).context("while parsing a user ID")?;
    if !is_subtree(&parts, base_tree) {
        bail!("Not a subtree of the base tree");
    }
    if parts.len() == base_tree.len() + 2 {
        if parts[1].0 != "ou"
            || parts[1].1 != "people"
            || (parts[0].0 != "cn" && parts[0].0 != "uid")
        {
            bail!(
                r#"Unexpected user DN format. Got "{}", expected: "uid=username,ou=people,{}""#,
                dn,
                base_dn_str
            );
        }
        Ok(UserId::new(&parts[0].1))
    } else {
        bail!(
            r#"Unexpected user DN format. Got "{}", expected: "uid=username,ou=people,{}""#,
            dn,
            base_dn_str
        );
    }
}

fn get_user_attribute(
    user: &User,
    attribute: &str,
    base_dn_str: &str,
    groups: Option<&[GroupDetails]>,
    ignored_user_attributes: &[String],
) -> Result<Option<Vec<Vec<u8>>>> {
    let attribute = attribute.to_ascii_lowercase();
    let attribute_values = match attribute.as_str() {
        "objectclass" => vec![
            b"inetOrgPerson".to_vec(),
            b"posixAccount".to_vec(),
            b"mailAccount".to_vec(),
            b"person".to_vec(),
        ],
        // dn is always returned as part of the base response.
        "dn" | "distinguishedname" => return Ok(None),
        "uid" => vec![user.user_id.to_string().into_bytes()],
        "entryuuid" => vec![user.uuid.to_string().into_bytes()],
        "mail" => vec![user.email.clone().into_bytes()],
        "givenname" => vec![user.first_name.clone().into_bytes()],
        "sn" => vec![user.last_name.clone().into_bytes()],
        "jpegphoto" => vec![user.avatar.clone().into_bytes()],
        "memberof" => groups
            .into_iter()
            .flatten()
            .map(|id_and_name| {
                format!(
                    "uid={},ou=groups,{}",
                    &id_and_name.display_name, base_dn_str
                )
                .into_bytes()
            })
            .collect(),
        "cn" | "displayname" => vec![user.display_name.clone().into_bytes()],
        "createtimestamp" | "modifytimestamp" => vec![user.creation_date.to_rfc3339().into_bytes()],
        "1.1" => return Ok(None),
        // We ignore the operational attribute wildcard.
        "+" => return Ok(None),
        "*" => {
            bail!(
                "Matched {}, * should have been expanded into attribute list and * removed",
                attribute
            )
        }
        _ => {
            if !ignored_user_attributes.contains(&attribute) {
                warn!(
                    r#"Ignoring unrecognized group attribute: {}\n\
                      To disable this warning, add it to "ignored_user_attributes" in the config."#,
                    attribute
                );
            }
            return Ok(None);
        }
    };
    if attribute_values.len() == 1 && attribute_values[0].is_empty() {
        Ok(None)
    } else {
        Ok(Some(attribute_values))
    }
}

#[instrument(skip_all, level = "debug")]
fn expand_attribute_wildcards<'a>(
    ldap_attributes: &'a [String],
    all_attribute_keys: &'a [&'static str],
) -> Vec<&'a str> {
    let mut attributes_out = ldap_attributes
        .iter()
        .map(String::as_str)
        .collect::<Vec<_>>();

    if attributes_out.iter().any(|&x| x == "*") || attributes_out.is_empty() {
        // Remove occurrences of '*'
        attributes_out.retain(|&x| x != "*");
        // Splice in all non-operational attributes
        attributes_out.extend(all_attribute_keys.iter());
    }

    // Deduplicate, preserving order
    let resolved_attributes = attributes_out
        .into_iter()
        .unique_by(|a| a.to_ascii_lowercase())
        .collect_vec();
    debug!(?ldap_attributes, ?resolved_attributes);
    resolved_attributes
}

const ALL_USER_ATTRIBUTE_KEYS: &[&str] = &[
    "objectclass",
    "uid",
    "mail",
    "givenname",
    "sn",
    "cn",
    "jpegPhoto",
    "createtimestamp",
];

fn make_ldap_search_user_result_entry(
    user: User,
    base_dn_str: &str,
    attributes: &[&str],
    groups: Option<&[GroupDetails]>,
    ignored_user_attributes: &[String],
) -> Result<LdapSearchResultEntry> {
    let dn = format!("uid={},ou=people,{}", user.user_id.as_str(), base_dn_str);

    Ok(LdapSearchResultEntry {
        dn,
        attributes: attributes
            .iter()
            .filter_map(|a| {
                let values = match get_user_attribute(
                    &user,
                    a,
                    base_dn_str,
                    groups,
                    ignored_user_attributes,
                ) {
                    Err(e) => return Some(Err(e)),
                    Ok(v) => v,
                }?;
                Some(Ok(LdapPartialAttribute {
                    atype: a.to_string(),
                    vals: values,
                }))
            })
            .collect::<Result<Vec<LdapPartialAttribute>>>()?,
    })
}

fn get_group_attribute(
    group: &Group,
    base_dn_str: &str,
    attribute: &str,
    user_filter: &Option<&UserId>,
    ignored_group_attributes: &[String],
) -> Result<Option<Vec<Vec<u8>>>> {
    let attribute = attribute.to_ascii_lowercase();
    let attribute_values = match attribute.as_str() {
        "objectclass" => vec![b"groupOfUniqueNames".to_vec()],
        // Always returned as part of the base response.
        "dn" | "distinguishedname" => return Ok(None),
        "cn" | "uid" => vec![group.display_name.clone().into_bytes()],
        "entryuuid" => vec![group.uuid.to_string().into_bytes()],
        "member" | "uniquemember" => group
            .users
            .iter()
            .filter(|u| user_filter.map(|f| *u == f).unwrap_or(true))
            .map(|u| format!("uid={},ou=people,{}", u, base_dn_str).into_bytes())
            .collect(),
        "1.1" => return Ok(None),
        // We ignore the operational attribute wildcard
        "+" => return Ok(None),
        "*" => {
            bail!(
                "Matched {}, * should have been expanded into attribute list and * removed",
                attribute
            )
        }
        _ => {
            if !ignored_group_attributes.contains(&attribute) {
                warn!(
                    r#"Ignoring unrecognized group attribute: {}\n\
                      To disable this warning, add it to "ignored_group_attributes" in the config."#,
                    attribute
                );
            }
            return Ok(None);
        }
    };
    if attribute_values.len() == 1 && attribute_values[0].is_empty() {
        Ok(None)
    } else {
        Ok(Some(attribute_values))
    }
}

const ALL_GROUP_ATTRIBUTE_KEYS: &[&str] = &["objectclass", "uid", "cn", "member", "uniquemember"];

fn make_ldap_search_group_result_entry(
    group: Group,
    base_dn_str: &str,
    attributes: &[String],
    user_filter: &Option<&UserId>,
    ignored_group_attributes: &[String],
) -> Result<LdapSearchResultEntry> {
    let expanded_attributes = expand_attribute_wildcards(attributes, ALL_GROUP_ATTRIBUTE_KEYS);

    Ok(LdapSearchResultEntry {
        dn: format!("cn={},ou=groups,{}", group.display_name, base_dn_str),
        attributes: expanded_attributes
            .iter()
            .filter_map(|a| {
                let values = match get_group_attribute(
                    &group,
                    base_dn_str,
                    a,
                    user_filter,
                    ignored_group_attributes,
                ) {
                    Err(e) => return Some(Err(e)),
                    Ok(v) => v,
                }?;
                Some(Ok(LdapPartialAttribute {
                    atype: a.to_string(),
                    vals: values,
                }))
            })
            .collect::<Result<Vec<LdapPartialAttribute>>>()?,
    })
}

fn is_subtree(subtree: &[(String, String)], base_tree: &[(String, String)]) -> bool {
    for (k, v) in subtree {
        assert!(k == &k.to_ascii_lowercase());
        assert!(v == &v.to_ascii_lowercase());
    }
    for (k, v) in base_tree {
        assert!(k == &k.to_ascii_lowercase());
        assert!(v == &v.to_ascii_lowercase());
    }
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

fn map_field(field: &str) -> Result<&'static str> {
    assert!(field == field.to_ascii_lowercase());
    Ok(match field {
        "uid" => "user_id",
        "mail" => "email",
        "cn" | "displayname" => "display_name",
        "givenname" => "first_name",
        "sn" => "last_name",
        "avatar" => "avatar",
        "creationdate" | "createtimestamp" | "modifytimestamp" => "creation_date",
        "entryuuid" => "uuid",
        _ => bail!("Unknown field: {}", field),
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
                vals: vec![b"top".to_vec()],
            },
            LdapPartialAttribute {
                atype: "vendorName".to_string(),
                vals: vec![b"LLDAP".to_vec()],
            },
            LdapPartialAttribute {
                atype: "vendorVersion".to_string(),
                vals: vec![b"lldap_0.2.0".to_vec()],
            },
            LdapPartialAttribute {
                atype: "supportedLDAPVersion".to_string(),
                vals: vec![b"3".to_vec()],
            },
            LdapPartialAttribute {
                atype: "supportedExtension".to_string(),
                vals: vec![b"1.3.6.1.4.1.4203.1.11.1".to_vec()],
            },
            LdapPartialAttribute {
                atype: "defaultnamingcontext".to_string(),
                vals: vec![base_dn.to_string().into_bytes()],
            },
        ],
    })
}

pub struct LdapHandler<Backend: BackendHandler + LoginHandler + OpaqueHandler> {
    user_info: Option<ValidationResults>,
    backend_handler: Backend,
    pub base_dn: Vec<(String, String)>,
    base_dn_str: String,
    ignored_user_attributes: Vec<String>,
    ignored_group_attributes: Vec<String>,
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
            base_dn: parse_distinguished_name(&ldap_base_dn).unwrap_or_else(|_| {
                panic!(
                    "Invalid value for ldap_base_dn in configuration: {}",
                    ldap_base_dn
                )
            }),
            base_dn_str: ldap_base_dn,
            ignored_user_attributes,
            ignored_group_attributes,
        }
    }

    #[instrument(skip_all, level = "debug")]
    pub async fn do_bind(&mut self, request: &LdapBindRequest) -> (LdapResultCode, String) {
        debug!("DN: {}", &request.dn);
        let user_id = match get_user_id_from_distinguished_name(
            &request.dn.to_ascii_lowercase(),
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
    ) -> Vec<LdapOp> {
        let credentials = match &self.user_info {
            Some(info) => info,
            _ => {
                return vec![make_search_error(
                    LdapResultCode::InsufficentAccessRights,
                    "No user currently bound".to_string(),
                )];
            }
        };
        match (&request.user_identity, &request.new_password) {
            (Some(user), Some(password)) => {
                match get_user_id_from_distinguished_name(user, &self.base_dn, &self.base_dn_str) {
                    Ok(uid) => {
                        let user_is_admin = match self.backend_handler.get_user_groups(&uid).await {
                            Ok(groups) => groups.iter().any(|g| g.display_name == "lldap_admin"),
                            Err(e) => {
                                return vec![make_extended_response(
                                    LdapResultCode::OperationsError,
                                    format!(
                                        "Internal error while requesting user's groups: {:#?}",
                                        e
                                    ),
                                )]
                            }
                        };
                        if !credentials.can_change_password(&uid, user_is_admin) {
                            return vec![make_extended_response(
                                LdapResultCode::InsufficentAccessRights,
                                format!(
                                    r#"User `{}` cannot modify the password of user `{}`"#,
                                    &credentials.user, &uid
                                ),
                            )];
                        }
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
                        format!("Invalid username: {:#?}", e),
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

    pub async fn do_search_or_dse(&mut self, request: &LdapSearchRequest) -> Vec<LdapOp> {
        let user_info = match &self.user_info {
            None => {
                return vec![make_search_error(
                    LdapResultCode::InsufficentAccessRights,
                    "No user currently bound".to_string(),
                )]
            }
            Some(u) => u,
        };
        if request.base.is_empty()
            && request.scope == LdapSearchScope::Base
            && request.filter == LdapFilter::Present("objectClass".to_string())
        {
            debug!("rootDSE request");
            return vec![root_dse_response(&self.base_dn_str), make_search_success()];
        }
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
    ) -> Vec<LdapOp> {
        let user_filter = user_filter.as_ref();
        let dn_parts = match parse_distinguished_name(&request.base.to_ascii_lowercase()) {
            Ok(dn) => dn,
            Err(_) => {
                return vec![make_search_error(
                    LdapResultCode::OperationsError,
                    format!(r#"Could not parse base DN: "{}""#, request.base),
                )]
            }
        };
        let scope = get_search_scope(&self.base_dn, &dn_parts);
        debug!(?request.base, ?scope);
        let get_user_list = || async {
            self.get_user_list(&request.filter, &request.attrs, &request.base, &user_filter)
                .await
        };
        let get_group_list = || async {
            self.get_groups_list(&request.filter, &request.attrs, &request.base, &user_filter)
                .await
        };
        let mut results = match scope {
            SearchScope::Global => {
                let mut results = Vec::new();
                results.extend(get_user_list().await);
                results.extend(get_group_list().await);
                results
            }
            SearchScope::Users => get_user_list().await,
            SearchScope::Groups => get_group_list().await,
            SearchScope::User(filter) => {
                let filter = LdapFilter::And(vec![request.filter.clone(), filter]);
                self.get_user_list(&filter, &request.attrs, &request.base, &user_filter)
                    .await
            }
            SearchScope::Group(filter) => {
                let filter = LdapFilter::And(vec![request.filter.clone(), filter]);
                self.get_groups_list(&filter, &request.attrs, &request.base, &user_filter)
                    .await
            }
            SearchScope::Unknown => {
                warn!(
                    r#"The requested search tree "{}" matches neither the user subtree "ou=people,{}" nor the group subtree "ou=groups,{}""#,
                    &request.base, &self.base_dn_str, &self.base_dn_str
                );
                Vec::new()
            }
            SearchScope::Invalid => {
                // Search path is not in our tree, just return an empty success.
                warn!(
                    "The specified search tree {:?} is not under the common subtree {:?}",
                    &dn_parts, &self.base_dn
                );
                Vec::new()
            }
        };
        if results.is_empty() || matches!(results[results.len() - 1], LdapOp::SearchResultEntry(_))
        {
            results.push(make_search_success());
        }
        results
    }

    #[instrument(skip_all, level = "debug")]
    async fn get_user_list(
        &self,
        ldap_filter: &LdapFilter,
        attributes: &[String],
        base: &str,
        user_filter: &Option<&UserId>,
    ) -> Vec<LdapOp> {
        debug!(?ldap_filter);
        let filters = match self.convert_user_filter(ldap_filter) {
            Ok(f) => f,
            Err(e) => {
                return vec![make_search_error(
                    LdapResultCode::UnwillingToPerform,
                    format!("Unsupported user filter: {:#}", e),
                )]
            }
        };
        let parsed_filters = match user_filter {
            None => filters,
            Some(u) => {
                info!("Unpriviledged search, limiting results");
                UserRequestFilter::And(vec![filters, UserRequestFilter::UserId((*u).clone())])
            }
        };
        debug!(?parsed_filters);
        let expanded_attributes = expand_attribute_wildcards(attributes, ALL_USER_ATTRIBUTE_KEYS);
        let need_groups = expanded_attributes
            .iter()
            .any(|s| s.to_ascii_lowercase() == "memberof");
        let users = match self
            .backend_handler
            .list_users(Some(parsed_filters), need_groups)
            .await
        {
            Ok(users) => users,
            Err(e) => {
                return vec![make_search_error(
                    LdapResultCode::Other,
                    format!(r#"Error while searching user "{}": {:#}"#, base, e),
                )]
            }
        };

        users
            .into_iter()
            .map(|u| {
                make_ldap_search_user_result_entry(
                    u.user,
                    &self.base_dn_str,
                    &expanded_attributes,
                    u.groups.as_deref(),
                    &self.ignored_user_attributes,
                )
            })
            .map(|entry| Ok(LdapOp::SearchResultEntry(entry?)))
            .collect::<Result<Vec<_>>>()
            .unwrap_or_else(|e| {
                vec![make_search_error(
                    LdapResultCode::NoSuchAttribute,
                    e.to_string(),
                )]
            })
    }

    #[instrument(skip_all, level = "debug")]
    async fn get_groups_list(
        &self,
        ldap_filter: &LdapFilter,
        attributes: &[String],
        base: &str,
        user_filter: &Option<&UserId>,
    ) -> Vec<LdapOp> {
        debug!(?ldap_filter);
        let filter = match self.convert_group_filter(ldap_filter) {
            Ok(f) => f,
            Err(e) => {
                return vec![make_search_error(
                    LdapResultCode::UnwillingToPerform,
                    format!("Unsupported group filter: {:#}", e),
                )]
            }
        };
        let parsed_filters = match user_filter {
            None => filter,
            Some(u) => {
                info!("Unpriviledged search, limiting results");
                GroupRequestFilter::And(vec![filter, GroupRequestFilter::Member((*u).clone())])
            }
        };
        debug!(?parsed_filters);
        let groups = match self.backend_handler.list_groups(Some(parsed_filters)).await {
            Ok(groups) => groups,
            Err(e) => {
                return vec![make_search_error(
                    LdapResultCode::Other,
                    format!(r#"Error while listing groups "{}": {:#}"#, base, e),
                )]
            }
        };

        groups
            .into_iter()
            .map(|u| {
                make_ldap_search_group_result_entry(
                    u,
                    &self.base_dn_str,
                    attributes,
                    user_filter,
                    &self.ignored_group_attributes,
                )
            })
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
            LdapOp::SearchRequest(request) => self.do_search_or_dse(&request).await,
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

    fn convert_group_filter(&self, filter: &LdapFilter) -> Result<GroupRequestFilter> {
        match filter {
            LdapFilter::Equality(field, value) => {
                let field = &field.to_ascii_lowercase();
                let value = &value.to_ascii_lowercase();
                match field.as_str() {
                    "member" | "uniquemember" => {
                        let user_name = get_user_id_from_distinguished_name(
                            value,
                            &self.base_dn,
                            &self.base_dn_str,
                        )?;
                        Ok(GroupRequestFilter::Member(user_name))
                    }
                    "objectclass" => match value.as_str() {
                        "groupofuniquenames" | "groupofnames" => {
                            Ok(GroupRequestFilter::And(vec![]))
                        }
                        _ => Ok(GroupRequestFilter::Not(Box::new(GroupRequestFilter::And(
                            vec![],
                        )))),
                    },
                    _ => {
                        match map_field(field) {
                            Ok("display_name") | Ok("user_id") => {
                                return Ok(GroupRequestFilter::DisplayName(value.to_string()));
                            }
                            Ok("uuid") => {
                                return Ok(GroupRequestFilter::Uuid(Uuid::try_from(
                                    value.as_str(),
                                )?));
                            }
                            _ => (),
                        };
                        if !self.ignored_group_attributes.contains(field) {
                            warn!(
                                r#"Ignoring unknown group attribute "{:?}" in filter.\n\
                                To disable this warning, add it to "ignored_group_attributes" in the config."#,
                                field
                            );
                        }
                        Ok(GroupRequestFilter::Not(Box::new(GroupRequestFilter::And(
                            vec![],
                        ))))
                    }
                }
            }
            LdapFilter::And(filters) => Ok(GroupRequestFilter::And(
                filters
                    .iter()
                    .map(|f| self.convert_group_filter(f))
                    .collect::<Result<_>>()?,
            )),
            LdapFilter::Or(filters) => Ok(GroupRequestFilter::Or(
                filters
                    .iter()
                    .map(|f| self.convert_group_filter(f))
                    .collect::<Result<_>>()?,
            )),
            LdapFilter::Not(filter) => Ok(GroupRequestFilter::Not(Box::new(
                self.convert_group_filter(filter)?,
            ))),
            LdapFilter::Present(field) => {
                let field = &field.to_ascii_lowercase();
                if field == "dn"
                    || field == "distinguishedname"
                    || ALL_GROUP_ATTRIBUTE_KEYS.contains(&field.as_str())
                {
                    Ok(GroupRequestFilter::And(vec![]))
                } else {
                    Ok(GroupRequestFilter::Not(Box::new(GroupRequestFilter::And(
                        vec![],
                    ))))
                }
            }
            _ => bail!("Unsupported group filter: {:?}", filter),
        }
    }

    fn convert_user_filter(&self, filter: &LdapFilter) -> Result<UserRequestFilter> {
        match filter {
            LdapFilter::And(filters) => Ok(UserRequestFilter::And(
                filters
                    .iter()
                    .map(|f| self.convert_user_filter(f))
                    .collect::<Result<_>>()?,
            )),
            LdapFilter::Or(filters) => Ok(UserRequestFilter::Or(
                filters
                    .iter()
                    .map(|f| self.convert_user_filter(f))
                    .collect::<Result<_>>()?,
            )),
            LdapFilter::Not(filter) => Ok(UserRequestFilter::Not(Box::new(
                self.convert_user_filter(filter)?,
            ))),
            LdapFilter::Equality(field, value) => {
                let field = &field.to_ascii_lowercase();
                match field.as_str() {
                    "memberof" => {
                        let group_name = get_group_id_from_distinguished_name(
                            &value.to_ascii_lowercase(),
                            &self.base_dn,
                            &self.base_dn_str,
                        )?;
                        Ok(UserRequestFilter::MemberOf(group_name))
                    }
                    "objectclass" => match value.to_ascii_lowercase().as_str() {
                        "person" | "inetorgperson" | "posixaccount" | "mailaccount" => {
                            Ok(UserRequestFilter::And(vec![]))
                        }
                        _ => Ok(UserRequestFilter::Not(Box::new(UserRequestFilter::And(
                            vec![],
                        )))),
                    },
                    _ => match map_field(field) {
                        Ok(field) => {
                            if field == "user_id" {
                                Ok(UserRequestFilter::UserId(UserId::new(value)))
                            } else {
                                Ok(UserRequestFilter::Equality(
                                    field.to_string(),
                                    value.clone(),
                                ))
                            }
                        }
                        Err(_) => {
                            if !self.ignored_user_attributes.contains(field) {
                                warn!(
                                    r#"Ignoring unknown user attribute "{}" in filter.\n\
                                      To disable this warning, add it to "ignored_user_attributes" in the config"#,
                                    field
                                );
                            }
                            Ok(UserRequestFilter::Not(Box::new(UserRequestFilter::And(
                                vec![],
                            ))))
                        }
                    },
                }
            }
            LdapFilter::Present(field) => {
                let field = &field.to_ascii_lowercase();
                // Check that it's a field we support.
                if field == "objectclass"
                    || field == "dn"
                    || field == "distinguishedname"
                    || map_field(field).is_ok()
                {
                    Ok(UserRequestFilter::And(vec![]))
                } else {
                    Ok(UserRequestFilter::Not(Box::new(UserRequestFilter::And(
                        vec![],
                    ))))
                }
            }
            _ => bail!("Unsupported user filter: {:?}", filter),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        domain::{error::Result, handler::*, opaque_handler::*},
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
        impl BackendHandler for TestBackendHandler {
            async fn list_users(&self, filters: Option<UserRequestFilter>, get_groups: bool) -> Result<Vec<UserAndGroups>>;
            async fn list_groups(&self, filters: Option<GroupRequestFilter>) -> Result<Vec<Group>>;
            async fn get_user_details(&self, user_id: &UserId) -> Result<User>;
            async fn get_group_details(&self, group_id: GroupId) -> Result<GroupDetails>;
            async fn get_user_groups(&self, user: &UserId) -> Result<HashSet<GroupDetails>>;
            async fn create_user(&self, request: CreateUserRequest) -> Result<()>;
            async fn update_user(&self, request: UpdateUserRequest) -> Result<()>;
            async fn update_group(&self, request: UpdateGroupRequest) -> Result<()>;
            async fn delete_user(&self, user_id: &UserId) -> Result<()>;
            async fn create_group(&self, group_name: &str) -> Result<GroupId>;
            async fn delete_group(&self, group_id: GroupId) -> Result<()>;
            async fn add_user_to_group(&self, user_id: &UserId, group_id: GroupId) -> Result<()>;
            async fn remove_user_from_group(&self, user_id: &UserId, group_id: GroupId) -> Result<()>;
        }
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
            vec![
                LdapOp::SearchResultEntry(LdapSearchResultEntry {
                    dn: "uid=test,ou=people,dc=example,dc=com".to_string(),
                    attributes: vec![],
                }),
                make_search_success()
            ],
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
            vec![make_search_success()],
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
            vec![
                LdapOp::SearchResultEntry(LdapSearchResultEntry {
                    dn: "uid=bob,ou=people,dc=example,dc=com".to_string(),
                    attributes: vec![LdapPartialAttribute {
                        atype: "memberOf".to_string(),
                        vals: vec![b"uid=rockstars,ou=groups,dc=example,dc=com".to_vec()]
                    }],
                }),
                make_search_success(),
            ],
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
            vec![make_search_success()],
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
            vec![
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
            ]
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
            vec![
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
            ]
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
            vec![
                LdapOp::SearchResultEntry(LdapSearchResultEntry {
                    dn: "cn=group_1,ou=groups,dc=example,dc=com".to_string(),
                    attributes: vec![],
                }),
                make_search_success(),
            ]
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
            vec![
                LdapOp::SearchResultEntry(LdapSearchResultEntry {
                    dn: "cn=group_1,ou=groups,dc=example,dc=com".to_string(),
                    attributes: vec![LdapPartialAttribute {
                        atype: "cn".to_string(),
                        vals: vec![b"group_1".to_vec()]
                    },],
                }),
                make_search_success(),
            ]
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
            vec![make_search_success()],
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
            vec![make_search_error(
                LdapResultCode::Other,
                r#"Error while listing groups "ou=groups,dc=example,dc=com": Internal error: `Error getting groups`"#.to_string()
            )]
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
            vec![make_search_error(
                LdapResultCode::UnwillingToPerform,
                r#"Unsupported group filter: Unsupported group filter: Substring("whatever", LdapSubstringFilter { initial: None, any: [], final_: None })"#
                    .to_string()
            )]
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
            vec![make_search_success()]
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
            vec![make_search_success()]
        );
        let request = make_user_search_request(
            LdapFilter::Equality("memberOf".to_string(), "group_1".to_string()),
            vec!["objectClass"],
        );
        assert_eq!(
            ldap_handler.do_search_or_dse(&request).await,
            vec![make_search_error(
                LdapResultCode::UnwillingToPerform,
                "Unsupported user filter: while parsing a group ID: Missing DN value".to_string()
            )]
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
            vec![make_search_error(
                LdapResultCode::UnwillingToPerform,
                "Unsupported user filter: Unexpected group DN format. Got \"cn=mygroup,dc=example,dc=com\", expected: \"cn=groupname,ou=groups,dc=example,dc=com\"".to_string()
            )]
        );
    }

    #[tokio::test]
    async fn test_search_filters_lowercase() {
        let mut mock = MockTestBackendHandler::new();
        mock.expect_list_users()
            .with(
                eq(Some(UserRequestFilter::And(vec![UserRequestFilter::Or(
                    vec![UserRequestFilter::Not(Box::new(
                        UserRequestFilter::Equality("first_name".to_string(), "bob".to_string()),
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
            vec![
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
            ]
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
            vec![
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
            ]
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

        let expected_result = vec![
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
                ],
            }),
            make_search_success(),
        ];

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
            vec![make_search_success()]
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
            vec![make_search_error(
                LdapResultCode::UnwillingToPerform,
                "Unsupported user filter: Unsupported user filter: Substring(\"uid\", LdapSubstringFilter { initial: None, any: [], final_: None })".to_string()
            )]
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
                r#"Invalid username: "Unexpected user DN format. Got \"uid=bob,ou=groups,ou=people,dc=example,dc=com\", expected: \"uid=username,ou=people,dc=example,dc=com\"""#.to_string(),
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
            vec![
                root_dse_response("dc=example,dc=com"),
                make_search_success()
            ]
        );
    }
}
