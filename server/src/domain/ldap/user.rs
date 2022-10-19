use ldap3_proto::{
    proto::LdapOp, LdapFilter, LdapPartialAttribute, LdapResultCode, LdapSearchResultEntry,
};
use tracing::{debug, info, instrument, warn};

use crate::domain::{
    handler::{BackendHandler, GroupDetails, User, UserId, UserRequestFilter},
    ldap::{error::LdapError, utils::expand_attribute_wildcards},
    sql_tables::UserColumn,
};

use super::{
    error::LdapResult,
    utils::{get_group_id_from_distinguished_name, map_user_field, LdapInfo},
};

fn get_user_attribute(
    user: &User,
    attribute: &str,
    base_dn_str: &str,
    groups: Option<&[GroupDetails]>,
    ignored_user_attributes: &[String],
) -> Option<Vec<Vec<u8>>> {
    let attribute = attribute.to_ascii_lowercase();
    let attribute_values = match attribute.as_str() {
        "objectclass" => vec![
            b"inetOrgPerson".to_vec(),
            b"posixAccount".to_vec(),
            b"mailAccount".to_vec(),
            b"person".to_vec(),
        ],
        // dn is always returned as part of the base response.
        "dn" | "distinguishedname" => return None,
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
        "1.1" => return None,
        // We ignore the operational attribute wildcard.
        "+" => return None,
        "*" => {
            panic!(
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
            return None;
        }
    };
    if attribute_values.len() == 1 && attribute_values[0].is_empty() {
        None
    } else {
        Some(attribute_values)
    }
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
    "entryuuid",
];

fn make_ldap_search_user_result_entry(
    user: User,
    base_dn_str: &str,
    attributes: &[&str],
    groups: Option<&[GroupDetails]>,
    ignored_user_attributes: &[String],
) -> LdapSearchResultEntry {
    let dn = format!("uid={},ou=people,{}", user.user_id.as_str(), base_dn_str);

    LdapSearchResultEntry {
        dn,
        attributes: attributes
            .iter()
            .filter_map(|a| {
                let values =
                    get_user_attribute(&user, a, base_dn_str, groups, ignored_user_attributes)?;
                Some(LdapPartialAttribute {
                    atype: a.to_string(),
                    vals: values,
                })
            })
            .collect::<Vec<LdapPartialAttribute>>(),
    }
}

fn convert_user_filter(ldap_info: &LdapInfo, filter: &LdapFilter) -> LdapResult<UserRequestFilter> {
    let rec = |f| convert_user_filter(ldap_info, f);
    match filter {
        LdapFilter::And(filters) => Ok(UserRequestFilter::And(
            filters.iter().map(rec).collect::<LdapResult<_>>()?,
        )),
        LdapFilter::Or(filters) => Ok(UserRequestFilter::Or(
            filters.iter().map(rec).collect::<LdapResult<_>>()?,
        )),
        LdapFilter::Not(filter) => Ok(UserRequestFilter::Not(Box::new(rec(filter)?))),
        LdapFilter::Equality(field, value) => {
            let field = &field.to_ascii_lowercase();
            match field.as_str() {
                "memberof" => {
                    let group_name = get_group_id_from_distinguished_name(
                        &value.to_ascii_lowercase(),
                        &ldap_info.base_dn,
                        &ldap_info.base_dn_str,
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
                _ => match map_user_field(field) {
                    Some(UserColumn::UserId) => Ok(UserRequestFilter::UserId(UserId::new(value))),
                    Some(field) => Ok(UserRequestFilter::Equality(field, value.clone())),
                    None => {
                        if !ldap_info.ignored_user_attributes.contains(field) {
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
                || ALL_USER_ATTRIBUTE_KEYS.contains(&field.as_str())
            {
                Ok(UserRequestFilter::And(vec![]))
            } else {
                Ok(UserRequestFilter::Not(Box::new(UserRequestFilter::And(
                    vec![],
                ))))
            }
        }
        _ => Err(LdapError {
            code: LdapResultCode::UnwillingToPerform,
            message: format!("Unsupported user filter: {:?}", filter),
        }),
    }
}

#[instrument(skip_all, level = "debug")]
pub async fn get_user_list<Backend: BackendHandler>(
    ldap_info: &LdapInfo,
    ldap_filter: &LdapFilter,
    attributes: &[String],
    base: &str,
    user_filter: &Option<&UserId>,
    backend: &mut Backend,
) -> LdapResult<Vec<LdapOp>> {
    debug!(?ldap_filter);
    let filters = convert_user_filter(ldap_info, ldap_filter)?;
    let parsed_filters = match user_filter {
        None => filters,
        Some(u) => {
            info!("Unprivileged search, limiting results");
            UserRequestFilter::And(vec![filters, UserRequestFilter::UserId((*u).clone())])
        }
    };
    debug!(?parsed_filters);
    let expanded_attributes = expand_attribute_wildcards(attributes, ALL_USER_ATTRIBUTE_KEYS);
    let need_groups = expanded_attributes
        .iter()
        .any(|s| s.to_ascii_lowercase() == "memberof");
    let users = backend
        .list_users(Some(parsed_filters), need_groups)
        .await
        .map_err(|e| LdapError {
            code: LdapResultCode::Other,
            message: format!(r#"Error while searching user "{}": {:#}"#, base, e),
        })?;

    Ok(users
        .into_iter()
        .map(|u| {
            LdapOp::SearchResultEntry(make_ldap_search_user_result_entry(
                u.user,
                &ldap_info.base_dn_str,
                &expanded_attributes,
                u.groups.as_deref(),
                &ldap_info.ignored_user_attributes,
            ))
        })
        .collect::<Vec<_>>())
}
