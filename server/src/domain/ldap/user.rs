use chrono::TimeZone;
use ldap3_proto::{
    proto::LdapOp, LdapFilter, LdapPartialAttribute, LdapResultCode, LdapSearchResultEntry,
};
use tracing::{debug, info, instrument, warn};

use crate::domain::{
    handler::{BackendHandler, UserRequestFilter},
    ldap::{
        error::LdapError,
        utils::{expand_attribute_wildcards, get_user_id_from_distinguished_name},
    },
    types::{GroupDetails, User, UserAndGroups, UserColumn, UserId},
};

use super::{
    error::LdapResult,
    utils::{get_group_id_from_distinguished_name, map_user_field, LdapInfo},
};

pub fn get_user_attribute(
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
        "uid" | "user_id" | "id" => vec![user.user_id.to_string().into_bytes()],
        "entryuuid" | "uuid" => vec![user.uuid.to_string().into_bytes()],
        "mail" | "email" => vec![user.email.clone().into_bytes()],
        "givenname" | "first_name" | "firstname" => vec![user.first_name.clone()?.into_bytes()],
        "sn" | "last_name" | "lastname" => vec![user.last_name.clone()?.into_bytes()],
        "jpegphoto" | "avatar" => vec![user.avatar.clone()?.into_bytes()],
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
        "cn" | "displayname" => vec![user.display_name.clone()?.into_bytes()],
        "creationdate" | "creation_date" | "createtimestamp" | "modifytimestamp" => {
            vec![chrono::Utc
                .from_utc_datetime(&user.creation_date)
                .to_rfc3339()
                .into_bytes()]
        }
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
    attributes: &[String],
    groups: Option<&[GroupDetails]>,
    ignored_user_attributes: &[String],
) -> LdapSearchResultEntry {
    let expanded_attributes = expand_user_attribute_wildcards(attributes);
    let dn = format!("uid={},ou=people,{}", user.user_id.as_str(), base_dn_str);
    dbg!(&attributes, &expanded_attributes, &user);

    LdapSearchResultEntry {
        dn,
        attributes: expanded_attributes
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
                "memberof" => Ok(UserRequestFilter::MemberOf(
                    get_group_id_from_distinguished_name(
                        &value.to_ascii_lowercase(),
                        &ldap_info.base_dn,
                        &ldap_info.base_dn_str,
                    )?,
                )),
                "objectclass" => Ok(UserRequestFilter::from(matches!(
                    value.to_ascii_lowercase().as_str(),
                    "person" | "inetorgperson" | "posixaccount" | "mailaccount"
                ))),
                "dn" => Ok(get_user_id_from_distinguished_name(
                    value.to_ascii_lowercase().as_str(),
                    &ldap_info.base_dn,
                    &ldap_info.base_dn_str,
                )
                .map(UserRequestFilter::UserId)
                .unwrap_or_else(|_| {
                    warn!("Invalid dn filter on user: {}", value);
                    UserRequestFilter::from(false)
                })),
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
                        Ok(UserRequestFilter::from(false))
                    }
                },
            }
        }
        LdapFilter::Present(field) => {
            let field = &field.to_ascii_lowercase();
            // Check that it's a field we support.
            Ok(UserRequestFilter::from(
                field == "objectclass"
                    || field == "dn"
                    || field == "distinguishedname"
                    || map_user_field(field).is_some(),
            ))
        }
        LdapFilter::Substring(field, substring_filter) => {
            let field = &field.to_ascii_lowercase();
            match map_user_field(field.as_str()) {
                Some(UserColumn::UserId) => Ok(UserRequestFilter::UserIdSubString(
                    substring_filter.clone().into(),
                )),
                None
                | Some(UserColumn::CreationDate)
                | Some(UserColumn::Avatar)
                | Some(UserColumn::Uuid) => Err(LdapError {
                    code: LdapResultCode::UnwillingToPerform,
                    message: format!(
                        "Unsupported user attribute for substring filter: {:?}",
                        field
                    ),
                }),
                Some(field) => Ok(UserRequestFilter::SubString(
                    field,
                    substring_filter.clone().into(),
                )),
            }
        }
        _ => Err(LdapError {
            code: LdapResultCode::UnwillingToPerform,
            message: format!("Unsupported user filter: {:?}", filter),
        }),
    }
}

fn expand_user_attribute_wildcards(attributes: &[String]) -> Vec<&str> {
    expand_attribute_wildcards(attributes, ALL_USER_ATTRIBUTE_KEYS)
}

#[instrument(skip_all, level = "debug")]
pub async fn get_user_list<Backend: BackendHandler>(
    ldap_info: &LdapInfo,
    ldap_filter: &LdapFilter,
    request_groups: bool,
    base: &str,
    user_filter: &Option<&UserId>,
    backend: &mut Backend,
) -> LdapResult<Vec<UserAndGroups>> {
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
    backend
        .list_users(Some(parsed_filters), request_groups)
        .await
        .map_err(|e| LdapError {
            code: LdapResultCode::Other,
            message: format!(r#"Error while searching user "{}": {:#}"#, base, e),
        })
}

pub fn convert_users_to_ldap_op<'a>(
    users: Vec<UserAndGroups>,
    attributes: &'a [String],
    ldap_info: &'a LdapInfo,
) -> impl Iterator<Item = LdapOp> + 'a {
    users.into_iter().map(move |u| {
        LdapOp::SearchResultEntry(make_ldap_search_user_result_entry(
            u.user,
            &ldap_info.base_dn_str,
            attributes,
            u.groups.as_deref(),
            &ldap_info.ignored_user_attributes,
        ))
    })
}
