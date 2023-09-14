use ldap3_proto::{
    proto::LdapOp, LdapFilter, LdapPartialAttribute, LdapResultCode, LdapSearchResultEntry,
};
use tracing::{debug, instrument, warn};

use crate::domain::{
    handler::{GroupListerBackendHandler, GroupRequestFilter},
    ldap::error::LdapError,
    schema::{PublicSchema, SchemaGroupAttributeExtractor},
    types::{Group, UserId, Uuid},
};

use super::{
    error::LdapResult,
    utils::{
        expand_attribute_wildcards, get_custom_attribute, get_group_id_from_distinguished_name,
        get_user_id_from_distinguished_name, map_group_field, LdapInfo,
    },
};

pub fn get_group_attribute(
    group: &Group,
    base_dn_str: &str,
    attribute: &str,
    user_filter: &Option<UserId>,
    ignored_group_attributes: &[String],
    schema: &PublicSchema,
) -> Option<Vec<Vec<u8>>> {
    let attribute = attribute.to_ascii_lowercase();
    let attribute_values = match attribute.as_str() {
        "objectclass" => vec![b"groupOfUniqueNames".to_vec()],
        // Always returned as part of the base response.
        "dn" | "distinguishedname" => return None,
        "cn" | "uid" | "id" => vec![group.display_name.clone().into_bytes()],
        "entryuuid" | "uuid" => vec![group.uuid.to_string().into_bytes()],
        "member" | "uniquemember" => group
            .users
            .iter()
            .filter(|u| user_filter.as_ref().map(|f| *u == f).unwrap_or(true))
            .map(|u| format!("uid={},ou=people,{}", u, base_dn_str).into_bytes())
            .collect(),
        "1.1" => return None,
        // We ignore the operational attribute wildcard
        "+" => return None,
        "*" => {
            panic!(
                "Matched {}, * should have been expanded into attribute list and * removed",
                attribute
            )
        }
        attr => {
            if !ignored_group_attributes.contains(&attribute) {
                match get_custom_attribute::<SchemaGroupAttributeExtractor>(
                    &group.attributes,
                    attr,
                    schema,
                ) {
                    Some(v) => return Some(v),
                    None => warn!(
                        r#"Ignoring unrecognized group attribute: {}\n\
                      To disable this warning, add it to "ignored_group_attributes" in the config."#,
                        attribute
                    ),
                };
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

const ALL_GROUP_ATTRIBUTE_KEYS: &[&str] = &[
    "objectclass",
    "uid",
    "cn",
    "member",
    "uniquemember",
    "entryuuid",
];

fn expand_group_attribute_wildcards(attributes: &[String]) -> Vec<&str> {
    expand_attribute_wildcards(attributes, ALL_GROUP_ATTRIBUTE_KEYS)
}

fn make_ldap_search_group_result_entry(
    group: Group,
    base_dn_str: &str,
    attributes: &[String],
    user_filter: &Option<UserId>,
    ignored_group_attributes: &[String],
    schema: &PublicSchema,
) -> LdapSearchResultEntry {
    let expanded_attributes = expand_group_attribute_wildcards(attributes);

    LdapSearchResultEntry {
        dn: format!("cn={},ou=groups,{}", group.display_name, base_dn_str),
        attributes: expanded_attributes
            .iter()
            .filter_map(|a| {
                let values = get_group_attribute(
                    &group,
                    base_dn_str,
                    a,
                    user_filter,
                    ignored_group_attributes,
                    schema,
                )?;
                Some(LdapPartialAttribute {
                    atype: a.to_string(),
                    vals: values,
                })
            })
            .collect::<Vec<LdapPartialAttribute>>(),
    }
}

fn convert_group_filter(
    ldap_info: &LdapInfo,
    filter: &LdapFilter,
) -> LdapResult<GroupRequestFilter> {
    let rec = |f| convert_group_filter(ldap_info, f);
    match filter {
        LdapFilter::Equality(field, value) => {
            let field = &field.to_ascii_lowercase();
            let value = &value.to_ascii_lowercase();
            match field.as_str() {
                "member" | "uniquemember" => {
                    let user_name = get_user_id_from_distinguished_name(
                        value,
                        &ldap_info.base_dn,
                        &ldap_info.base_dn_str,
                    )?;
                    Ok(GroupRequestFilter::Member(user_name))
                }
                "objectclass" => Ok(GroupRequestFilter::from(matches!(
                    value.as_str(),
                    "groupofuniquenames" | "groupofnames"
                ))),
                "dn" => Ok(get_group_id_from_distinguished_name(
                    value.to_ascii_lowercase().as_str(),
                    &ldap_info.base_dn,
                    &ldap_info.base_dn_str,
                )
                .map(GroupRequestFilter::DisplayName)
                .unwrap_or_else(|_| {
                    warn!("Invalid dn filter on group: {}", value);
                    GroupRequestFilter::from(false)
                })),
                _ => match map_group_field(field) {
                    Some("display_name") => Ok(GroupRequestFilter::DisplayName(value.to_string())),
                    Some("uuid") => Ok(GroupRequestFilter::Uuid(
                        Uuid::try_from(value.as_str()).map_err(|e| LdapError {
                            code: LdapResultCode::InappropriateMatching,
                            message: format!("Invalid UUID: {:#}", e),
                        })?,
                    )),
                    _ => {
                        if !ldap_info.ignored_group_attributes.contains(field) {
                            warn!(
                                r#"Ignoring unknown group attribute "{:?}" in filter.\n\
                                To disable this warning, add it to "ignored_group_attributes" in the config."#,
                                field
                            );
                        }
                        Ok(GroupRequestFilter::from(false))
                    }
                },
            }
        }
        LdapFilter::And(filters) => Ok(GroupRequestFilter::And(
            filters.iter().map(rec).collect::<LdapResult<_>>()?,
        )),
        LdapFilter::Or(filters) => Ok(GroupRequestFilter::Or(
            filters.iter().map(rec).collect::<LdapResult<_>>()?,
        )),
        LdapFilter::Not(filter) => Ok(GroupRequestFilter::Not(Box::new(rec(filter)?))),
        LdapFilter::Present(field) => {
            let field = &field.to_ascii_lowercase();
            Ok(GroupRequestFilter::from(
                field == "objectclass"
                    || field == "dn"
                    || field == "distinguishedname"
                    || map_group_field(field).is_some(),
            ))
        }
        LdapFilter::Substring(field, substring_filter) => {
            let field = &field.to_ascii_lowercase();
            match map_group_field(field.as_str()) {
                Some("display_name") => Ok(GroupRequestFilter::DisplayNameSubString(
                    substring_filter.clone().into(),
                )),
                _ => Err(LdapError {
                    code: LdapResultCode::UnwillingToPerform,
                    message: format!(
                        "Unsupported group attribute for substring filter: {:?}",
                        field
                    ),
                }),
            }
        }
        _ => Err(LdapError {
            code: LdapResultCode::UnwillingToPerform,
            message: format!("Unsupported group filter: {:?}", filter),
        }),
    }
}

#[instrument(skip_all, level = "debug", fields(ldap_filter))]
pub async fn get_groups_list<Backend: GroupListerBackendHandler>(
    ldap_info: &LdapInfo,
    ldap_filter: &LdapFilter,
    base: &str,
    backend: &Backend,
) -> LdapResult<Vec<Group>> {
    let filters = convert_group_filter(ldap_info, ldap_filter)?;
    debug!(?filters);
    backend
        .list_groups(Some(filters))
        .await
        .map_err(|e| LdapError {
            code: LdapResultCode::Other,
            message: format!(r#"Error while listing groups "{}": {:#}"#, base, e),
        })
}

pub fn convert_groups_to_ldap_op<'a>(
    groups: Vec<Group>,
    attributes: &'a [String],
    ldap_info: &'a LdapInfo,
    user_filter: &'a Option<UserId>,
    schema: &'a PublicSchema,
) -> impl Iterator<Item = LdapOp> + 'a {
    groups.into_iter().map(move |g| {
        LdapOp::SearchResultEntry(make_ldap_search_group_result_entry(
            g,
            &ldap_info.base_dn_str,
            attributes,
            user_filter,
            &ldap_info.ignored_group_attributes,
            schema,
        ))
    })
}
