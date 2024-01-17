use chrono::TimeZone;
use ldap3_proto::{
    proto::LdapOp, LdapFilter, LdapPartialAttribute, LdapResultCode, LdapSearchResultEntry,
};
use tracing::{debug, instrument, warn};

use crate::domain::{
    deserialize::deserialize_attribute_value,
    handler::{GroupListerBackendHandler, GroupRequestFilter},
    ldap::error::LdapError,
    schema::{PublicSchema, SchemaGroupAttributeExtractor},
    types::{AttributeName, AttributeType, Group, UserId, Uuid},
};

use super::{
    error::LdapResult,
    utils::{
        expand_attribute_wildcards, get_custom_attribute, get_group_id_from_distinguished_name,
        get_user_id_from_distinguished_name, map_group_field, GroupFieldType, LdapInfo,
    },
};

pub fn get_group_attribute(
    group: &Group,
    base_dn_str: &str,
    attribute: &str,
    user_filter: &Option<UserId>,
    ignored_group_attributes: &[AttributeName],
    schema: &PublicSchema,
) -> Option<Vec<Vec<u8>>> {
    let attribute = AttributeName::from(attribute);
    let attribute_values = match map_group_field(&attribute, schema) {
        GroupFieldType::ObjectClass => vec![b"groupOfUniqueNames".to_vec()],
        // Always returned as part of the base response.
        GroupFieldType::Dn => return None,
        GroupFieldType::EntryDn => {
            vec![format!("uid={},ou=groups,{}", group.display_name, base_dn_str).into_bytes()]
        }
        GroupFieldType::DisplayName => vec![group.display_name.to_string().into_bytes()],
        GroupFieldType::CreationDate => vec![chrono::Utc
            .from_utc_datetime(&group.creation_date)
            .to_rfc3339()
            .into_bytes()],
        GroupFieldType::Member => group
            .users
            .iter()
            .filter(|u| user_filter.as_ref().map(|f| *u == f).unwrap_or(true))
            .map(|u| format!("uid={},ou=people,{}", u, base_dn_str).into_bytes())
            .collect(),
        GroupFieldType::Uuid => vec![group.uuid.to_string().into_bytes()],
        GroupFieldType::Attribute(attr, _, _) => {
            get_custom_attribute::<SchemaGroupAttributeExtractor>(&group.attributes, &attr, schema)?
        }
        GroupFieldType::NoMatch => match attribute.as_str() {
            "1.1" => return None,
            // We ignore the operational attribute wildcard
            "+" => return None,
            "*" => {
                panic!(
                    "Matched {}, * should have been expanded into attribute list and * removed",
                    attribute
                )
            }
            _ => {
                if ignored_group_attributes.contains(&attribute) {
                    return None;
                }
                get_custom_attribute::<SchemaGroupAttributeExtractor>(
                        &group.attributes,
                        &attribute,
                        schema,
                    ).or_else(||{warn!(
                            r#"Ignoring unrecognized group attribute: {}\n\
                               To disable this warning, add it to "ignored_group_attributes" in the config."#,
                            attribute
                        );None})?
            }
        },
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
    ignored_group_attributes: &[AttributeName],
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

fn get_group_attribute_equality_filter(
    field: &AttributeName,
    typ: AttributeType,
    is_list: bool,
    value: &str,
) -> LdapResult<GroupRequestFilter> {
    deserialize_attribute_value(&[value.to_owned()], typ, is_list)
        .map_err(|e| LdapError {
            code: LdapResultCode::Other,
            message: format!("Invalid value for attribute {}: {}", field, e),
        })
        .map(|v| GroupRequestFilter::AttributeEquality(field.clone(), v))
}

fn convert_group_filter(
    ldap_info: &LdapInfo,
    filter: &LdapFilter,
    schema: &PublicSchema,
) -> LdapResult<GroupRequestFilter> {
    let rec = |f| convert_group_filter(ldap_info, f, schema);
    match filter {
        LdapFilter::Equality(field, value) => {
            let field = AttributeName::from(field.as_str());
            let value = value.to_ascii_lowercase();
            match map_group_field(&field, schema) {
                GroupFieldType::DisplayName => Ok(GroupRequestFilter::DisplayName(value.into())),
                GroupFieldType::Uuid => Ok(GroupRequestFilter::Uuid(
                    Uuid::try_from(value.as_str()).map_err(|e| LdapError {
                        code: LdapResultCode::InappropriateMatching,
                        message: format!("Invalid UUID: {:#}", e),
                    })?,
                )),
                GroupFieldType::Member => {
                    let user_name = get_user_id_from_distinguished_name(
                        &value,
                        &ldap_info.base_dn,
                        &ldap_info.base_dn_str,
                    )?;
                    Ok(GroupRequestFilter::Member(user_name))
                }
                GroupFieldType::ObjectClass => Ok(GroupRequestFilter::from(matches!(
                    value.as_str(),
                    "groupofuniquenames" | "groupofnames"
                ))),
                GroupFieldType::Dn | GroupFieldType::EntryDn => {
                    Ok(get_group_id_from_distinguished_name(
                        value.as_str(),
                        &ldap_info.base_dn,
                        &ldap_info.base_dn_str,
                    )
                    .map(GroupRequestFilter::DisplayName)
                    .unwrap_or_else(|_| {
                        warn!("Invalid dn filter on group: {}", value);
                        GroupRequestFilter::from(false)
                    }))
                }
                GroupFieldType::NoMatch => {
                    if !ldap_info.ignored_group_attributes.contains(&field) {
                        warn!(
                            r#"Ignoring unknown group attribute "{}" in filter.\n\
                                To disable this warning, add it to "ignored_group_attributes" in the config."#,
                            field
                        );
                    }
                    Ok(GroupRequestFilter::from(false))
                }
                GroupFieldType::Attribute(field, typ, is_list) => {
                    get_group_attribute_equality_filter(&field, typ, is_list, &value)
                }
                GroupFieldType::CreationDate => Err(LdapError {
                    code: LdapResultCode::UnwillingToPerform,
                    message: "Creation date filter for groups not supported".to_owned(),
                }),
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
            let field = AttributeName::from(field.as_str());
            Ok(GroupRequestFilter::from(!matches!(
                map_group_field(&field, schema),
                GroupFieldType::NoMatch
            )))
        }
        LdapFilter::Substring(field, substring_filter) => {
            let field = AttributeName::from(field.as_str());
            match map_group_field(&field, schema) {
                GroupFieldType::DisplayName => Ok(GroupRequestFilter::DisplayNameSubString(
                    substring_filter.clone().into(),
                )),
                GroupFieldType::NoMatch => Ok(GroupRequestFilter::from(false)),
                _ => Err(LdapError {
                    code: LdapResultCode::UnwillingToPerform,
                    message: format!(
                        "Unsupported group attribute for substring filter: \"{}\"",
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
    schema: &PublicSchema,
) -> LdapResult<Vec<Group>> {
    let filters = convert_group_filter(ldap_info, ldap_filter, schema)?;
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
