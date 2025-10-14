use crate::core::{
    error::{LdapError, LdapResult},
    utils::{
        ExpandedAttributes, GroupFieldType, LdapInfo, expand_attribute_wildcards,
        get_custom_attribute, get_group_id_from_distinguished_name_or_plain_name,
        get_user_id_from_distinguished_name_or_plain_name, map_group_field,
    },
};
use chrono::TimeZone;
use ldap3_proto::{
    LdapFilter, LdapPartialAttribute, LdapResultCode, LdapSearchResultEntry, proto::LdapOp,
};
use lldap_domain::{
    deserialize::deserialize_attribute_value,
    public_schema::PublicSchema,
    types::{AttributeName, AttributeType, Group, GroupId, LdapObjectClass, UserId, Uuid},
};
use lldap_domain_handlers::handler::{GroupListerBackendHandler, GroupRequestFilter};
use tracing::{debug, instrument, warn};

pub const REQUIRED_GROUP_ATTRIBUTES: &[&str] = &["display_name"];

const DEFAULT_GROUP_OBJECT_CLASSES: &[&str] = &["groupOfUniqueNames", "groupOfNames"];

fn get_default_group_object_classes_as_bytes() -> Vec<Vec<u8>> {
    DEFAULT_GROUP_OBJECT_CLASSES
        .iter()
        .map(|c| c.as_bytes().to_vec())
        .collect()
}

pub fn get_default_group_object_classes() -> Vec<LdapObjectClass> {
    DEFAULT_GROUP_OBJECT_CLASSES
        .iter()
        .map(|&c| LdapObjectClass::from(c))
        .collect()
}

pub fn get_group_attribute(
    group: &Group,
    base_dn_str: &str,
    attribute: &AttributeName,
    user_filter: &Option<UserId>,
    ignored_group_attributes: &[AttributeName],
    schema: &PublicSchema,
) -> Option<Vec<Vec<u8>>> {
    let attribute_values = match map_group_field(attribute, schema) {
        GroupFieldType::ObjectClass => {
            let mut classes: Vec<Vec<u8>> = get_default_group_object_classes_as_bytes();

            classes.extend(
                schema
                    .get_schema()
                    .extra_group_object_classes
                    .iter()
                    .map(|c| c.as_str().as_bytes().to_vec()),
            );
            classes
        }
        // Always returned as part of the base response.
        GroupFieldType::Dn => return None,
        GroupFieldType::EntryDn => {
            vec![format!("uid={},ou=groups,{}", group.display_name, base_dn_str).into_bytes()]
        }
        GroupFieldType::GroupId => {
            vec![group.id.0.to_string().into_bytes()]
        }
        GroupFieldType::DisplayName => vec![group.display_name.to_string().into_bytes()],
        GroupFieldType::CreationDate => vec![
            chrono::Utc
                .from_utc_datetime(&group.creation_date)
                .to_rfc3339()
                .into_bytes(),
        ],
        GroupFieldType::ModifiedDate => vec![
            chrono::Utc
                .from_utc_datetime(&group.modified_date)
                .to_rfc3339()
                .into_bytes(),
        ],
        GroupFieldType::Member => group
            .users
            .iter()
            .filter(|u| user_filter.as_ref().map(|f| *u == f).unwrap_or(true))
            .map(|u| format!("uid={u},ou=people,{base_dn_str}").into_bytes())
            .collect(),
        GroupFieldType::Uuid => vec![group.uuid.to_string().into_bytes()],
        GroupFieldType::Attribute(attr, _, _) => get_custom_attribute(&group.attributes, &attr)?,
        GroupFieldType::NoMatch => match attribute.as_str() {
            "1.1" => return None,
            // We ignore the operational attribute wildcard
            "+" => return None,
            "*" => {
                panic!(
                    "Matched {attribute}, * should have been expanded into attribute list and * removed"
                )
            }
            _ => {
                if ignored_group_attributes.contains(attribute) {
                    return None;
                }
                get_custom_attribute(
                        &group.attributes,
                        attribute,
                    ).or_else(||{warn!(
                            r#"Ignoring unrecognized group attribute: {}. To disable this warning, add it to "ignored_group_attributes" in the config."#,
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

fn expand_group_attribute_wildcards(attributes: &[String]) -> ExpandedAttributes {
    expand_attribute_wildcards(attributes, ALL_GROUP_ATTRIBUTE_KEYS)
}

fn make_ldap_search_group_result_entry(
    group: Group,
    base_dn_str: &str,
    mut expanded_attributes: ExpandedAttributes,
    user_filter: &Option<UserId>,
    ignored_group_attributes: &[AttributeName],
    schema: &PublicSchema,
) -> LdapSearchResultEntry {
    if expanded_attributes.include_custom_attributes {
        expanded_attributes.attribute_keys.extend(
            group
                .attributes
                .iter()
                .map(|a| (a.name.clone(), a.name.to_string())),
        );
    }
    LdapSearchResultEntry {
        dn: format!("cn={},ou=groups,{}", group.display_name, base_dn_str),
        attributes: expanded_attributes
            .attribute_keys
            .into_iter()
            .filter_map(|(attribute, name)| {
                let values = get_group_attribute(
                    &group,
                    base_dn_str,
                    &attribute,
                    user_filter,
                    ignored_group_attributes,
                    schema,
                )?;
                Some(LdapPartialAttribute {
                    atype: name,
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
) -> GroupRequestFilter {
    let value_lc = value.to_ascii_lowercase();
    let serialized_value = deserialize_attribute_value(&[value.to_owned()], typ, is_list);
    let serialized_value_lc = deserialize_attribute_value(&[value_lc.to_owned()], typ, is_list);
    match (serialized_value, serialized_value_lc) {
        (Ok(v), Ok(v_lc)) => GroupRequestFilter::Or(vec![
            GroupRequestFilter::AttributeEquality(field.clone(), v),
            GroupRequestFilter::AttributeEquality(field.clone(), v_lc),
        ]),
        (Ok(_), Err(e)) => {
            warn!("Invalid value for attribute {} (lowercased): {}", field, e);
            GroupRequestFilter::False
        }
        (Err(e), _) => {
            warn!("Invalid value for attribute {}: {}", field, e);
            GroupRequestFilter::False
        }
    }
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
            let value_lc = value.to_ascii_lowercase();
            match map_group_field(&field, schema) {
                GroupFieldType::GroupId => Ok(value_lc
                    .parse::<i32>()
                    .map(|id| GroupRequestFilter::GroupId(GroupId(id)))
                    .unwrap_or_else(|_| {
                        warn!("Given group id is not a valid integer: {}", value_lc);
                        GroupRequestFilter::False
                    })),
                GroupFieldType::DisplayName => Ok(GroupRequestFilter::DisplayName(value_lc.into())),
                GroupFieldType::Uuid => Uuid::try_from(value_lc.as_str())
                    .map(GroupRequestFilter::Uuid)
                    .map_err(|e| LdapError {
                        code: LdapResultCode::Other,
                        message: format!("Invalid UUID: {e:#}"),
                    }),
                GroupFieldType::Member => Ok(get_user_id_from_distinguished_name_or_plain_name(
                    &value_lc,
                    &ldap_info.base_dn,
                    &ldap_info.base_dn_str,
                )
                .map(GroupRequestFilter::Member)
                .unwrap_or_else(|e| {
                    warn!("Invalid member filter on group: {}", e);
                    GroupRequestFilter::False
                })),
                GroupFieldType::ObjectClass => Ok(GroupRequestFilter::from(
                    get_default_group_object_classes()
                        .iter()
                        .any(|class| class.as_str().eq_ignore_ascii_case(value_lc.as_str()))
                        || schema
                            .get_schema()
                            .extra_group_object_classes
                            .contains(&LdapObjectClass::from(value_lc)),
                )),
                GroupFieldType::Dn | GroupFieldType::EntryDn => {
                    Ok(get_group_id_from_distinguished_name_or_plain_name(
                        value_lc.as_str(),
                        &ldap_info.base_dn,
                        &ldap_info.base_dn_str,
                    )
                    .map(GroupRequestFilter::DisplayName)
                    .unwrap_or_else(|_| {
                        warn!("Invalid dn filter on group: {}", value_lc);
                        GroupRequestFilter::False
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
                    Ok(GroupRequestFilter::False)
                }
                GroupFieldType::Attribute(field, typ, is_list) => Ok(
                    get_group_attribute_equality_filter(&field, typ, is_list, value),
                ),
                GroupFieldType::CreationDate => Err(LdapError {
                    code: LdapResultCode::UnwillingToPerform,
                    message: "Creation date filter for groups not supported".to_owned(),
                }),
                GroupFieldType::ModifiedDate => Err(LdapError {
                    code: LdapResultCode::UnwillingToPerform,
                    message: "Modified date filter for groups not supported".to_owned(),
                }),
            }
        }
        LdapFilter::And(filters) => {
            let res = filters
                .iter()
                .map(rec)
                .filter(|f| !matches!(f, Ok(GroupRequestFilter::True)))
                .flat_map(|f| match f {
                    Ok(GroupRequestFilter::And(v)) => v.into_iter().map(Ok).collect(),
                    f => vec![f],
                })
                .collect::<LdapResult<Vec<_>>>()?;
            if res.is_empty() {
                Ok(GroupRequestFilter::True)
            } else if res.len() == 1 {
                Ok(res.into_iter().next().unwrap())
            } else {
                Ok(GroupRequestFilter::And(res))
            }
        }
        LdapFilter::Or(filters) => {
            let res = filters
                .iter()
                .map(rec)
                .filter(|c| !matches!(c, Ok(GroupRequestFilter::False)))
                .flat_map(|f| match f {
                    Ok(GroupRequestFilter::Or(v)) => v.into_iter().map(Ok).collect(),
                    f => vec![f],
                })
                .collect::<LdapResult<Vec<_>>>()?;
            if res.is_empty() {
                Ok(GroupRequestFilter::False)
            } else if res.len() == 1 {
                Ok(res.into_iter().next().unwrap())
            } else {
                Ok(GroupRequestFilter::Or(res))
            }
        }
        LdapFilter::Not(filter) => Ok(match rec(filter)? {
            GroupRequestFilter::True => GroupRequestFilter::False,
            GroupRequestFilter::False => GroupRequestFilter::True,
            f => GroupRequestFilter::Not(Box::new(f)),
        }),
        LdapFilter::Present(field) => {
            let field = AttributeName::from(field.as_str());
            Ok(match map_group_field(&field, schema) {
                GroupFieldType::Attribute(name, _, _) => {
                    GroupRequestFilter::CustomAttributePresent(name)
                }
                GroupFieldType::NoMatch => GroupRequestFilter::False,
                _ => GroupRequestFilter::True,
            })
        }
        LdapFilter::Substring(field, substring_filter) => {
            let field = AttributeName::from(field.as_str());
            match map_group_field(&field, schema) {
                GroupFieldType::DisplayName => Ok(GroupRequestFilter::DisplayNameSubString(
                    substring_filter.clone().into(),
                )),
                GroupFieldType::Uuid => Ok(GroupRequestFilter::UuidSubString(
                    substring_filter.clone().into(),
                )),
                GroupFieldType::NoMatch => Ok(GroupRequestFilter::False),
                _ => Err(LdapError {
                    code: LdapResultCode::UnwillingToPerform,
                    message: format!(
                        "Unsupported group attribute for substring filter: \"{field}\""
                    ),
                }),
            }
        }
        _ => Err(LdapError {
            code: LdapResultCode::UnwillingToPerform,
            message: format!("Unsupported group filter: {filter:?}"),
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
            message: format!(r#"Error while listing groups "{base}": {e:#}"#),
        })
}

pub fn convert_groups_to_ldap_op<'a>(
    groups: Vec<Group>,
    attributes: &'a [String],
    ldap_info: &'a LdapInfo,
    user_filter: &'a Option<UserId>,
    schema: &'a PublicSchema,
) -> impl Iterator<Item = LdapOp> + 'a {
    let expanded_attributes = if groups.is_empty() {
        None
    } else {
        Some(expand_group_attribute_wildcards(attributes))
    };

    groups.into_iter().map(move |g| {
        LdapOp::SearchResultEntry(make_ldap_search_group_result_entry(
            g,
            &ldap_info.base_dn_str,
            expanded_attributes.clone().unwrap(),
            user_filter,
            &ldap_info.ignored_group_attributes,
            schema,
        ))
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        handler::tests::{make_group_search_request, setup_bound_admin_handler},
        search::{make_search_request, make_search_success},
    };
    use ldap3_proto::proto::LdapSubstringFilter;
    use lldap_domain::{
        types::{GroupId, UserId},
        uuid,
    };
    use lldap_domain_handlers::handler::*;
    use lldap_test_utils::MockTestBackendHandler;
    use mockall::predicate::eq;
    use pretty_assertions::assert_eq;

    #[tokio::test]
    async fn test_search_groups() {
        let mut mock = MockTestBackendHandler::new();
        mock.expect_list_groups()
            .with(eq(Some(GroupRequestFilter::True)))
            .times(1)
            .return_once(|_| {
                Ok(vec![
                    Group {
                        id: GroupId(1),
                        display_name: "group_1".into(),
                        creation_date: chrono::Utc.timestamp_opt(42, 42).unwrap().naive_utc(),
                        users: vec![UserId::new("bob"), UserId::new("john")],
                        uuid: uuid!("04ac75e0-2900-3e21-926c-2f732c26b3fc"),
                        attributes: Vec::new(),
                        modified_date: chrono::Utc.timestamp_opt(42, 42).unwrap().naive_utc(),
                    },
                    Group {
                        id: GroupId(3),
                        display_name: "BestGroup".into(),
                        creation_date: chrono::Utc.timestamp_opt(42, 42).unwrap().naive_utc(),
                        users: vec![UserId::new("john")],
                        uuid: uuid!("04ac75e0-2900-3e21-926c-2f732c26b3fc"),
                        attributes: Vec::new(),
                        modified_date: chrono::Utc.timestamp_opt(42, 42).unwrap().naive_utc(),
                    },
                ])
            });
        let ldap_handler = setup_bound_admin_handler(mock).await;
        let request = make_group_search_request(
            LdapFilter::And(vec![]),
            vec![
                "objectClass",
                "dn",
                "cn",
                "uniqueMember",
                "entryUuid",
                "entryDN",
            ],
        );
        assert_eq!(
            ldap_handler.do_search_or_dse(&request).await,
            Ok(vec![
                LdapOp::SearchResultEntry(LdapSearchResultEntry {
                    dn: "cn=group_1,ou=groups,dc=example,dc=com".to_string(),
                    attributes: vec![
                        LdapPartialAttribute {
                            atype: "cn".to_string(),
                            vals: vec![b"group_1".to_vec()]
                        },
                        LdapPartialAttribute {
                            atype: "entryDN".to_string(),
                            vals: vec![b"uid=group_1,ou=groups,dc=example,dc=com".to_vec()],
                        },
                        LdapPartialAttribute {
                            atype: "entryUuid".to_string(),
                            vals: vec![b"04ac75e0-2900-3e21-926c-2f732c26b3fc".to_vec()],
                        },
                        LdapPartialAttribute {
                            atype: "objectClass".to_string(),
                            vals: vec![b"groupOfUniqueNames".to_vec(), b"groupOfNames".to_vec()]
                        },
                        LdapPartialAttribute {
                            atype: "uniqueMember".to_string(),
                            vals: vec![
                                b"uid=bob,ou=people,dc=example,dc=com".to_vec(),
                                b"uid=john,ou=people,dc=example,dc=com".to_vec(),
                            ],
                        },
                    ],
                }),
                LdapOp::SearchResultEntry(LdapSearchResultEntry {
                    dn: "cn=BestGroup,ou=groups,dc=example,dc=com".to_string(),
                    attributes: vec![
                        LdapPartialAttribute {
                            atype: "cn".to_string(),
                            vals: vec![b"BestGroup".to_vec()]
                        },
                        LdapPartialAttribute {
                            atype: "entryDN".to_string(),
                            vals: vec![b"uid=BestGroup,ou=groups,dc=example,dc=com".to_vec()],
                        },
                        LdapPartialAttribute {
                            atype: "entryUuid".to_string(),
                            vals: vec![b"04ac75e0-2900-3e21-926c-2f732c26b3fc".to_vec()],
                        },
                        LdapPartialAttribute {
                            atype: "objectClass".to_string(),
                            vals: vec![b"groupOfUniqueNames".to_vec(), b"groupOfNames".to_vec()]
                        },
                        LdapPartialAttribute {
                            atype: "uniqueMember".to_string(),
                            vals: vec![b"uid=john,ou=people,dc=example,dc=com".to_vec()],
                        },
                    ],
                }),
                make_search_success(),
            ])
        );
    }

    #[tokio::test]
    async fn test_search_groups_by_groupid() {
        let mut mock = MockTestBackendHandler::new();
        mock.expect_list_groups()
            .with(eq(Some(GroupRequestFilter::GroupId(GroupId(1)))))
            .times(1)
            .return_once(|_| {
                Ok(vec![Group {
                    display_name: "group_1".into(),
                    id: GroupId(1),
                    creation_date: chrono::Utc.timestamp_opt(42, 42).unwrap().naive_utc(),
                    users: vec![],
                    uuid: uuid!("04ac75e0-2900-3e21-926c-2f732c26b3fc"),
                    attributes: Vec::new(),
                    modified_date: chrono::Utc.timestamp_opt(42, 42).unwrap().naive_utc(),
                }])
            });
        let ldap_handler = setup_bound_admin_handler(mock).await;
        let request = make_group_search_request(
            LdapFilter::Equality("groupid".to_string(), "1".to_string()),
            vec!["dn"],
        );
        assert_eq!(
            ldap_handler.do_search_or_dse(&request).await,
            Ok(vec![
                LdapOp::SearchResultEntry(LdapSearchResultEntry {
                    dn: "cn=group_1,ou=groups,dc=example,dc=com".to_string(),
                    attributes: vec![],
                }),
                make_search_success(),
            ])
        );
    }

    #[tokio::test]
    async fn test_search_groups_filter() {
        let mut mock = MockTestBackendHandler::new();
        mock.expect_list_groups()
            .with(eq(Some(GroupRequestFilter::And(vec![
                GroupRequestFilter::DisplayName("group_1".into()),
                GroupRequestFilter::Member(UserId::new("bob")),
                GroupRequestFilter::DisplayName("rockstars".into()),
                false.into(),
                GroupRequestFilter::Uuid(uuid!("04ac75e0-2900-3e21-926c-2f732c26b3fc")),
                false.into(),
                GroupRequestFilter::DisplayNameSubString(SubStringFilter {
                    initial: Some("iNIt".to_owned()),
                    any: vec!["1".to_owned(), "2aA".to_owned()],
                    final_: Some("finAl".to_owned()),
                }),
            ]))))
            .times(1)
            .return_once(|_| {
                Ok(vec![Group {
                    display_name: "group_1".into(),
                    id: GroupId(1),
                    creation_date: chrono::Utc.timestamp_opt(42, 42).unwrap().naive_utc(),
                    users: vec![],
                    uuid: uuid!("04ac75e0-2900-3e21-926c-2f732c26b3fc"),
                    attributes: Vec::new(),
                    modified_date: chrono::Utc.timestamp_opt(42, 42).unwrap().naive_utc(),
                }])
            });
        let ldap_handler = setup_bound_admin_handler(mock).await;
        let request = make_group_search_request(
            LdapFilter::And(vec![
                LdapFilter::Equality("cN".to_string(), "Group_1".to_string()),
                LdapFilter::Equality(
                    "uniqueMember".to_string(),
                    "uid=bob,ou=peopLe,Dc=eXample,dc=com".to_string(),
                ),
                LdapFilter::Equality(
                    "dn".to_string(),
                    "uid=rockstars,ou=groups,dc=example,dc=com".to_string(),
                ),
                LdapFilter::Equality(
                    "dn".to_string(),
                    "uid=rockstars,ou=people,dc=example,dc=com".to_string(),
                ),
                LdapFilter::Equality(
                    "uuid".to_string(),
                    "04ac75e0-2900-3e21-926c-2f732c26b3fc".to_string(),
                ),
                LdapFilter::Equality("obJEctclass".to_string(), "groupofUniqueNames".to_string()),
                LdapFilter::Equality("objectclass".to_string(), "groupOfNames".to_string()),
                LdapFilter::Present("objectclass".to_string()),
                LdapFilter::Present("dn".to_string()),
                LdapFilter::Not(Box::new(LdapFilter::Present(
                    "random_attribUte".to_string(),
                ))),
                LdapFilter::Equality("unknown_attribute".to_string(), "randomValue".to_string()),
                LdapFilter::Substring(
                    "cn".to_owned(),
                    LdapSubstringFilter {
                        initial: Some("iNIt".to_owned()),
                        any: vec!["1".to_owned(), "2aA".to_owned()],
                        final_: Some("finAl".to_owned()),
                    },
                ),
            ]),
            vec!["1.1"],
        );
        assert_eq!(
            ldap_handler.do_search_or_dse(&request).await,
            Ok(vec![
                LdapOp::SearchResultEntry(LdapSearchResultEntry {
                    dn: "cn=group_1,ou=groups,dc=example,dc=com".to_string(),
                    attributes: vec![],
                }),
                make_search_success(),
            ])
        );
    }

    #[tokio::test]
    async fn test_search_groups_filter_2() {
        let mut mock = MockTestBackendHandler::new();
        mock.expect_list_groups()
            .with(eq(Some(GroupRequestFilter::Or(vec![
                GroupRequestFilter::DisplayName("group_1".into()),
                GroupRequestFilter::Member(UserId::new("bob")),
            ]))))
            .times(1)
            .return_once(|_| Ok(vec![]));
        let ldap_handler = setup_bound_admin_handler(mock).await;
        let request = make_group_search_request(
            LdapFilter::Or(vec![
                LdapFilter::Equality("cn".to_string(), "group_1".to_string()),
                LdapFilter::Equality(
                    "member".to_string(),
                    "uid=bob,ou=people,dc=example,dc=com".to_string(),
                ),
            ]),
            vec!["cn"],
        );
        assert_eq!(
            ldap_handler.do_search_or_dse(&request).await,
            Ok(vec![make_search_success()])
        );
    }

    #[tokio::test]
    async fn test_search_groups_filter_3() {
        let mut mock = MockTestBackendHandler::new();
        mock.expect_list_groups()
            .with(eq(Some(GroupRequestFilter::Not(Box::new(
                GroupRequestFilter::DisplayName("group_1".into()),
            )))))
            .times(1)
            .return_once(|_| Ok(vec![]));
        let ldap_handler = setup_bound_admin_handler(mock).await;
        let request = make_group_search_request(
            LdapFilter::Not(Box::new(LdapFilter::Equality(
                "cn".to_string(),
                "group_1".to_string(),
            ))),
            vec!["cn"],
        );
        assert_eq!(
            ldap_handler.do_search_or_dse(&request).await,
            Ok(vec![make_search_success()])
        );
    }

    #[tokio::test]
    async fn test_search_groups_filter_uuid_substring() {
        let mut mock = MockTestBackendHandler::new();
        mock.expect_list_groups()
            .with(eq(Some(GroupRequestFilter::UuidSubString(
                SubStringFilter {
                    initial: Some("iNIt".to_owned()),
                    any: vec!["1".to_owned(), "2aA".to_owned()],
                    final_: Some("finAl".to_owned()),
                },
            ))))
            .times(1)
            .return_once(|_| {
                Ok(vec![Group {
                    display_name: "group_1".into(),
                    id: GroupId(1),
                    creation_date: chrono::Utc.timestamp_opt(42, 42).unwrap().naive_utc(),
                    users: vec![],
                    uuid: uuid!("04ac75e0-2900-3e21-926c-2f732c26b3fc"),
                    attributes: Vec::new(),
                    modified_date: chrono::Utc.timestamp_opt(42, 42).unwrap().naive_utc(),
                }])
            });
        let ldap_handler = setup_bound_admin_handler(mock).await;
        let request = make_group_search_request(
            LdapFilter::Substring(
                "uuid".to_owned(),
                LdapSubstringFilter {
                    initial: Some("iNIt".to_owned()),
                    any: vec!["1".to_owned(), "2aA".to_owned()],
                    final_: Some("finAl".to_owned()),
                },
            ),
            vec!["1.1"],
        );
        assert_eq!(
            ldap_handler.do_search_or_dse(&request).await,
            Ok(vec![
                LdapOp::SearchResultEntry(LdapSearchResultEntry {
                    dn: "cn=group_1,ou=groups,dc=example,dc=com".to_string(),
                    attributes: vec![],
                }),
                make_search_success(),
            ])
        );
    }

    #[tokio::test]
    async fn test_search_group_as_scope() {
        let mut mock = MockTestBackendHandler::new();
        mock.expect_list_groups()
            .with(eq(Some(GroupRequestFilter::DisplayName("group_1".into()))))
            .times(1)
            .return_once(|_| Ok(vec![]));
        let ldap_handler = setup_bound_admin_handler(mock).await;
        let request = make_search_request(
            "cn=group_1,ou=groups,dc=example,dc=com",
            LdapFilter::And(vec![]),
            vec!["objectClass"],
        );
        assert_eq!(
            ldap_handler.do_search_or_dse(&request).await,
            Ok(vec![make_search_success()]),
        );
    }
}
