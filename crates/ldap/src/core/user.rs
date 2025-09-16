use crate::core::{
    error::{LdapError, LdapResult},
    utils::{
        ExpandedAttributes, LdapInfo, UserFieldType, expand_attribute_wildcards,
        get_custom_attribute, get_group_id_from_distinguished_name_or_plain_name,
        get_user_id_from_distinguished_name_or_plain_name, map_user_field,
    },
};
use chrono::TimeZone;
use ldap3_proto::{
    LdapFilter, LdapPartialAttribute, LdapResultCode, LdapSearchResultEntry, proto::LdapOp,
};
use lldap_domain::{
    deserialize::deserialize_attribute_value,
    public_schema::PublicSchema,
    types::{
        AttributeName, AttributeType, GroupDetails, LdapObjectClass, User, UserAndGroups, UserId,
    },
};
use lldap_domain_handlers::handler::{UserListerBackendHandler, UserRequestFilter};
use lldap_domain_model::model::UserColumn;
use tracing::{debug, instrument, warn};

pub const REQUIRED_USER_ATTRIBUTES: &[&str] = &["user_id", "mail"];

const DEFAULT_USER_OBJECT_CLASSES: &[&str] =
    &["inetOrgPerson", "posixAccount", "mailAccount", "person"];

fn get_default_user_object_classes_vec_u8() -> Vec<Vec<u8>> {
    DEFAULT_USER_OBJECT_CLASSES
        .iter()
        .map(|c| c.as_bytes().to_vec())
        .collect()
}

pub fn get_default_user_object_classes() -> Vec<LdapObjectClass> {
    DEFAULT_USER_OBJECT_CLASSES
        .iter()
        .map(|&c| LdapObjectClass::from(c))
        .collect()
}

pub fn get_user_attribute(
    user: &User,
    attribute: &AttributeName,
    base_dn_str: &str,
    groups: Option<&[GroupDetails]>,
    ignored_user_attributes: &[AttributeName],
    schema: &PublicSchema,
) -> Option<Vec<Vec<u8>>> {
    let attribute_values = match map_user_field(attribute, schema) {
        UserFieldType::ObjectClass => {
            let mut classes: Vec<Vec<u8>> = get_default_user_object_classes_vec_u8();

            classes.extend(
                schema
                    .get_schema()
                    .extra_user_object_classes
                    .iter()
                    .map(|c| c.as_str().as_bytes().to_vec()),
            );
            classes
        }
        // dn is always returned as part of the base response.
        UserFieldType::Dn => return None,
        UserFieldType::EntryDn => {
            vec![format!("uid={},ou=people,{}", &user.user_id, base_dn_str).into_bytes()]
        }
        UserFieldType::MemberOf => groups
            .into_iter()
            .flatten()
            .map(|id_and_name| {
                format!("cn={},ou=groups,{}", &id_and_name.display_name, base_dn_str).into_bytes()
            })
            .collect(),
        UserFieldType::PrimaryField(UserColumn::UserId) => {
            vec![user.user_id.to_string().into_bytes()]
        }
        UserFieldType::PrimaryField(UserColumn::Email) => vec![user.email.to_string().into_bytes()],
        UserFieldType::PrimaryField(
            UserColumn::LowercaseEmail
            | UserColumn::PasswordHash
            | UserColumn::TotpSecret
            | UserColumn::MfaType,
        ) => panic!("Should not get here"),
        UserFieldType::PrimaryField(UserColumn::Uuid) => vec![user.uuid.to_string().into_bytes()],
        UserFieldType::PrimaryField(UserColumn::DisplayName) => {
            vec![user.display_name.clone()?.into_bytes()]
        }
        UserFieldType::PrimaryField(UserColumn::CreationDate) => vec![
            chrono::Utc
                .from_utc_datetime(&user.creation_date)
                .to_rfc3339()
                .into_bytes(),
        ],
        UserFieldType::PrimaryField(UserColumn::ModifiedDate) => vec![
            chrono::Utc
                .from_utc_datetime(&user.modified_date)
                .to_rfc3339()
                .into_bytes(),
        ],
        UserFieldType::PrimaryField(UserColumn::PasswordModifiedDate) => vec![
            chrono::Utc
                .from_utc_datetime(&user.password_modified_date)
                .to_rfc3339()
                .into_bytes(),
        ],
        UserFieldType::Attribute(attr, _, _) => get_custom_attribute(&user.attributes, &attr)?,
        UserFieldType::NoMatch => match attribute.as_str() {
            "1.1" => return None,
            // We ignore the operational attribute wildcard.
            "+" => return None,
            "*" => {
                panic!(
                    "Matched {attribute}, * should have been expanded into attribute list and * removed"
                )
            }
            _ => {
                if ignored_user_attributes.contains(attribute) {
                    return None;
                }
                get_custom_attribute(&user.attributes, attribute).or_else(|| {
                    warn!(
                        r#"Ignoring unrecognized user attribute: {}. To disable this warning, add it to "ignored_user_attributes" in the config."#,
                        attribute
                    );
                    None
                })?
            }
        },
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
    mut expanded_attributes: ExpandedAttributes,
    groups: Option<&[GroupDetails]>,
    ignored_user_attributes: &[AttributeName],
    schema: &PublicSchema,
) -> LdapSearchResultEntry {
    if expanded_attributes.include_custom_attributes {
        expanded_attributes.attribute_keys.extend(
            user.attributes
                .iter()
                .map(|a| (a.name.clone(), a.name.to_string())),
        );
    }
    LdapSearchResultEntry {
        dn: format!("uid={},ou=people,{}", user.user_id.as_str(), base_dn_str),
        attributes: expanded_attributes
            .attribute_keys
            .into_iter()
            .filter_map(|(attribute, name)| {
                let values = get_user_attribute(
                    &user,
                    &attribute,
                    base_dn_str,
                    groups,
                    ignored_user_attributes,
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

fn get_user_attribute_equality_filter(
    field: &AttributeName,
    typ: AttributeType,
    is_list: bool,
    value: &str,
) -> UserRequestFilter {
    let value_lc = value.to_ascii_lowercase();
    let serialized_value = deserialize_attribute_value(&[value.to_owned()], typ, is_list);
    let serialized_value_lc = deserialize_attribute_value(&[value_lc.to_owned()], typ, is_list);
    match (serialized_value, serialized_value_lc) {
        (Ok(v), Ok(v_lc)) => UserRequestFilter::Or(vec![
            UserRequestFilter::AttributeEquality(field.clone(), v),
            UserRequestFilter::AttributeEquality(field.clone(), v_lc),
        ]),
        (Ok(_), Err(e)) => {
            warn!("Invalid value for attribute {} (lowercased): {}", field, e);
            UserRequestFilter::False
        }
        (Err(e), _) => {
            warn!("Invalid value for attribute {}: {}", field, e);
            UserRequestFilter::False
        }
    }
}

fn convert_user_filter(
    ldap_info: &LdapInfo,
    filter: &LdapFilter,
    schema: &PublicSchema,
) -> LdapResult<UserRequestFilter> {
    let rec = |f| convert_user_filter(ldap_info, f, schema);
    match filter {
        LdapFilter::And(filters) => {
            let res = filters
                .iter()
                .map(rec)
                .filter(|c| !matches!(c, Ok(UserRequestFilter::False)))
                .flat_map(|f| match f {
                    Ok(UserRequestFilter::And(v)) => v.into_iter().map(Ok).collect(),
                    f => vec![f],
                })
                .collect::<LdapResult<Vec<_>>>()?;
            if res.is_empty() {
                Ok(UserRequestFilter::True)
            } else if res.len() == 1 {
                Ok(res.into_iter().next().unwrap())
            } else {
                Ok(UserRequestFilter::And(res))
            }
        }
        LdapFilter::Or(filters) => {
            let res = filters
                .iter()
                .map(rec)
                .filter(|c| !matches!(c, Ok(UserRequestFilter::True)))
                .flat_map(|f| match f {
                    Ok(UserRequestFilter::Or(v)) => v.into_iter().map(Ok).collect(),
                    f => vec![f],
                })
                .collect::<LdapResult<Vec<_>>>()?;
            if res.is_empty() {
                Ok(UserRequestFilter::False)
            } else if res.len() == 1 {
                Ok(res.into_iter().next().unwrap())
            } else {
                Ok(UserRequestFilter::Or(res))
            }
        }
        LdapFilter::Not(filter) => Ok(match rec(filter)? {
            UserRequestFilter::True => UserRequestFilter::False,
            UserRequestFilter::False => UserRequestFilter::True,
            f => UserRequestFilter::Not(Box::new(f)),
        }),
        LdapFilter::Equality(field, value) => {
            let field = AttributeName::from(field.as_str());
            let value_lc = value.to_ascii_lowercase();
            match map_user_field(&field, schema) {
                UserFieldType::PrimaryField(UserColumn::UserId) => {
                    Ok(UserRequestFilter::UserId(UserId::new(&value_lc)))
                }
                UserFieldType::PrimaryField(UserColumn::Email) => Ok(UserRequestFilter::Equality(
                    UserColumn::LowercaseEmail,
                    value_lc,
                )),
                UserFieldType::PrimaryField(field) => {
                    Ok(UserRequestFilter::Equality(field, value_lc))
                }
                UserFieldType::Attribute(field, typ, is_list) => Ok(
                    get_user_attribute_equality_filter(&field, typ, is_list, value),
                ),
                UserFieldType::NoMatch => {
                    if !ldap_info.ignored_user_attributes.contains(&field) {
                        warn!(
                            r#"Ignoring unknown user attribute "{}" in filter.\n\
                                      To disable this warning, add it to "ignored_user_attributes" in the config"#,
                            field
                        );
                    }
                    Ok(UserRequestFilter::False)
                }
                UserFieldType::ObjectClass => Ok(UserRequestFilter::from(
                    get_default_user_object_classes()
                        .iter()
                        .any(|class| class.as_str().eq_ignore_ascii_case(value_lc.as_str()))
                        || schema
                            .get_schema()
                            .extra_user_object_classes
                            .contains(&LdapObjectClass::from(value_lc)),
                )),
                UserFieldType::MemberOf => Ok(get_group_id_from_distinguished_name_or_plain_name(
                    &value_lc,
                    &ldap_info.base_dn,
                    &ldap_info.base_dn_str,
                )
                .map(UserRequestFilter::MemberOf)
                .unwrap_or_else(|e| {
                    warn!("Invalid memberOf filter: {}", e);
                    UserRequestFilter::False
                })),
                UserFieldType::EntryDn | UserFieldType::Dn => {
                    Ok(get_user_id_from_distinguished_name_or_plain_name(
                        value_lc.as_str(),
                        &ldap_info.base_dn,
                        &ldap_info.base_dn_str,
                    )
                    .map(UserRequestFilter::UserId)
                    .unwrap_or_else(|_| {
                        warn!("Invalid dn filter on user: {}", value_lc);
                        UserRequestFilter::False
                    }))
                }
            }
        }
        LdapFilter::Present(field) => {
            let field = AttributeName::from(field.as_str());
            Ok(match map_user_field(&field, schema) {
                UserFieldType::Attribute(name, _, _) => {
                    UserRequestFilter::CustomAttributePresent(name)
                }
                UserFieldType::NoMatch => UserRequestFilter::False,
                _ => UserRequestFilter::True,
            })
        }
        LdapFilter::Substring(field, substring_filter) => {
            let field = AttributeName::from(field.as_str());
            match map_user_field(&field, schema) {
                UserFieldType::PrimaryField(UserColumn::UserId) => Ok(
                    UserRequestFilter::UserIdSubString(substring_filter.clone().into()),
                ),
                UserFieldType::Attribute(_, _, _)
                | UserFieldType::ObjectClass
                | UserFieldType::MemberOf
                | UserFieldType::Dn
                | UserFieldType::EntryDn
                | UserFieldType::PrimaryField(UserColumn::CreationDate)
                | UserFieldType::PrimaryField(UserColumn::Uuid) => Err(LdapError {
                    code: LdapResultCode::UnwillingToPerform,
                    message: format!("Unsupported user attribute for substring filter: {field:?}"),
                }),
                UserFieldType::NoMatch => Ok(UserRequestFilter::False),
                UserFieldType::PrimaryField(UserColumn::Email) => Ok(UserRequestFilter::SubString(
                    UserColumn::LowercaseEmail,
                    substring_filter.clone().into(),
                )),
                UserFieldType::PrimaryField(field) => Ok(UserRequestFilter::SubString(
                    field,
                    substring_filter.clone().into(),
                )),
            }
        }
        _ => Err(LdapError {
            code: LdapResultCode::UnwillingToPerform,
            message: format!("Unsupported user filter: {filter:?}"),
        }),
    }
}

fn expand_user_attribute_wildcards(attributes: &[String]) -> ExpandedAttributes {
    expand_attribute_wildcards(attributes, ALL_USER_ATTRIBUTE_KEYS)
}

#[instrument(skip_all, level = "debug", fields(ldap_filter, request_groups))]
pub async fn get_user_list<Backend: UserListerBackendHandler>(
    ldap_info: &LdapInfo,
    ldap_filter: &LdapFilter,
    request_groups: bool,
    base: &str,
    backend: &Backend,
    schema: &PublicSchema,
) -> LdapResult<Vec<UserAndGroups>> {
    let filters = convert_user_filter(ldap_info, ldap_filter, schema)?;
    debug!(?filters);
    backend
        .list_users(Some(filters), request_groups)
        .await
        .map_err(|e| LdapError {
            code: LdapResultCode::Other,
            message: format!(r#"Error while searching user "{base}": {e:#}"#),
        })
}

pub fn convert_users_to_ldap_op<'a>(
    users: Vec<UserAndGroups>,
    attributes: &'a [String],
    ldap_info: &'a LdapInfo,
    schema: &'a PublicSchema,
) -> impl Iterator<Item = LdapOp> + 'a {
    let expanded_attributes = if users.is_empty() {
        None
    } else {
        Some(expand_user_attribute_wildcards(attributes))
    };
    users.into_iter().map(move |u| {
        LdapOp::SearchResultEntry(make_ldap_search_user_result_entry(
            u.user,
            &ldap_info.base_dn_str,
            expanded_attributes.clone().unwrap(),
            u.groups.as_deref(),
            &ldap_info.ignored_user_attributes,
            schema,
        ))
    })
}
