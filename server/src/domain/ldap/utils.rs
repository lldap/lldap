use std::collections::BTreeMap;

use chrono::{NaiveDateTime, TimeZone};
use ldap3_proto::{proto::LdapSubstringFilter, LdapResultCode};
use tracing::{debug, instrument, warn};

use crate::domain::{
    handler::SubStringFilter,
    ldap::error::{LdapError, LdapResult},
    schema::{PublicSchema, SchemaAttributeExtractor},
    types::{
        AttributeName, AttributeType, AttributeValue, GroupName, JpegPhoto, UserColumn, UserId,
    },
};

impl From<LdapSubstringFilter> for SubStringFilter {
    fn from(
        LdapSubstringFilter {
            initial,
            any,
            final_,
        }: LdapSubstringFilter,
    ) -> Self {
        Self {
            initial,
            any,
            final_,
        }
    }
}

fn make_dn_pair<I>(mut iter: I) -> LdapResult<(String, String)>
where
    I: Iterator<Item = String>,
{
    (|| {
        let pair = (
            iter.next().ok_or_else(|| "Empty DN element".to_string())?,
            iter.next().ok_or_else(|| "Missing DN value".to_string())?,
        );
        if let Some(e) = iter.next() {
            Err(format!(
                r#"Too many elements in distinguished name: "{:?}", "{:?}", "{:?}""#,
                pair.0, pair.1, e
            ))
        } else {
            Ok(pair)
        }
    })()
    .map_err(|s| LdapError {
        code: LdapResultCode::InvalidDNSyntax,
        message: s,
    })
}

pub fn parse_distinguished_name(dn: &str) -> LdapResult<Vec<(String, String)>> {
    assert!(dn == dn.to_ascii_lowercase());
    dn.split(',')
        .map(|s| make_dn_pair(s.split('=').map(str::trim).map(String::from)))
        .collect()
}

fn get_id_from_distinguished_name(
    dn: &str,
    base_tree: &[(String, String)],
    base_dn_str: &str,
    is_group: bool,
) -> LdapResult<String> {
    let parts = parse_distinguished_name(dn)?;
    {
        let ou = if is_group { "groups" } else { "people" };
        if !is_subtree(&parts, base_tree) {
            Err("Not a subtree of the base tree".to_string())
        } else if parts.len() == base_tree.len() + 2 {
            if parts[1].0 != "ou" || parts[1].1 != ou || (parts[0].0 != "cn" && parts[0].0 != "uid")
            {
                Err(format!(
                    r#"Unexpected DN format. Got "{}", expected: "uid=id,ou={},{}""#,
                    dn, ou, base_dn_str
                ))
            } else {
                Ok(parts[0].1.to_string())
            }
        } else {
            Err(format!(
                r#"Unexpected DN format. Got "{}", expected: "uid=id,ou={},{}""#,
                dn, ou, base_dn_str
            ))
        }
    }
    .map_err(|s| LdapError {
        code: LdapResultCode::InvalidDNSyntax,
        message: s,
    })
}

pub fn get_user_id_from_distinguished_name(
    dn: &str,
    base_tree: &[(String, String)],
    base_dn_str: &str,
) -> LdapResult<UserId> {
    get_id_from_distinguished_name(dn, base_tree, base_dn_str, false).map(UserId::from)
}

pub fn get_group_id_from_distinguished_name(
    dn: &str,
    base_tree: &[(String, String)],
    base_dn_str: &str,
) -> LdapResult<GroupName> {
    get_id_from_distinguished_name(dn, base_tree, base_dn_str, true).map(GroupName::from)
}

fn looks_like_distinguished_name(dn: &str) -> bool {
    dn.contains('=') || dn.contains(',')
}

pub fn get_user_id_from_distinguished_name_or_plain_name(
    dn: &str,
    base_tree: &[(String, String)],
    base_dn_str: &str,
) -> LdapResult<UserId> {
    if !looks_like_distinguished_name(dn) {
        Ok(UserId::from(dn))
    } else {
        get_user_id_from_distinguished_name(dn, base_tree, base_dn_str)
    }
}

pub fn get_group_id_from_distinguished_name_or_plain_name(
    dn: &str,
    base_tree: &[(String, String)],
    base_dn_str: &str,
) -> LdapResult<GroupName> {
    if !looks_like_distinguished_name(dn) {
        Ok(GroupName::from(dn))
    } else {
        get_group_id_from_distinguished_name(dn, base_tree, base_dn_str)
    }
}

#[derive(Clone)]
pub struct ExpandedAttributes {
    // Lowercase name to original name.
    pub attribute_keys: BTreeMap<AttributeName, String>,
    pub include_custom_attributes: bool,
}

#[instrument(skip(all_attribute_keys), level = "debug")]
pub fn expand_attribute_wildcards(
    ldap_attributes: &[String],
    all_attribute_keys: &[&'static str],
) -> ExpandedAttributes {
    let mut include_custom_attributes = false;
    let mut attributes_out: BTreeMap<_, _> = ldap_attributes
        .iter()
        .filter(|&s| s != "*" && s != "+" && s != "1.1")
        .map(|s| (AttributeName::from(s), s.to_string()))
        .collect();
    attributes_out.extend(
        if ldap_attributes.iter().any(|x| x == "*") || ldap_attributes.is_empty() {
            include_custom_attributes = true;
            all_attribute_keys
        } else {
            &[]
        }
        .iter()
        .map(|&s| (AttributeName::from(s), s.to_string())),
    );
    debug!(?attributes_out);
    ExpandedAttributes {
        attribute_keys: attributes_out,
        include_custom_attributes,
    }
}

pub fn is_subtree(subtree: &[(String, String)], base_tree: &[(String, String)]) -> bool {
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

pub enum UserFieldType {
    NoMatch,
    ObjectClass,
    MemberOf,
    Dn,
    EntryDn,
    PrimaryField(UserColumn),
    Attribute(AttributeName, AttributeType, bool),
}

pub fn map_user_field(field: &AttributeName, schema: &PublicSchema) -> UserFieldType {
    match field.as_str() {
        "memberof" | "ismemberof" => UserFieldType::MemberOf,
        "objectclass" => UserFieldType::ObjectClass,
        "dn" | "distinguishedname" => UserFieldType::Dn,
        "entrydn" => UserFieldType::EntryDn,
        "uid" | "user_id" | "id" => UserFieldType::PrimaryField(UserColumn::UserId),
        "mail" | "email" => UserFieldType::PrimaryField(UserColumn::Email),
        "cn" | "displayname" | "display_name" => {
            UserFieldType::PrimaryField(UserColumn::DisplayName)
        }
        "givenname" | "first_name" | "firstname" => UserFieldType::Attribute(
            AttributeName::from("first_name"),
            AttributeType::String,
            false,
        ),
        "sn" | "last_name" | "lastname" => UserFieldType::Attribute(
            AttributeName::from("last_name"),
            AttributeType::String,
            false,
        ),
        "avatar" | "jpegphoto" => UserFieldType::Attribute(
            AttributeName::from("avatar"),
            AttributeType::JpegPhoto,
            false,
        ),
        "creationdate" | "createtimestamp" | "modifytimestamp" | "creation_date" => {
            UserFieldType::PrimaryField(UserColumn::CreationDate)
        }
        "entryuuid" | "uuid" => UserFieldType::PrimaryField(UserColumn::Uuid),
        _ => schema
            .get_schema()
            .user_attributes
            .get_attribute_type(field)
            .map(|(t, is_list)| UserFieldType::Attribute(field.clone(), t, is_list))
            .unwrap_or(UserFieldType::NoMatch),
    }
}

pub enum GroupFieldType {
    NoMatch,
    DisplayName,
    CreationDate,
    ObjectClass,
    Dn,
    // Like Dn, but returned as part of the attributes.
    EntryDn,
    Member,
    Uuid,
    Attribute(AttributeName, AttributeType, bool),
}

pub fn map_group_field(field: &AttributeName, schema: &PublicSchema) -> GroupFieldType {
    match field.as_str() {
        "dn" | "distinguishedname" => GroupFieldType::Dn,
        "entrydn" => GroupFieldType::EntryDn,
        "objectclass" => GroupFieldType::ObjectClass,
        "cn" | "displayname" | "uid" | "display_name" | "id" => GroupFieldType::DisplayName,
        "creationdate" | "createtimestamp" | "modifytimestamp" | "creation_date" => {
            GroupFieldType::CreationDate
        }
        "member" | "uniquemember" => GroupFieldType::Member,
        "entryuuid" | "uuid" => GroupFieldType::Uuid,
        _ => schema
            .get_schema()
            .group_attributes
            .get_attribute_type(field)
            .map(|(t, is_list)| GroupFieldType::Attribute(field.clone(), t, is_list))
            .unwrap_or(GroupFieldType::NoMatch),
    }
}

pub struct LdapInfo {
    pub base_dn: Vec<(String, String)>,
    pub base_dn_str: String,
    pub ignored_user_attributes: Vec<AttributeName>,
    pub ignored_group_attributes: Vec<AttributeName>,
}

pub fn get_custom_attribute<Extractor: SchemaAttributeExtractor>(
    attributes: &[AttributeValue],
    attribute_name: &AttributeName,
    schema: &PublicSchema,
) -> Option<Vec<Vec<u8>>> {
    let convert_date = |date| {
        chrono::Utc
            .from_utc_datetime(&date)
            .to_rfc3339()
            .into_bytes()
    };
    Extractor::get_attributes(schema)
        .get_attribute_type(attribute_name)
        .and_then(|attribute_type| {
            attributes
                .iter()
                .find(|a| &a.name == attribute_name)
                .map(|attribute| match attribute_type {
                    (AttributeType::String, false) => {
                        vec![attribute.value.unwrap::<String>().into_bytes()]
                    }
                    (AttributeType::Integer, false) => {
                        // LDAP integers are encoded as strings.
                        vec![attribute.value.unwrap::<i64>().to_string().into_bytes()]
                    }
                    (AttributeType::JpegPhoto, false) => {
                        vec![attribute.value.unwrap::<JpegPhoto>().into_bytes()]
                    }
                    (AttributeType::DateTime, false) => {
                        vec![convert_date(attribute.value.unwrap::<NaiveDateTime>())]
                    }
                    (AttributeType::String, true) => attribute
                        .value
                        .unwrap::<Vec<String>>()
                        .into_iter()
                        .map(String::into_bytes)
                        .collect(),
                    (AttributeType::Integer, true) => attribute
                        .value
                        .unwrap::<Vec<i64>>()
                        .into_iter()
                        .map(|i| i.to_string())
                        .map(String::into_bytes)
                        .collect(),
                    (AttributeType::JpegPhoto, true) => attribute
                        .value
                        .unwrap::<Vec<JpegPhoto>>()
                        .into_iter()
                        .map(JpegPhoto::into_bytes)
                        .collect(),
                    (AttributeType::DateTime, true) => attribute
                        .value
                        .unwrap::<Vec<NaiveDateTime>>()
                        .into_iter()
                        .map(convert_date)
                        .collect(),
                })
        })
}
