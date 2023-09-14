use chrono::{NaiveDateTime, TimeZone};
use itertools::Itertools;
use ldap3_proto::{proto::LdapSubstringFilter, LdapResultCode};
use tracing::{debug, instrument, warn};

use crate::domain::{
    handler::SubStringFilter,
    ldap::error::{LdapError, LdapResult},
    schema::{PublicSchema, SchemaAttributeExtractor},
    types::{AttributeType, AttributeValue, JpegPhoto, UserColumn, UserId},
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
) -> LdapResult<String> {
    get_id_from_distinguished_name(dn, base_tree, base_dn_str, true)
}

#[instrument(skip(all_attribute_keys), level = "debug")]
pub fn expand_attribute_wildcards<'a>(
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
    debug!(?resolved_attributes);
    resolved_attributes
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
    PrimaryField(UserColumn),
    Attribute(&'static str),
}

pub fn map_user_field(field: &str) -> UserFieldType {
    assert!(field == field.to_ascii_lowercase());
    match field {
        "uid" | "user_id" | "id" => UserFieldType::PrimaryField(UserColumn::UserId),
        "mail" | "email" => UserFieldType::PrimaryField(UserColumn::Email),
        "cn" | "displayname" | "display_name" => {
            UserFieldType::PrimaryField(UserColumn::DisplayName)
        }
        "givenname" | "first_name" | "firstname" => UserFieldType::Attribute("first_name"),
        "sn" | "last_name" | "lastname" => UserFieldType::Attribute("last_name"),
        "avatar" | "jpegphoto" => UserFieldType::Attribute("avatar"),
        "creationdate" | "createtimestamp" | "modifytimestamp" | "creation_date" => {
            UserFieldType::PrimaryField(UserColumn::CreationDate)
        }
        "entryuuid" | "uuid" => UserFieldType::PrimaryField(UserColumn::Uuid),
        _ => UserFieldType::NoMatch,
    }
}

pub fn map_group_field(field: &str) -> Option<&'static str> {
    assert!(field == field.to_ascii_lowercase());
    Some(match field {
        "cn" | "displayname" | "uid" | "display_name" => "display_name",
        "creationdate" | "createtimestamp" | "modifytimestamp" | "creation_date" => "creation_date",
        "entryuuid" | "uuid" => "uuid",
        _ => return None,
    })
}

pub struct LdapInfo {
    pub base_dn: Vec<(String, String)>,
    pub base_dn_str: String,
    pub ignored_user_attributes: Vec<String>,
    pub ignored_group_attributes: Vec<String>,
}

pub fn get_custom_attribute<Extractor: SchemaAttributeExtractor>(
    attributes: &[AttributeValue],
    attribute_name: &str,
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
                .find(|a| a.name == attribute_name)
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
