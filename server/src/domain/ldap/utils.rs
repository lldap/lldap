use itertools::Itertools;
use ldap3_proto::LdapResultCode;
use tracing::{debug, instrument, warn};

use crate::domain::{
    ldap::error::{LdapError, LdapResult},
    types::{GroupColumn, UserColumn, UserId},
};

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

#[instrument(skip_all, level = "debug")]
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
    debug!(?ldap_attributes, ?resolved_attributes);
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

pub fn map_user_field(field: &str) -> Option<UserColumn> {
    assert!(field == field.to_ascii_lowercase());
    Some(match field {
        "uid" | "user_id" | "id" => UserColumn::UserId,
        "mail" | "email" => UserColumn::Email,
        "cn" | "displayname" | "display_name" => UserColumn::DisplayName,
        "givenname" | "first_name" => UserColumn::FirstName,
        "sn" | "last_name" => UserColumn::LastName,
        "avatar" => UserColumn::Avatar,
        "creationdate" | "createtimestamp" | "modifytimestamp" | "creation_date" => {
            UserColumn::CreationDate
        }
        "entryuuid" | "uuid" => UserColumn::Uuid,
        _ => return None,
    })
}

pub fn map_group_field(field: &str) -> Option<GroupColumn> {
    assert!(field == field.to_ascii_lowercase());
    Some(match field {
        "cn" | "displayname" | "uid" | "display_name" => GroupColumn::DisplayName,
        "creationdate" | "createtimestamp" | "modifytimestamp" | "creation_date" => {
            GroupColumn::CreationDate
        }
        "entryuuid" | "uuid" => GroupColumn::Uuid,
        _ => return None,
    })
}

pub struct LdapInfo {
    pub base_dn: Vec<(String, String)>,
    pub base_dn_str: String,
    pub ignored_user_attributes: Vec<String>,
    pub ignored_group_attributes: Vec<String>,
}
