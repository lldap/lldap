use crate::core::{
    error::{LdapError, LdapResult},
    group::{REQUIRED_GROUP_ATTRIBUTES, get_default_group_object_classes},
    user::{REQUIRED_USER_ATTRIBUTES, get_default_user_object_classes},
};
use chrono::TimeZone;
use itertools::join;
use ldap3_proto::LdapResultCode;
use lldap_domain::{
    public_schema::PublicSchema,
    schema::{AttributeList, Schema},
    types::{
        Attribute, AttributeName, AttributeType, AttributeValue, Cardinality, GroupName,
        LdapObjectClass, UserId,
    },
};
use lldap_domain_model::model::UserColumn;
use std::collections::BTreeMap;
use tracing::{debug, instrument, warn};

/// Convert a boolean to LDAP string representation.
/// LDAP booleans are encoded as strings: "TRUE" or "FALSE"
fn convert_bool(b: bool) -> Vec<u8> {
    if b {
        b"TRUE".to_vec()
    } else {
        b"FALSE".to_vec()
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
                r#"Too many elements in distinguished name: "{}", "{}", "{}""#,
                pair.0, pair.1, e
            ))
        } else {
            Ok(pair)
        }
    })()
    .map_err(|e| LdapError {
        code: LdapResultCode::InvalidDNSyntax,
        message: e,
    })
}

pub fn parse_distinguished_name(dn: &str) -> LdapResult<Vec<(String, String)>> {
    assert!(dn == dn.to_ascii_lowercase());
    dn.split(',')
        .map(|s| make_dn_pair(s.split('=').map(str::trim).map(String::from)))
        .collect()
}

pub enum UserOrGroupName {
    User(UserId),
    Group(GroupName),
    BadSubStree,
    UnexpectedFormat,
    InvalidSyntax(LdapError),
}

impl UserOrGroupName {
    pub fn into_ldap_error(self, input: &str, expected_format: String) -> LdapError {
        LdapError {
            code: LdapResultCode::InvalidDNSyntax,
            message: match self {
                UserOrGroupName::BadSubStree => "Not a subtree of the base tree".to_string(),
                UserOrGroupName::InvalidSyntax(err) => return err,
                UserOrGroupName::UnexpectedFormat
                | UserOrGroupName::User(_)
                | UserOrGroupName::Group(_) => {
                    format!(r#"Unexpected DN format. Got "{input}", expected: {expected_format}"#)
                }
            },
        }
    }
}

pub fn get_user_or_group_id_from_distinguished_name(
    dn: &str,
    base_tree: &[(String, String)],
) -> UserOrGroupName {
    let parts = match parse_distinguished_name(dn) {
        Ok(p) => p,
        Err(e) => return UserOrGroupName::InvalidSyntax(e),
    };
    if !is_subtree(&parts, base_tree) {
        return UserOrGroupName::BadSubStree;
    } else if parts.len() == base_tree.len() + 2
        && parts[1].0 == "ou"
        && (parts[0].0 == "cn" || parts[0].0 == "uid")
    {
        if parts[1].1 == "groups" {
            return UserOrGroupName::Group(GroupName::from(parts[0].1.clone()));
        } else if parts[1].1 == "people" {
            return UserOrGroupName::User(UserId::from(parts[0].1.clone()));
        }
    }
    UserOrGroupName::UnexpectedFormat
}

pub fn get_user_id_from_distinguished_name(
    dn: &str,
    base_tree: &[(String, String)],
    base_dn_str: &str,
) -> LdapResult<UserId> {
    match get_user_or_group_id_from_distinguished_name(dn, base_tree) {
        UserOrGroupName::User(user_id) => Ok(user_id),
        err => Err(err.into_ldap_error(dn, format!(r#""uid=id,ou=people,{base_dn_str}""#))),
    }
}

pub fn get_group_id_from_distinguished_name(
    dn: &str,
    base_tree: &[(String, String)],
    base_dn_str: &str,
) -> LdapResult<GroupName> {
    match get_user_or_group_id_from_distinguished_name(dn, base_tree) {
        UserOrGroupName::Group(group_name) => Ok(group_name),
        err => Err(err.into_ldap_error(dn, format!(r#""uid=id,ou=groups,{base_dn_str}""#))),
    }
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
        "loginenabled" => UserFieldType::PrimaryField(UserColumn::LoginEnabled),
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
    GroupId,
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
        "group_id" | "groupid" => GroupFieldType::GroupId,
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

pub fn get_custom_attribute(
    attributes: &[Attribute],
    attribute_name: &AttributeName,
) -> Option<Vec<Vec<u8>>> {
    let convert_date = |date| {
        chrono::Utc
            .from_utc_datetime(date)
            .to_rfc3339()
            .into_bytes()
    };
    attributes
        .iter()
        .find(|a| &a.name == attribute_name)
        .map(|attribute| match &attribute.value {
            AttributeValue::String(Cardinality::Singleton(s)) => {
                vec![s.clone().into_bytes()]
            }
            AttributeValue::String(Cardinality::Unbounded(l)) => {
                l.iter().map(|s| s.clone().into_bytes()).collect()
            }
            AttributeValue::Integer(Cardinality::Singleton(i)) => {
                // LDAP integers are encoded as strings.
                vec![i.to_string().into_bytes()]
            }
            AttributeValue::Integer(Cardinality::Unbounded(l)) => l
                .iter()
                // LDAP integers are encoded as strings.
                .map(|i| i.to_string().into_bytes())
                .collect(),
            AttributeValue::JpegPhoto(Cardinality::Singleton(p)) => {
                vec![p.clone().into_bytes()]
            }
            AttributeValue::JpegPhoto(Cardinality::Unbounded(l)) => {
                l.iter().map(|p| p.clone().into_bytes()).collect()
            }
            AttributeValue::DateTime(Cardinality::Singleton(dt)) => vec![convert_date(dt)],
            AttributeValue::DateTime(Cardinality::Unbounded(l)) => {
                l.iter().map(convert_date).collect()
            }
            AttributeValue::Boolean(Cardinality::Singleton(b)) => {
                vec![convert_bool(*b)]
            }
            AttributeValue::Boolean(Cardinality::Unbounded(l)) => l
                .iter()
                .map(|b| convert_bool(*b))
                .collect(),
        })
}

#[derive(derive_more::From)]
pub struct ObjectClassList(Vec<LdapObjectClass>);

// See RFC4512 section 4.2.1 "objectClasses"
impl ObjectClassList {
    pub fn format_for_ldap_schema_description(&self) -> String {
        join(self.0.iter().map(|c| format!("'{c}'")), " ")
    }
}

// See RFC4512 section 4.2 "Subschema Subentries"
// This struct holds all information on what attributes and objectclasses are present on the server.
// It can be used to 'index' a server using a LDAP subschema call.
pub struct LdapSchemaDescription {
    base: PublicSchema,
    user_object_classes: ObjectClassList,
    group_object_classes: ObjectClassList,
}

impl LdapSchemaDescription {
    pub fn from(schema: PublicSchema) -> Self {
        let mut user_object_classes = get_default_user_object_classes();
        user_object_classes.extend(schema.get_schema().extra_user_object_classes.clone());
        let mut group_object_classes = get_default_group_object_classes();
        group_object_classes.extend(schema.get_schema().extra_group_object_classes.clone());

        Self {
            base: schema,
            user_object_classes: ObjectClassList(user_object_classes),
            group_object_classes: ObjectClassList(group_object_classes),
        }
    }

    fn schema(&self) -> &Schema {
        self.base.get_schema()
    }

    pub fn user_object_classes(&self) -> &ObjectClassList {
        &self.user_object_classes
    }

    pub fn group_object_classes(&self) -> &ObjectClassList {
        &self.group_object_classes
    }

    pub fn required_user_attributes(&self) -> AttributeList {
        let attributes = self
            .schema()
            .user_attributes
            .attributes
            .iter()
            .filter(|a| REQUIRED_USER_ATTRIBUTES.contains(&a.name.as_str()))
            .cloned()
            .collect();

        AttributeList { attributes }
    }

    pub fn optional_user_attributes(&self) -> AttributeList {
        let attributes = self
            .schema()
            .user_attributes
            .attributes
            .iter()
            .filter(|a| !REQUIRED_USER_ATTRIBUTES.contains(&a.name.as_str()))
            .cloned()
            .collect();

        AttributeList { attributes }
    }

    pub fn required_group_attributes(&self) -> AttributeList {
        let attributes = self
            .schema()
            .group_attributes
            .attributes
            .iter()
            .filter(|a| REQUIRED_GROUP_ATTRIBUTES.contains(&a.name.as_str()))
            .cloned()
            .collect();

        AttributeList { attributes }
    }

    pub fn optional_group_attributes(&self) -> AttributeList {
        let attributes = self
            .schema()
            .group_attributes
            .attributes
            .iter()
            .filter(|a| !REQUIRED_GROUP_ATTRIBUTES.contains(&a.name.as_str()))
            .cloned()
            .collect();

        AttributeList { attributes }
    }

    // See RFC4512 section 4.2.2 "attributeTypes"
    // Parameter 'index_offset' is an offset for the enumeration of this list of attributes,
    // it has been preceeded by the list of hardcoded attributes.
    pub fn formatted_attribute_list(&self, index_offset: usize) -> Vec<Vec<u8>> {
        let mut formatted_list: Vec<Vec<u8>> = Vec::new();

        for (index, attribute) in self.all_attributes().attributes.into_iter().enumerate() {
            formatted_list.push(
                format!(
                    "( 2.{} NAME '{}' DESC 'LLDAP: {}' SUP {:?} )",
                    (index + index_offset),
                    attribute.name,
                    if attribute.is_hardcoded {
                        "builtin attribute"
                    } else {
                        "custom attribute"
                    },
                    attribute.attribute_type
                )
                .into_bytes()
                .to_vec(),
            )
        }

        formatted_list
    }

    pub fn all_attributes(&self) -> AttributeList {
        let mut combined_attributes = self.schema().user_attributes.attributes.clone();
        combined_attributes.extend_from_slice(&self.schema().group_attributes.attributes);
        AttributeList {
            attributes: combined_attributes,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
}
