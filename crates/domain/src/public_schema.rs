use crate::{
    schema::{AttributeSchema, Schema},
    types::AttributeType,
};
use serde::{Deserialize, Serialize};

/// Attribute names that never leave the server, on any interface.
pub const PRIVATE_ATTRIBUTE_NAMES: &[&str] = &["totp_secret"];

#[derive(PartialEq, Eq, Debug, Serialize, Deserialize, Clone)]
pub struct PublicSchema(Schema);

impl PublicSchema {
    pub fn get_schema(&self) -> &Schema {
        &self.0
    }
}

impl From<Schema> for PublicSchema {
    fn from(mut schema: Schema) -> Self {
        schema.user_attributes.attributes.extend_from_slice(&[
            AttributeSchema {
                name: "user_id".into(),
                attribute_type: AttributeType::String,
                is_list: false,
                is_visible: true,
                is_editable: false,
                is_hardcoded: true,
                is_readonly: true,
            },
            AttributeSchema {
                name: "creation_date".into(),
                attribute_type: AttributeType::DateTime,
                is_list: false,
                is_visible: true,
                is_editable: false,
                is_hardcoded: true,
                is_readonly: true,
            },
            AttributeSchema {
                name: "modified_date".into(),
                attribute_type: AttributeType::DateTime,
                is_list: false,
                is_visible: true,
                is_editable: false,
                is_hardcoded: true,
                is_readonly: true,
            },
            AttributeSchema {
                name: "password_modified_date".into(),
                attribute_type: AttributeType::DateTime,
                is_list: false,
                is_visible: true,
                is_editable: false,
                is_hardcoded: true,
                is_readonly: true,
            },
            AttributeSchema {
                name: "mail".into(),
                attribute_type: AttributeType::String,
                is_list: false,
                is_visible: true,
                is_editable: true,
                is_hardcoded: true,
                is_readonly: false,
            },
            AttributeSchema {
                name: "uuid".into(),
                attribute_type: AttributeType::String,
                is_list: false,
                is_visible: true,
                is_editable: false,
                is_hardcoded: true,
                is_readonly: true,
            },
            AttributeSchema {
                name: "display_name".into(),
                attribute_type: AttributeType::String,
                is_list: false,
                is_visible: true,
                is_editable: true,
                is_hardcoded: true,
                is_readonly: false,
            },
            // TOTP MFA (columns pre-exist in the users table).
            AttributeSchema {
                name: "totp_secret".into(),
                attribute_type: AttributeType::String,
                is_list: false,
                is_visible: false,
                is_editable: false,
                is_hardcoded: true,
                is_readonly: true,
            },
            AttributeSchema {
                name: "mfa_type".into(),
                attribute_type: AttributeType::String,
                is_list: false,
                is_visible: true,
                is_editable: false,
                is_hardcoded: true,
                is_readonly: true,
            },
        ]);
        schema
            .user_attributes
            .attributes
            .retain(|a| !PRIVATE_ATTRIBUTE_NAMES.contains(&a.name.as_str()));
        schema
            .user_attributes
            .attributes
            .sort_by(|a, b| a.name.cmp(&b.name));
        schema.group_attributes.attributes.extend_from_slice(&[
            AttributeSchema {
                name: "group_id".into(),
                attribute_type: AttributeType::Integer,
                is_list: false,
                is_visible: true,
                is_editable: false,
                is_hardcoded: true,
                is_readonly: true,
            },
            AttributeSchema {
                name: "creation_date".into(),
                attribute_type: AttributeType::DateTime,
                is_list: false,
                is_visible: true,
                is_editable: false,
                is_hardcoded: true,
                is_readonly: true,
            },
            AttributeSchema {
                name: "modified_date".into(),
                attribute_type: AttributeType::DateTime,
                is_list: false,
                is_visible: true,
                is_editable: false,
                is_hardcoded: true,
                is_readonly: true,
            },
            AttributeSchema {
                name: "uuid".into(),
                attribute_type: AttributeType::String,
                is_list: false,
                is_visible: true,
                is_editable: false,
                is_hardcoded: true,
                is_readonly: true,
            },
            AttributeSchema {
                name: "display_name".into(),
                attribute_type: AttributeType::String,
                is_list: false,
                is_visible: true,
                is_editable: true,
                is_hardcoded: true,
                is_readonly: false,
            },
        ]);
        schema
            .group_attributes
            .attributes
            .sort_by(|a, b| a.name.cmp(&b.name));
        PublicSchema(schema)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::schema::{AttributeList, Schema};
    use pretty_assertions::assert_eq;

    fn empty_schema() -> Schema {
        Schema {
            user_attributes: AttributeList {
                attributes: Vec::new(),
            },
            group_attributes: AttributeList {
                attributes: Vec::new(),
            },
            extra_user_object_classes: Vec::new(),
            extra_group_object_classes: Vec::new(),
        }
    }

    #[test]
    fn hardcoded_mfa_attributes() {
        let public = PublicSchema::from(empty_schema());
        let attrs = &public.get_schema().user_attributes.attributes;

        // Private attributes are stripped from every derived surface.
        assert!(!attrs.iter().any(|a| a.name == "totp_secret".into()));

        let mfa = attrs.iter().find(|a| a.name == "mfa_type".into()).unwrap();
        assert_eq!(mfa.attribute_type, AttributeType::String);
        assert!(!mfa.is_list);
        assert!(mfa.is_visible);
        assert!(!mfa.is_editable);
        assert!(mfa.is_hardcoded);
        assert!(mfa.is_readonly);
    }
}
