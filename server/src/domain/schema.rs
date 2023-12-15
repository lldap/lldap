use crate::domain::{
    handler::{AttributeList, AttributeSchema, Schema},
    types::AttributeType,
};
use serde::{Deserialize, Serialize};

#[derive(PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct PublicSchema(Schema);

impl PublicSchema {
    pub fn get_schema(&self) -> &Schema {
        &self.0
    }
}

pub trait SchemaAttributeExtractor: std::marker::Send {
    fn get_attributes(schema: &PublicSchema) -> &AttributeList;
}

pub struct SchemaUserAttributeExtractor;

impl SchemaAttributeExtractor for SchemaUserAttributeExtractor {
    fn get_attributes(schema: &PublicSchema) -> &AttributeList {
        &schema.get_schema().user_attributes
    }
}

pub struct SchemaGroupAttributeExtractor;

impl SchemaAttributeExtractor for SchemaGroupAttributeExtractor {
    fn get_attributes(schema: &PublicSchema) -> &AttributeList {
        &schema.get_schema().group_attributes
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
            },
            AttributeSchema {
                name: "creation_date".into(),
                attribute_type: AttributeType::DateTime,
                is_list: false,
                is_visible: true,
                is_editable: false,
                is_hardcoded: true,
            },
            AttributeSchema {
                name: "mail".into(),
                attribute_type: AttributeType::String,
                is_list: false,
                is_visible: true,
                is_editable: true,
                is_hardcoded: true,
            },
            AttributeSchema {
                name: "uuid".into(),
                attribute_type: AttributeType::String,
                is_list: false,
                is_visible: true,
                is_editable: false,
                is_hardcoded: true,
            },
            AttributeSchema {
                name: "display_name".into(),
                attribute_type: AttributeType::String,
                is_list: false,
                is_visible: true,
                is_editable: true,
                is_hardcoded: true,
            },
        ]);
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
            },
            AttributeSchema {
                name: "creation_date".into(),
                attribute_type: AttributeType::DateTime,
                is_list: false,
                is_visible: true,
                is_editable: false,
                is_hardcoded: true,
            },
            AttributeSchema {
                name: "uuid".into(),
                attribute_type: AttributeType::String,
                is_list: false,
                is_visible: true,
                is_editable: false,
                is_hardcoded: true,
            },
            AttributeSchema {
                name: "display_name".into(),
                attribute_type: AttributeType::String,
                is_list: false,
                is_visible: true,
                is_editable: true,
                is_hardcoded: true,
            },
        ]);
        schema
            .group_attributes
            .attributes
            .sort_by(|a, b| a.name.cmp(&b.name));
        PublicSchema(schema)
    }
}
