use crate::domain::{
    handler::{AttributeSchema, Schema},
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

impl From<Schema> for PublicSchema {
    fn from(mut schema: Schema) -> Self {
        schema.user_attributes.attributes.extend_from_slice(&[
            AttributeSchema {
                name: "user_id".to_owned(),
                attribute_type: AttributeType::String,
                is_list: false,
                is_visible: true,
                is_editable: false,
                is_hardcoded: true,
            },
            AttributeSchema {
                name: "creation_date".to_owned(),
                attribute_type: AttributeType::DateTime,
                is_list: false,
                is_visible: true,
                is_editable: false,
                is_hardcoded: true,
            },
            AttributeSchema {
                name: "mail".to_owned(),
                attribute_type: AttributeType::String,
                is_list: false,
                is_visible: true,
                is_editable: true,
                is_hardcoded: true,
            },
            AttributeSchema {
                name: "uuid".to_owned(),
                attribute_type: AttributeType::String,
                is_list: false,
                is_visible: true,
                is_editable: false,
                is_hardcoded: true,
            },
            AttributeSchema {
                name: "display_name".to_owned(),
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
                name: "group_id".to_owned(),
                attribute_type: AttributeType::Integer,
                is_list: false,
                is_visible: true,
                is_editable: false,
                is_hardcoded: true,
            },
            AttributeSchema {
                name: "creation_date".to_owned(),
                attribute_type: AttributeType::DateTime,
                is_list: false,
                is_visible: true,
                is_editable: false,
                is_hardcoded: true,
            },
            AttributeSchema {
                name: "uuid".to_owned(),
                attribute_type: AttributeType::String,
                is_list: false,
                is_visible: true,
                is_editable: false,
                is_hardcoded: true,
            },
            AttributeSchema {
                name: "display_name".to_owned(),
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
