use mlua::{Error, Result as LuaResult, Table};
use std::str::FromStr;

use lldap_domain::{requests::CreateAttributeRequest, types::AttributeType};

#[derive(PartialEq, Eq, Debug, Clone)]
pub struct CreateAttributeParams {
    pub name: String,
    pub attribute_type: AttributeType,
    pub is_list: bool,
    pub is_visible: bool,
    pub is_editable: bool,
}

impl CreateAttributeParams {
    pub fn from(args: &Table) -> LuaResult<Self> {
        Ok(CreateAttributeParams {
            name: args.get("name")?,
            attribute_type: AttributeType::from_str(args.get::<String>("attribute_type")?.as_str())
                .map_err(|_| Error::FromLuaConversionError {
                    from: "<attribute-type>",
                    to: "AttributeType".to_string(),
                    message: Some("Unable to deserialize to AttributeType".to_string()),
                })?,
            is_list: args.get("is_list")?,
            is_visible: args.get("is_visible")?,
            is_editable: args.get("is_editable")?,
        })
    }
}

impl Into<CreateAttributeRequest> for CreateAttributeParams {
    fn into(self) -> CreateAttributeRequest {
        CreateAttributeRequest {
            name: self.name.into(),
            attribute_type: self.attribute_type,
            is_list: self.is_list,
            is_visible: self.is_visible,
            is_editable: self.is_editable,
        }
    }
}
