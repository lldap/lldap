use anyhow::{Context as AnyhowContext, anyhow};
use juniper::FieldResult;
use lldap_access_control::{AdminBackendHandler, ReadonlyBackendHandler};
use lldap_domain::{
    deserialize::deserialize_attribute_value,
    public_schema::PublicSchema,
    requests::CreateGroupRequest,
    schema::AttributeList,
    types::{Attribute as DomainAttribute, AttributeName, Email},
};
use lldap_domain_handlers::handler::{BackendHandler, ReadSchemaBackendHandler};
use std::{collections::BTreeMap, sync::Arc};
use tracing::{Instrument, Span};

use super::inputs::AttributeValue;
use crate::api::{Context, field_error_callback};

pub struct UnpackedAttributes {
    pub email: Option<Email>,
    pub display_name: Option<String>,
    pub attributes: Vec<DomainAttribute>,
}

pub fn unpack_attributes(
    attributes: Vec<AttributeValue>,
    schema: &PublicSchema,
    is_admin: bool,
) -> FieldResult<UnpackedAttributes> {
    let email = attributes
        .iter()
        .find(|attr| attr.name == "mail")
        .cloned()
        .map(|attr| deserialize_attribute(&schema.get_schema().user_attributes, attr, is_admin))
        .transpose()?
        .map(|attr| attr.value.into_string().unwrap())
        .map(Email::from);
    let display_name = attributes
        .iter()
        .find(|attr| attr.name == "display_name")
        .cloned()
        .map(|attr| deserialize_attribute(&schema.get_schema().user_attributes, attr, is_admin))
        .transpose()?
        .map(|attr| attr.value.into_string().unwrap());
    let attributes = attributes
        .into_iter()
        .filter(|attr| attr.name != "mail" && attr.name != "display_name")
        .map(|attr| deserialize_attribute(&schema.get_schema().user_attributes, attr, is_admin))
        .collect::<Result<Vec<_>, _>>()?;
    Ok(UnpackedAttributes {
        email,
        display_name,
        attributes,
    })
}

/// Consolidates caller supplied user fields and attributes into a list of attributes.
///
/// A number of user fields are internally represented as attributes, but are still also
/// available as fields on user objects. This function consolidates these fields and the
/// given attributes into a resulting attribute list. If a value is supplied for both a
/// field and the corresponding attribute, the attribute will take precedence.
pub fn consolidate_attributes(
    attributes: Vec<AttributeValue>,
    first_name: Option<String>,
    last_name: Option<String>,
    avatar: Option<String>,
) -> Vec<AttributeValue> {
    // Prepare map of the client provided attributes
    let mut provided_attributes: BTreeMap<AttributeName, AttributeValue> = attributes
        .into_iter()
        .map(|x| {
            (
                x.name.clone().into(),
                AttributeValue {
                    name: x.name.to_ascii_lowercase(),
                    value: x.value,
                },
            )
        })
        .collect::<BTreeMap<_, _>>();
    // Prepare list of fallback attribute values
    let field_attrs = [
        ("first_name", first_name),
        ("last_name", last_name),
        ("avatar", avatar),
    ];
    for (name, value) in field_attrs.into_iter() {
        if let Some(val) = value {
            let attr_name: AttributeName = name.into();
            provided_attributes
                .entry(attr_name)
                .or_insert_with(|| AttributeValue {
                    name: name.to_string(),
                    value: vec![val],
                });
        }
    }
    // Return the values of the resulting map
    provided_attributes.into_values().collect()
}

pub async fn create_group_with_details<Handler: BackendHandler>(
    context: &Context<Handler>,
    request: super::inputs::CreateGroupInput,
    span: Span,
) -> FieldResult<crate::query::Group<Handler>> {
    let handler = context
        .get_admin_handler()
        .ok_or_else(field_error_callback(&span, "Unauthorized group creation"))?;
    let schema = handler.get_schema().await?;
    let public_schema: PublicSchema = schema.into();
    let attributes = request
        .attributes
        .unwrap_or_default()
        .into_iter()
        .map(|attr| deserialize_attribute(&public_schema.get_schema().group_attributes, attr, true))
        .collect::<Result<Vec<_>, _>>()?;
    let request = CreateGroupRequest {
        display_name: request.display_name.into(),
        attributes,
    };
    let group_id = handler.create_group(request).await?;
    let group_details = handler.get_group_details(group_id).instrument(span).await?;
    crate::query::Group::<Handler>::from_group_details(group_details, Arc::new(public_schema))
}

pub fn deserialize_attribute(
    attribute_schema: &AttributeList,
    attribute: AttributeValue,
    is_admin: bool,
) -> FieldResult<DomainAttribute> {
    let attribute_name = AttributeName::from(attribute.name.as_str());
    let attribute_schema = attribute_schema
        .get_attribute_schema(&attribute_name)
        .ok_or_else(|| anyhow!("Attribute {} is not defined in the schema", attribute.name))?;
    if attribute_schema.is_readonly {
        return Err(anyhow!(
            "Permission denied: Attribute {} is read-only",
            attribute.name
        )
        .into());
    }
    if !is_admin && !attribute_schema.is_editable {
        return Err(anyhow!(
            "Permission denied: Attribute {} is not editable by regular users",
            attribute.name
        )
        .into());
    }
    let deserialized_values = deserialize_attribute_value(
        &attribute.value,
        attribute_schema.attribute_type,
        attribute_schema.is_list,
    )
    .context(format!("While deserializing attribute {}", attribute.name))?;
    Ok(DomainAttribute {
        name: attribute_name,
        value: deserialized_values,
    })
}
