use chrono::TimeZone;
use juniper::{FieldResult, graphql_object};
use lldap_domain::public_schema::PublicSchema;
use lldap_domain::schema::AttributeList as DomainAttributeList;
use lldap_domain::schema::AttributeSchema as DomainAttributeSchema;
use lldap_domain::types::{Attribute as DomainAttribute, AttributeValue as DomainAttributeValue};
use lldap_domain::types::{Cardinality, Group as DomainGroup, GroupDetails, User as DomainUser};
use lldap_domain_handlers::handler::BackendHandler;
use serde::{Deserialize, Serialize};

use crate::api::Context;

#[derive(PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct AttributeSchema<Handler: BackendHandler> {
    schema: DomainAttributeSchema,
    _phantom: std::marker::PhantomData<Box<Handler>>,
}

#[graphql_object(context = Context<Handler>)]
impl<Handler: BackendHandler> AttributeSchema<Handler> {
    fn name(&self) -> String {
        self.schema.name.to_string()
    }
    fn attribute_type(&self) -> lldap_domain::types::AttributeType {
        self.schema.attribute_type
    }
    fn is_list(&self) -> bool {
        self.schema.is_list
    }
    fn is_visible(&self) -> bool {
        self.schema.is_visible
    }
    fn is_editable(&self) -> bool {
        self.schema.is_editable
    }
    fn is_hardcoded(&self) -> bool {
        self.schema.is_hardcoded
    }
    fn is_readonly(&self) -> bool {
        self.schema.is_readonly
    }
}

impl<Handler: BackendHandler> Clone for AttributeSchema<Handler> {
    fn clone(&self) -> Self {
        Self {
            schema: self.schema.clone(),
            _phantom: std::marker::PhantomData,
        }
    }
}

impl<Handler: BackendHandler> From<DomainAttributeSchema> for AttributeSchema<Handler> {
    fn from(value: DomainAttributeSchema) -> Self {
        Self {
            schema: value,
            _phantom: std::marker::PhantomData,
        }
    }
}

#[derive(PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct AttributeValue<Handler: BackendHandler> {
    pub(super) attribute: DomainAttribute,
    pub(super) schema: AttributeSchema<Handler>,
    _phantom: std::marker::PhantomData<Box<Handler>>,
}

#[graphql_object(context = Context<Handler>)]
impl<Handler: BackendHandler> AttributeValue<Handler> {
    fn name(&self) -> &str {
        self.attribute.name.as_str()
    }

    fn value(&self) -> FieldResult<Vec<String>> {
        Ok(serialize_attribute_to_graphql(&self.attribute.value))
    }

    fn schema(&self) -> &AttributeSchema<Handler> {
        &self.schema
    }
}

impl<Handler: BackendHandler> AttributeValue<Handler> {
    fn from_value(attr: DomainAttribute, schema: DomainAttributeSchema) -> Self {
        Self {
            attribute: attr,
            schema: AttributeSchema::<Handler> {
                schema,
                _phantom: std::marker::PhantomData,
            },
            _phantom: std::marker::PhantomData,
        }
    }

    pub(super) fn name(&self) -> &str {
        self.attribute.name.as_str()
    }
}

impl<Handler: BackendHandler> Clone for AttributeValue<Handler> {
    fn clone(&self) -> Self {
        Self {
            attribute: self.attribute.clone(),
            schema: self.schema.clone(),
            _phantom: std::marker::PhantomData,
        }
    }
}

pub fn serialize_attribute_to_graphql(attribute_value: &DomainAttributeValue) -> Vec<String> {
    let convert_date = |&date| chrono::Utc.from_utc_datetime(&date).to_rfc3339();
    match attribute_value {
        DomainAttributeValue::String(Cardinality::Singleton(s)) => vec![s.clone()],
        DomainAttributeValue::String(Cardinality::Unbounded(l)) => l.clone(),
        DomainAttributeValue::Integer(Cardinality::Singleton(i)) => vec![i.to_string()],
        DomainAttributeValue::Integer(Cardinality::Unbounded(l)) => {
            l.iter().map(|i| i.to_string()).collect()
        }
        DomainAttributeValue::DateTime(Cardinality::Singleton(dt)) => vec![convert_date(dt)],
        DomainAttributeValue::DateTime(Cardinality::Unbounded(l)) => {
            l.iter().map(convert_date).collect()
        }
        DomainAttributeValue::JpegPhoto(Cardinality::Singleton(p)) => vec![String::from(p)],
        DomainAttributeValue::JpegPhoto(Cardinality::Unbounded(l)) => {
            l.iter().map(String::from).collect()
        }
    }
}

impl<Handler: BackendHandler> AttributeValue<Handler> {
    fn from_schema(a: DomainAttribute, schema: &DomainAttributeList) -> Option<Self> {
        schema
            .get_attribute_schema(&a.name)
            .map(|s| AttributeValue::<Handler>::from_value(a, s.clone()))
    }

    pub fn user_attributes_from_schema(
        user: &mut DomainUser,
        schema: &PublicSchema,
    ) -> Vec<AttributeValue<Handler>> {
        let user_attributes = std::mem::take(&mut user.attributes);
        let mut all_attributes = schema
            .get_schema()
            .user_attributes
            .attributes
            .iter()
            .filter(|a| a.is_hardcoded)
            .flat_map(|attribute_schema| {
                let value: Option<DomainAttributeValue> = match attribute_schema.name.as_str() {
                    "user_id" => Some(user.user_id.clone().into_string().into()),
                    "creation_date" => Some(user.creation_date.into()),
                    "modified_date" => Some(user.modified_date.into()),
                    "password_modified_date" => Some(user.password_modified_date.into()),
                    "mail" => Some(user.email.clone().into_string().into()),
                    "uuid" => Some(user.uuid.clone().into_string().into()),
                    "display_name" => user.display_name.as_ref().map(|d| d.clone().into()),
                    "avatar" | "first_name" | "last_name" => None,
                    _ => panic!("Unexpected hardcoded attribute: {}", attribute_schema.name),
                };
                value.map(|v| (attribute_schema, v))
            })
            .map(|(attribute_schema, value)| {
                AttributeValue::<Handler>::from_value(
                    DomainAttribute {
                        name: attribute_schema.name.clone(),
                        value,
                    },
                    attribute_schema.clone(),
                )
            })
            .collect::<Vec<_>>();
        user_attributes
            .into_iter()
            .flat_map(|a| {
                AttributeValue::<Handler>::from_schema(a, &schema.get_schema().user_attributes)
            })
            .for_each(|value| all_attributes.push(value));
        all_attributes
    }

    pub fn group_attributes_from_schema(
        group: &mut DomainGroup,
        schema: &PublicSchema,
    ) -> Vec<AttributeValue<Handler>> {
        let group_attributes = std::mem::take(&mut group.attributes);
        let mut all_attributes = schema
            .get_schema()
            .group_attributes
            .attributes
            .iter()
            .filter(|a| a.is_hardcoded)
            .map(|attribute_schema| {
                (
                    attribute_schema,
                    match attribute_schema.name.as_str() {
                        "group_id" => (group.id.0 as i64).into(),
                        "creation_date" => group.creation_date.into(),
                        "modified_date" => group.modified_date.into(),
                        "uuid" => group.uuid.clone().into_string().into(),
                        "display_name" => group.display_name.clone().into_string().into(),
                        _ => panic!("Unexpected hardcoded attribute: {}", attribute_schema.name),
                    },
                )
            })
            .map(|(attribute_schema, value)| {
                AttributeValue::<Handler>::from_value(
                    DomainAttribute {
                        name: attribute_schema.name.clone(),
                        value,
                    },
                    attribute_schema.clone(),
                )
            })
            .collect::<Vec<_>>();
        group_attributes
            .into_iter()
            .flat_map(|a| {
                AttributeValue::<Handler>::from_schema(a, &schema.get_schema().group_attributes)
            })
            .for_each(|value| all_attributes.push(value));
        all_attributes
    }

    pub fn group_details_attributes_from_schema(
        group: &mut GroupDetails,
        schema: &PublicSchema,
    ) -> Vec<AttributeValue<Handler>> {
        let group_attributes = std::mem::take(&mut group.attributes);
        let mut all_attributes = schema
            .get_schema()
            .group_attributes
            .attributes
            .iter()
            .filter(|a| a.is_hardcoded)
            .map(|attribute_schema| {
                (
                    attribute_schema,
                    match attribute_schema.name.as_str() {
                        "group_id" => (group.group_id.0 as i64).into(),
                        "creation_date" => group.creation_date.into(),
                        "modified_date" => group.modified_date.into(),
                        "uuid" => group.uuid.clone().into_string().into(),
                        "display_name" => group.display_name.clone().into_string().into(),
                        _ => panic!("Unexpected hardcoded attribute: {}", attribute_schema.name),
                    },
                )
            })
            .map(|(attribute_schema, value)| {
                AttributeValue::<Handler>::from_value(
                    DomainAttribute {
                        name: attribute_schema.name.clone(),
                        value,
                    },
                    attribute_schema.clone(),
                )
            })
            .collect::<Vec<_>>();
        group_attributes
            .into_iter()
            .flat_map(|a| {
                AttributeValue::<Handler>::from_schema(a, &schema.get_schema().group_attributes)
            })
            .for_each(|value| all_attributes.push(value));
        all_attributes
    }
}
