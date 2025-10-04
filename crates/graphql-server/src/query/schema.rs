use juniper::graphql_object;
use lldap_domain::public_schema::PublicSchema;
use lldap_domain::schema::AttributeList as DomainAttributeList;
use lldap_domain::types::LdapObjectClass;
use lldap_domain_handlers::handler::BackendHandler;
use lldap_ldap::{get_default_group_object_classes, get_default_user_object_classes};
use serde::{Deserialize, Serialize};

use crate::api::Context;
use super::attribute::AttributeSchema;

#[derive(PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct AttributeList<Handler: BackendHandler> {
    attributes: DomainAttributeList,
    default_classes: Vec<LdapObjectClass>,
    extra_classes: Vec<LdapObjectClass>,
    _phantom: std::marker::PhantomData<Box<Handler>>,
}

#[derive(Clone)]
pub struct ObjectClassInfo {
    object_class: String,
    is_hardcoded: bool,
}

#[graphql_object]
impl ObjectClassInfo {
    fn object_class(&self) -> &str {
        &self.object_class
    }

    fn is_hardcoded(&self) -> bool {
        self.is_hardcoded
    }
}

#[graphql_object(context = Context<Handler>)]
impl<Handler: BackendHandler> AttributeList<Handler> {
    fn attributes(&self) -> Vec<AttributeSchema<Handler>> {
        self.attributes
            .attributes
            .clone()
            .into_iter()
            .map(Into::into)
            .collect()
    }

    fn extra_ldap_object_classes(&self) -> Vec<String> {
        self.extra_classes.iter().map(|c| c.to_string()).collect()
    }

    fn ldap_object_classes(&self) -> Vec<ObjectClassInfo> {
        let mut all_object_classes: Vec<ObjectClassInfo> = self
            .default_classes
            .iter()
            .map(|c| ObjectClassInfo {
                object_class: c.to_string(),
                is_hardcoded: true,
            })
            .collect();

        all_object_classes.extend(self.extra_classes.iter().map(|c| ObjectClassInfo {
            object_class: c.to_string(),
            is_hardcoded: false,
        }));

        all_object_classes
    }
}

impl<Handler: BackendHandler> AttributeList<Handler> {
    pub fn new(
        attributes: DomainAttributeList,
        default_classes: Vec<LdapObjectClass>,
        extra_classes: Vec<LdapObjectClass>,
    ) -> Self {
        Self {
            attributes,
            default_classes,
            extra_classes,
            _phantom: std::marker::PhantomData,
        }
    }
}

#[derive(PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct Schema<Handler: BackendHandler> {
    schema: PublicSchema,
    _phantom: std::marker::PhantomData<Box<Handler>>,
}

#[graphql_object(context = Context<Handler>)]
impl<Handler: BackendHandler> Schema<Handler> {
    fn user_schema(&self) -> AttributeList<Handler> {
        AttributeList::<Handler>::new(
            self.schema.get_schema().user_attributes.clone(),
            get_default_user_object_classes(),
            self.schema.get_schema().extra_user_object_classes.clone(),
        )
    }
    fn group_schema(&self) -> AttributeList<Handler> {
        AttributeList::<Handler>::new(
            self.schema.get_schema().group_attributes.clone(),
            get_default_group_object_classes(),
            self.schema.get_schema().extra_group_object_classes.clone(),
        )
    }
}

impl<Handler: BackendHandler> From<PublicSchema> for Schema<Handler> {
    fn from(value: PublicSchema) -> Self {
        Self {
            schema: value,
            _phantom: std::marker::PhantomData,
        }
    }
}
