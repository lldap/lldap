use juniper::{FieldResult, GraphQLInputObject};
use lldap_domain::public_schema::PublicSchema;
use lldap_domain::types::GroupId;
use lldap_domain_handlers::handler::UserRequestFilter as DomainRequestFilter;
use lldap_domain_model::model::UserColumn;
use lldap_domain::deserialize::deserialize_attribute_value;
use lldap_domain::types::UserId;
use lldap_ldap::{UserFieldType, map_user_field};
use anyhow::Context as AnyhowContext;

#[derive(PartialEq, Eq, Debug, GraphQLInputObject)]
/// A filter for requests, specifying a boolean expression based on field constraints. Only one of
/// the fields can be set at a time.
pub struct RequestFilter {
    any: Option<Vec<RequestFilter>>,
    all: Option<Vec<RequestFilter>>,
    not: Option<Box<RequestFilter>>,
    eq: Option<EqualityConstraint>,
    member_of: Option<String>,
    member_of_id: Option<i32>,
}

impl RequestFilter {
    pub fn try_into_domain_filter(self, schema: &PublicSchema) -> FieldResult<DomainRequestFilter> {
        match (
            self.eq,
            self.any,
            self.all,
            self.not,
            self.member_of,
            self.member_of_id,
        ) {
            (Some(eq), None, None, None, None, None) => {
                match map_user_field(&eq.field.as_str().into(), schema) {
                    UserFieldType::NoMatch => {
                        Err(format!("Unknown request filter: {}", &eq.field).into())
                    }
                    UserFieldType::PrimaryField(UserColumn::UserId) => {
                        Ok(DomainRequestFilter::UserId(UserId::new(&eq.value)))
                    }
                    UserFieldType::PrimaryField(column) => {
                        Ok(DomainRequestFilter::Equality(column, eq.value))
                    }
                    UserFieldType::Attribute(name, typ, false) => {
                        let value = deserialize_attribute_value(&[eq.value], typ, false)
                            .context(format!("While deserializing attribute {}", &name))?;
                        Ok(DomainRequestFilter::AttributeEquality(name, value))
                    }
                    UserFieldType::Attribute(_, _, true) => {
                        Err("Equality not supported for list fields".into())
                    }
                    UserFieldType::MemberOf => Ok(DomainRequestFilter::MemberOf(eq.value.into())),
                    UserFieldType::ObjectClass | UserFieldType::Dn | UserFieldType::EntryDn => {
                        Err("Ldap fields not supported in request filter".into())
                    }
                }
            }
            (None, Some(any), None, None, None, None) => Ok(DomainRequestFilter::Or(
                any.into_iter()
                    .map(|f| f.try_into_domain_filter(schema))
                    .collect::<FieldResult<Vec<_>>>()?,
            )),
            (None, None, Some(all), None, None, None) => Ok(DomainRequestFilter::And(
                all.into_iter()
                    .map(|f| f.try_into_domain_filter(schema))
                    .collect::<FieldResult<Vec<_>>>()?,
            )),
            (None, None, None, Some(not), None, None) => Ok(DomainRequestFilter::Not(Box::new(
                (*not).try_into_domain_filter(schema)?,
            ))),
            (None, None, None, None, Some(group), None) => {
                Ok(DomainRequestFilter::MemberOf(group.into()))
            }
            (None, None, None, None, None, Some(group_id)) => {
                Ok(DomainRequestFilter::MemberOfId(GroupId(group_id)))
            }
            (None, None, None, None, None, None) => {
                Err("No field specified in request filter".into())
            }
            _ => Err("Multiple fields specified in request filter".into()),
        }
    }
}

#[derive(PartialEq, Eq, Debug, GraphQLInputObject)]
pub struct EqualityConstraint {
    field: String,
    value: String,
}
