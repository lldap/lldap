use std::sync::Arc;

use crate::{
    domain::{
        deserialize::deserialize_attribute_value,
        ldap::{
            group::get_default_group_object_classes,
            user::get_default_user_object_classes,
            utils::{map_user_field, UserFieldType},
        },
        schema::PublicSchema,
    },
    infra::{
        access_control::{ReadonlyBackendHandler, UserReadableBackendHandler},
        graphql::api::{field_error_callback, Context},
    },
};
use anyhow::Context as AnyhowContext;
use chrono::TimeZone;
use juniper::{graphql_object, FieldResult, GraphQLInputObject};
use lldap_domain::types::{
    AttributeType, Cardinality, GroupDetails, GroupId, LdapObjectClass, UserId,
};
use lldap_domain_handlers::handler::{BackendHandler, ReadSchemaBackendHandler};
use lldap_domain_model::model::UserColumn;
use serde::{Deserialize, Serialize};
use tracing::{debug, debug_span, Instrument, Span};

type DomainRequestFilter = lldap_domain_handlers::handler::UserRequestFilter;
type DomainUser = lldap_domain::types::User;
type DomainGroup = lldap_domain::types::Group;
type DomainUserAndGroups = lldap_domain::types::UserAndGroups;
type DomainAttributeList = lldap_domain::schema::AttributeList;
type DomainAttributeSchema = lldap_domain::schema::AttributeSchema;
type DomainAttribute = lldap_domain::types::Attribute;
type DomainAttributeValue = lldap_domain::types::AttributeValue;

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
    fn try_into_domain_filter(self, schema: &PublicSchema) -> FieldResult<DomainRequestFilter> {
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

#[derive(PartialEq, Eq, Debug)]
/// The top-level GraphQL query type.
pub struct Query<Handler: BackendHandler> {
    _phantom: std::marker::PhantomData<Box<Handler>>,
}

impl<Handler: BackendHandler> Query<Handler> {
    pub fn new() -> Self {
        Self {
            _phantom: std::marker::PhantomData,
        }
    }
}

#[graphql_object(context = Context<Handler>)]
impl<Handler: BackendHandler> Query<Handler> {
    fn api_version() -> &'static str {
        "1.0"
    }

    pub async fn user(context: &Context<Handler>, user_id: String) -> FieldResult<User<Handler>> {
        use anyhow::Context;
        let span = debug_span!("[GraphQL query] user");
        span.in_scope(|| {
            debug!(?user_id);
        });
        let user_id = urlencoding::decode(&user_id).context("Invalid user parameter")?;
        let user_id = UserId::new(&user_id);
        let handler = context
            .get_readable_handler(&user_id)
            .ok_or_else(field_error_callback(
                &span,
                "Unauthorized access to user data",
            ))?;
        let schema = Arc::new(self.get_schema(context, span.clone()).await?);
        let user = handler.get_user_details(&user_id).instrument(span).await?;
        User::<Handler>::from_user(user, schema)
    }

    async fn users(
        context: &Context<Handler>,
        #[graphql(name = "where")] filters: Option<RequestFilter>,
    ) -> FieldResult<Vec<User<Handler>>> {
        let span = debug_span!("[GraphQL query] users");
        span.in_scope(|| {
            debug!(?filters);
        });
        let handler = context
            .get_readonly_handler()
            .ok_or_else(field_error_callback(
                &span,
                "Unauthorized access to user list",
            ))?;
        let schema = Arc::new(self.get_schema(context, span.clone()).await?);
        let users = handler
            .list_users(
                filters
                    .map(|f| f.try_into_domain_filter(&schema))
                    .transpose()?,
                false,
            )
            .instrument(span)
            .await?;
        users
            .into_iter()
            .map(|u| User::<Handler>::from_user_and_groups(u, schema.clone()))
            .collect()
    }

    async fn groups(context: &Context<Handler>) -> FieldResult<Vec<Group<Handler>>> {
        let span = debug_span!("[GraphQL query] groups");
        let handler = context
            .get_readonly_handler()
            .ok_or_else(field_error_callback(
                &span,
                "Unauthorized access to group list",
            ))?;
        let schema = Arc::new(self.get_schema(context, span.clone()).await?);
        let domain_groups = handler.list_groups(None).instrument(span).await?;
        domain_groups
            .into_iter()
            .map(|g| Group::<Handler>::from_group(g, schema.clone()))
            .collect()
    }

    async fn group(context: &Context<Handler>, group_id: i32) -> FieldResult<Group<Handler>> {
        let span = debug_span!("[GraphQL query] group");
        span.in_scope(|| {
            debug!(?group_id);
        });
        let handler = context
            .get_readonly_handler()
            .ok_or_else(field_error_callback(
                &span,
                "Unauthorized access to group data",
            ))?;
        let schema = Arc::new(self.get_schema(context, span.clone()).await?);
        let group_details = handler
            .get_group_details(GroupId(group_id))
            .instrument(span)
            .await?;
        Group::<Handler>::from_group_details(group_details, schema.clone())
    }

    async fn schema(context: &Context<Handler>) -> FieldResult<Schema<Handler>> {
        let span = debug_span!("[GraphQL query] get_schema");
        self.get_schema(context, span).await.map(Into::into)
    }
}

impl<Handler: BackendHandler> Query<Handler> {
    async fn get_schema(
        &self,
        context: &Context<Handler>,
        span: Span,
    ) -> FieldResult<PublicSchema> {
        let handler = context
            .handler
            .get_user_restricted_lister_handler(&context.validation_result);
        Ok(handler
            .get_schema()
            .instrument(span)
            .await
            .map(Into::<PublicSchema>::into)?)
    }
}

#[derive(PartialEq, Eq, Debug, Serialize, Deserialize)]
/// Represents a single user.
pub struct User<Handler: BackendHandler> {
    user: DomainUser,
    attributes: Vec<AttributeValue<Handler>>,
    schema: Arc<PublicSchema>,
    groups: Option<Vec<Group<Handler>>>,
    _phantom: std::marker::PhantomData<Box<Handler>>,
}

impl<Handler: BackendHandler> User<Handler> {
    pub fn from_user(mut user: DomainUser, schema: Arc<PublicSchema>) -> FieldResult<Self> {
        let attributes = AttributeValue::<Handler>::user_attributes_from_schema(&mut user, &schema);
        Ok(Self {
            user,
            attributes,
            schema,
            groups: None,
            _phantom: std::marker::PhantomData,
        })
    }
}

impl<Handler: BackendHandler> User<Handler> {
    pub fn from_user_and_groups(
        DomainUserAndGroups { user, groups }: DomainUserAndGroups,
        schema: Arc<PublicSchema>,
    ) -> FieldResult<Self> {
        let mut user = Self::from_user(user, schema.clone())?;
        if let Some(groups) = groups {
            user.groups = Some(
                groups
                    .into_iter()
                    .map(|g| Group::<Handler>::from_group_details(g, schema.clone()))
                    .collect::<FieldResult<Vec<_>>>()?,
            );
        }
        Ok(user)
    }
}

#[graphql_object(context = Context<Handler>)]
impl<Handler: BackendHandler> User<Handler> {
    fn id(&self) -> &str {
        self.user.user_id.as_str()
    }

    fn email(&self) -> &str {
        self.user.email.as_str()
    }

    fn display_name(&self) -> &str {
        self.user.display_name.as_deref().unwrap_or("")
    }

    fn first_name(&self) -> &str {
        self.attributes
            .iter()
            .find(|a| a.attribute.name.as_str() == "first_name")
            .map(|a| a.attribute.value.as_str().unwrap_or_default())
            .unwrap_or_default()
    }

    fn last_name(&self) -> &str {
        self.attributes
            .iter()
            .find(|a| a.attribute.name.as_str() == "last_name")
            .map(|a| a.attribute.value.as_str().unwrap_or_default())
            .unwrap_or_default()
    }

    fn avatar(&self) -> Option<String> {
        self.attributes
            .iter()
            .find(|a| a.attribute.name.as_str() == "avatar")
            .map(|a| {
                String::from(
                    a.attribute
                        .value
                        .as_jpeg_photo()
                        .expect("Invalid JPEG returned by the DB"),
                )
            })
    }

    fn creation_date(&self) -> chrono::DateTime<chrono::Utc> {
        chrono::Utc.from_utc_datetime(&self.user.creation_date)
    }

    fn uuid(&self) -> &str {
        self.user.uuid.as_str()
    }

    /// User-defined attributes.
    fn attributes(&self) -> &[AttributeValue<Handler>] {
        &self.attributes
    }

    /// The groups to which this user belongs.
    async fn groups(&self, context: &Context<Handler>) -> FieldResult<Vec<Group<Handler>>> {
        if let Some(groups) = &self.groups {
            return Ok(groups.clone());
        }
        let span = debug_span!("[GraphQL query] user::groups");
        span.in_scope(|| {
            debug!(user_id = ?self.user.user_id);
        });
        let handler = context
            .get_readable_handler(&self.user.user_id)
            .expect("We shouldn't be able to get there without readable permission");
        let domain_groups = handler
            .get_user_groups(&self.user.user_id)
            .instrument(span)
            .await?;
        let mut groups = domain_groups
            .into_iter()
            .map(|g| Group::<Handler>::from_group_details(g, self.schema.clone()))
            .collect::<FieldResult<Vec<Group<Handler>>>>()?;
        groups.sort_by(|g1, g2| g1.display_name.cmp(&g2.display_name));
        Ok(groups)
    }
}

#[derive(PartialEq, Eq, Debug, Serialize, Deserialize)]
/// Represents a single group.
pub struct Group<Handler: BackendHandler> {
    group_id: i32,
    display_name: String,
    creation_date: chrono::NaiveDateTime,
    uuid: String,
    attributes: Vec<AttributeValue<Handler>>,
    schema: Arc<PublicSchema>,
    _phantom: std::marker::PhantomData<Box<Handler>>,
}

impl<Handler: BackendHandler> Group<Handler> {
    pub fn from_group(
        mut group: DomainGroup,
        schema: Arc<PublicSchema>,
    ) -> FieldResult<Group<Handler>> {
        let attributes =
            AttributeValue::<Handler>::group_attributes_from_schema(&mut group, &schema);
        Ok(Self {
            group_id: group.id.0,
            display_name: group.display_name.to_string(),
            creation_date: group.creation_date,
            uuid: group.uuid.into_string(),
            attributes,
            schema,
            _phantom: std::marker::PhantomData,
        })
    }

    pub fn from_group_details(
        mut group_details: GroupDetails,
        schema: Arc<PublicSchema>,
    ) -> FieldResult<Group<Handler>> {
        let attributes = AttributeValue::<Handler>::group_details_attributes_from_schema(
            &mut group_details,
            &schema,
        );
        Ok(Self {
            group_id: group_details.group_id.0,
            display_name: group_details.display_name.to_string(),
            creation_date: group_details.creation_date,
            uuid: group_details.uuid.into_string(),
            attributes,
            schema,
            _phantom: std::marker::PhantomData,
        })
    }
}

impl<Handler: BackendHandler> Clone for Group<Handler> {
    fn clone(&self) -> Self {
        Self {
            group_id: self.group_id,
            display_name: self.display_name.clone(),
            creation_date: self.creation_date,
            uuid: self.uuid.clone(),
            attributes: self.attributes.clone(),
            schema: self.schema.clone(),
            _phantom: std::marker::PhantomData,
        }
    }
}

#[graphql_object(context = Context<Handler>)]
impl<Handler: BackendHandler> Group<Handler> {
    fn id(&self) -> i32 {
        self.group_id
    }
    fn display_name(&self) -> String {
        self.display_name.clone()
    }
    fn creation_date(&self) -> chrono::DateTime<chrono::Utc> {
        chrono::Utc.from_utc_datetime(&self.creation_date)
    }
    fn uuid(&self) -> String {
        self.uuid.clone()
    }

    /// User-defined attributes.
    fn attributes(&self) -> &[AttributeValue<Handler>] {
        &self.attributes
    }

    /// The groups to which this user belongs.
    async fn users(&self, context: &Context<Handler>) -> FieldResult<Vec<User<Handler>>> {
        let span = debug_span!("[GraphQL query] group::users");
        span.in_scope(|| {
            debug!(name = %self.display_name);
        });
        let handler = context
            .get_readonly_handler()
            .ok_or_else(field_error_callback(
                &span,
                "Unauthorized access to group data",
            ))?;
        let domain_users = handler
            .list_users(
                Some(DomainRequestFilter::MemberOfId(GroupId(self.group_id))),
                false,
            )
            .instrument(span)
            .await?;
        domain_users
            .into_iter()
            .map(|u| User::<Handler>::from_user_and_groups(u, self.schema.clone()))
            .collect()
    }
}

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
    fn attribute_type(&self) -> AttributeType {
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
    fn new(
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

#[derive(PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct AttributeValue<Handler: BackendHandler> {
    attribute: DomainAttribute,
    schema: AttributeSchema<Handler>,
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

    fn user_attributes_from_schema(
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

    fn group_attributes_from_schema(
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

    fn group_details_attributes_from_schema(
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::infra::{
        access_control::{Permission, ValidationResults},
        test_utils::{setup_default_schema, MockTestBackendHandler},
    };
    use chrono::TimeZone;
    use juniper::{
        execute, graphql_value, DefaultScalarValue, EmptyMutation, EmptySubscription, GraphQLType,
        RootNode, Variables,
    };
    use lldap_domain::{
        schema::{AttributeList, Schema},
        types::{AttributeName, AttributeType, LdapObjectClass},
    };
    use mockall::predicate::eq;
    use pretty_assertions::assert_eq;
    use std::collections::HashSet;

    fn schema<'q, C, Q>(query_root: Q) -> RootNode<'q, Q, EmptyMutation<C>, EmptySubscription<C>>
    where
        Q: GraphQLType<DefaultScalarValue, Context = C, TypeInfo = ()> + 'q,
    {
        RootNode::new(
            query_root,
            EmptyMutation::<C>::new(),
            EmptySubscription::<C>::new(),
        )
    }

    #[tokio::test]
    async fn get_user_by_id() {
        const QUERY: &str = r#"{
          user(userId: "bob") {
            id
            email
            creationDate
            firstName
            lastName
            uuid
            attributes {
              name
              value
            }
            groups {
              id
              displayName
              creationDate
              uuid
              attributes {
                name
                value
              }
            }
          }
        }"#;

        let mut mock = MockTestBackendHandler::new();
        mock.expect_get_schema().returning(|| {
            Ok(Schema {
                user_attributes: DomainAttributeList {
                    attributes: vec![
                        DomainAttributeSchema {
                            name: "first_name".into(),
                            attribute_type: AttributeType::String,
                            is_list: false,
                            is_visible: true,
                            is_editable: true,
                            is_hardcoded: true,
                            is_readonly: false,
                        },
                        DomainAttributeSchema {
                            name: "last_name".into(),
                            attribute_type: AttributeType::String,
                            is_list: false,
                            is_visible: true,
                            is_editable: true,
                            is_hardcoded: true,
                            is_readonly: false,
                        },
                    ],
                },
                group_attributes: DomainAttributeList {
                    attributes: vec![DomainAttributeSchema {
                        name: "club_name".into(),
                        attribute_type: AttributeType::String,
                        is_list: false,
                        is_visible: true,
                        is_editable: true,
                        is_hardcoded: false,
                        is_readonly: false,
                    }],
                },
                extra_user_object_classes: vec![
                    LdapObjectClass::from("customUserClass"),
                    LdapObjectClass::from("myUserClass"),
                ],
                extra_group_object_classes: vec![LdapObjectClass::from("customGroupClass")],
            })
        });
        mock.expect_get_user_details()
            .with(eq(UserId::new("bob")))
            .return_once(|_| {
                Ok(DomainUser {
                    user_id: UserId::new("bob"),
                    email: "bob@bobbers.on".into(),
                    creation_date: chrono::Utc.timestamp_millis_opt(42).unwrap().naive_utc(),
                    uuid: lldap_domain::uuid!("b1a2a3a4b1b2c1c2d1d2d3d4d5d6d7d8"),
                    attributes: vec![
                        DomainAttribute {
                            name: "first_name".into(),
                            value: "Bob".to_string().into(),
                        },
                        DomainAttribute {
                            name: "last_name".into(),
                            value: "Bobberson".to_string().into(),
                        },
                    ],
                    ..Default::default()
                })
            });
        let mut groups = HashSet::new();
        groups.insert(GroupDetails {
            group_id: GroupId(3),
            display_name: "Bobbersons".into(),
            creation_date: chrono::Utc.timestamp_nanos(42).naive_utc(),
            uuid: lldap_domain::uuid!("a1a2a3a4b1b2c1c2d1d2d3d4d5d6d7d8"),
            attributes: vec![DomainAttribute {
                name: "club_name".into(),
                value: "Gang of Four".to_string().into(),
            }],
        });
        groups.insert(GroupDetails {
            group_id: GroupId(7),
            display_name: "Jefferees".into(),
            creation_date: chrono::Utc.timestamp_nanos(12).naive_utc(),
            uuid: lldap_domain::uuid!("b1a2a3a4b1b2c1c2d1d2d3d4d5d6d7d8"),
            attributes: Vec::new(),
        });
        mock.expect_get_user_groups()
            .with(eq(UserId::new("bob")))
            .return_once(|_| Ok(groups));

        let context =
            Context::<MockTestBackendHandler>::new_for_tests(mock, ValidationResults::admin());

        let schema = schema(Query::<MockTestBackendHandler>::new());
        assert_eq!(
            Ok((
                graphql_value!(
                {
                    "user": {
                        "id": "bob",
                        "email": "bob@bobbers.on",
                        "creationDate": "1970-01-01T00:00:00.042+00:00",
                        "firstName": "Bob",
                        "lastName": "Bobberson",
                        "uuid": "b1a2a3a4-b1b2-c1c2-d1d2-d3d4d5d6d7d8",
                        "attributes": [{
                            "name": "creation_date",
                            "value": ["1970-01-01T00:00:00.042+00:00"],
                          },
                          {
                            "name": "mail",
                            "value": ["bob@bobbers.on"],
                          },
                          {
                            "name": "user_id",
                            "value": ["bob"],
                          },
                          {
                            "name": "uuid",
                            "value": ["b1a2a3a4-b1b2-c1c2-d1d2-d3d4d5d6d7d8"],
                          },
                          {
                            "name": "first_name",
                            "value": ["Bob"],
                          },
                          {
                            "name": "last_name",
                            "value": ["Bobberson"],
                        }],
                        "groups": [{
                            "id": 3,
                            "displayName": "Bobbersons",
                            "creationDate": "1970-01-01T00:00:00.000000042+00:00",
                            "uuid": "a1a2a3a4-b1b2-c1c2-d1d2-d3d4d5d6d7d8",
                            "attributes": [{
                                "name": "creation_date",
                                "value": ["1970-01-01T00:00:00.000000042+00:00"],
                              },
                              {
                                "name": "display_name",
                                "value": ["Bobbersons"],
                              },
                              {
                                "name": "group_id",
                                "value": ["3"],
                              },
                              {
                                "name": "uuid",
                                "value": ["a1a2a3a4-b1b2-c1c2-d1d2-d3d4d5d6d7d8"],
                              },
                              {
                                "name": "club_name",
                                "value": ["Gang of Four"],
                              },
                            ],
                          },
                          {
                            "id": 7,
                            "displayName": "Jefferees",
                            "creationDate": "1970-01-01T00:00:00.000000012+00:00",
                            "uuid": "b1a2a3a4-b1b2-c1c2-d1d2-d3d4d5d6d7d8",
                            "attributes": [{
                                "name": "creation_date",
                                "value": ["1970-01-01T00:00:00.000000012+00:00"],
                              },
                              {
                                "name": "display_name",
                                "value": ["Jefferees"],
                              },
                              {
                                "name": "group_id",
                                "value": ["7"],
                              },
                              {
                                "name": "uuid",
                                "value": ["b1a2a3a4-b1b2-c1c2-d1d2-d3d4d5d6d7d8"],
                              },
                            ],
                        }]
                    }
                }),
                vec![]
            )),
            execute(QUERY, None, &schema, &Variables::new(), &context).await
        );
    }

    #[tokio::test]
    async fn list_users() {
        const QUERY: &str = r#"{
          users(filters: {
            any: [
              {eq: {
                field: "id"
                value: "bob"
              }},
              {eq: {
                field: "email"
                value: "robert@bobbers.on"
              }},
              {eq: {
                field: "firstName"
                value: "robert"
              }}
            ]}) {
            id
            email
          }
        }"#;

        let mut mock = MockTestBackendHandler::new();
        setup_default_schema(&mut mock);
        mock.expect_list_users()
            .with(
                eq(Some(DomainRequestFilter::Or(vec![
                    DomainRequestFilter::UserId(UserId::new("bob")),
                    DomainRequestFilter::Equality(
                        UserColumn::Email,
                        "robert@bobbers.on".to_owned(),
                    ),
                    DomainRequestFilter::AttributeEquality(
                        AttributeName::from("first_name"),
                        "robert".to_string().into(),
                    ),
                ]))),
                eq(false),
            )
            .return_once(|_, _| {
                Ok(vec![
                    DomainUserAndGroups {
                        user: DomainUser {
                            user_id: UserId::new("bob"),
                            email: "bob@bobbers.on".into(),
                            ..Default::default()
                        },
                        groups: None,
                    },
                    DomainUserAndGroups {
                        user: DomainUser {
                            user_id: UserId::new("robert"),
                            email: "robert@bobbers.on".into(),
                            ..Default::default()
                        },
                        groups: None,
                    },
                ])
            });

        let context =
            Context::<MockTestBackendHandler>::new_for_tests(mock, ValidationResults::admin());

        let schema = schema(Query::<MockTestBackendHandler>::new());
        assert_eq!(
            execute(QUERY, None, &schema, &Variables::new(), &context).await,
            Ok((
                graphql_value!(
                {
                    "users": [
                        {
                            "id": "bob",
                            "email": "bob@bobbers.on"
                        },
                        {
                            "id": "robert",
                            "email": "robert@bobbers.on"
                        },
                    ]
                }),
                vec![]
            ))
        );
    }

    #[tokio::test]
    async fn get_schema() {
        const QUERY: &str = r#"{
          schema {
            userSchema {
                attributes {
                    name
                    attributeType
                    isList
                    isVisible
                    isEditable
                    isHardcoded
                }
                extraLdapObjectClasses
            }
            groupSchema {
                attributes {
                    name
                    attributeType
                    isList
                    isVisible
                    isEditable
                    isHardcoded
                }
                extraLdapObjectClasses
            }
          }
        }"#;

        let mut mock = MockTestBackendHandler::new();

        setup_default_schema(&mut mock);

        let context =
            Context::<MockTestBackendHandler>::new_for_tests(mock, ValidationResults::admin());

        let schema = schema(Query::<MockTestBackendHandler>::new());
        assert_eq!(
            execute(QUERY, None, &schema, &Variables::new(), &context).await,
            Ok((
                graphql_value!(
                {
                    "schema": {
                        "userSchema": {
                            "attributes": [
                                {
                                    "name": "avatar",
                                    "attributeType": "JPEG_PHOTO",
                                    "isList": false,
                                    "isVisible": true,
                                    "isEditable": true,
                                    "isHardcoded": true,
                                },
                                {
                                    "name": "creation_date",
                                    "attributeType": "DATE_TIME",
                                    "isList": false,
                                    "isVisible": true,
                                    "isEditable": false,
                                    "isHardcoded": true,
                                },
                                {
                                    "name": "display_name",
                                    "attributeType": "STRING",
                                    "isList": false,
                                    "isVisible": true,
                                    "isEditable": true,
                                    "isHardcoded": true,
                                },
                                {
                                    "name": "first_name",
                                    "attributeType": "STRING",
                                    "isList": false,
                                    "isVisible": true,
                                    "isEditable": true,
                                    "isHardcoded": true,
                                },
                                {
                                    "name": "last_name",
                                    "attributeType": "STRING",
                                    "isList": false,
                                    "isVisible": true,
                                    "isEditable": true,
                                    "isHardcoded": true,
                                },
                                {
                                    "name": "mail",
                                    "attributeType": "STRING",
                                    "isList": false,
                                    "isVisible": true,
                                    "isEditable": true,
                                    "isHardcoded": true,
                                },
                                {
                                    "name": "user_id",
                                    "attributeType": "STRING",
                                    "isList": false,
                                    "isVisible": true,
                                    "isEditable": false,
                                    "isHardcoded": true,
                                },
                                {
                                    "name": "uuid",
                                    "attributeType": "STRING",
                                    "isList": false,
                                    "isVisible": true,
                                    "isEditable": false,
                                    "isHardcoded": true,
                                },
                            ],
                            "extraLdapObjectClasses": ["customUserClass"],
                        },
                        "groupSchema": {
                            "attributes": [
                                {
                                    "name": "creation_date",
                                    "attributeType": "DATE_TIME",
                                    "isList": false,
                                    "isVisible": true,
                                    "isEditable": false,
                                    "isHardcoded": true,
                                },
                                {
                                    "name": "display_name",
                                    "attributeType": "STRING",
                                    "isList": false,
                                    "isVisible": true,
                                    "isEditable": true,
                                    "isHardcoded": true,
                                },
                                {
                                    "name": "group_id",
                                    "attributeType": "INTEGER",
                                    "isList": false,
                                    "isVisible": true,
                                    "isEditable": false,
                                    "isHardcoded": true,
                                },
                                {
                                    "name": "uuid",
                                    "attributeType": "STRING",
                                    "isList": false,
                                    "isVisible": true,
                                    "isEditable": false,
                                    "isHardcoded": true,
                                },
                            ],
                            "extraLdapObjectClasses": [],
                        }
                    }
                }),
                vec![]
            ))
        );
    }

    #[tokio::test]
    async fn regular_user_doesnt_see_non_visible_attributes() {
        const QUERY: &str = r#"{
          schema {
            userSchema {
                attributes {
                    name
                }
                extraLdapObjectClasses
            }
          }
        }"#;

        let mut mock = MockTestBackendHandler::new();

        mock.expect_get_schema().times(1).return_once(|| {
            Ok(Schema {
                user_attributes: AttributeList {
                    attributes: vec![DomainAttributeSchema {
                        name: "invisible".into(),
                        attribute_type: AttributeType::JpegPhoto,
                        is_list: false,
                        is_visible: false,
                        is_editable: true,
                        is_hardcoded: true,
                        is_readonly: false,
                    }],
                },
                group_attributes: AttributeList {
                    attributes: Vec::new(),
                },
                extra_user_object_classes: vec![LdapObjectClass::from("customUserClass")],
                extra_group_object_classes: Vec::new(),
            })
        });

        let context = Context::<MockTestBackendHandler>::new_for_tests(
            mock,
            ValidationResults {
                user: UserId::new("bob"),
                permission: Permission::Regular,
            },
        );

        let schema = schema(Query::<MockTestBackendHandler>::new());
        assert_eq!(
            execute(QUERY, None, &schema, &Variables::new(), &context).await,
            Ok((
                graphql_value!(
                {
                    "schema": {
                        "userSchema": {
                            "attributes": [
                                {"name": "creation_date"},
                                {"name": "display_name"},
                                {"name": "mail"},
                                {"name": "user_id"},
                                {"name": "uuid"},
                            ],
                            "extraLdapObjectClasses": ["customUserClass"],
                        }
                    }
                } ),
                vec![]
            ))
        );
    }
}
