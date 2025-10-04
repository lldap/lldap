use juniper::{FieldResult, graphql_object};
use lldap_access_control::ReadonlyBackendHandler;
use lldap_domain::public_schema::PublicSchema;
use lldap_domain::types::{Group as DomainGroup, GroupDetails, GroupId};
use lldap_domain_handlers::handler::{BackendHandler, UserRequestFilter as DomainRequestFilter};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tracing::{Instrument, debug, debug_span};
use chrono::TimeZone;

use crate::api::{Context, field_error_callback};
use super::attribute::AttributeValue;
use super::user::User;

#[derive(PartialEq, Eq, Debug, Serialize, Deserialize)]
/// Represents a single group.
pub struct Group<Handler: BackendHandler> {
    pub group_id: i32,
    pub display_name: String,
    creation_date: chrono::NaiveDateTime,
    uuid: String,
    attributes: Vec<AttributeValue<Handler>>,
    pub schema: Arc<PublicSchema>,
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
