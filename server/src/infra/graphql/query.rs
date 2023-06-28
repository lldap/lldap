use crate::{
    domain::{
        handler::BackendHandler,
        ldap::utils::{map_user_field, UserFieldType},
        types::{GroupDetails, GroupId, JpegPhoto, UserColumn, UserId},
    },
    infra::{
        access_control::{ReadonlyBackendHandler, UserReadableBackendHandler},
        graphql::api::field_error_callback,
    },
};
use chrono::TimeZone;
use juniper::{graphql_object, FieldResult, GraphQLInputObject};
use serde::{Deserialize, Serialize};
use tracing::{debug, debug_span, Instrument};

type DomainRequestFilter = crate::domain::handler::UserRequestFilter;
type DomainUser = crate::domain::types::User;
type DomainGroup = crate::domain::types::Group;
type DomainUserAndGroups = crate::domain::types::UserAndGroups;
use super::api::Context;

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

impl TryInto<DomainRequestFilter> for RequestFilter {
    type Error = String;
    fn try_into(self) -> Result<DomainRequestFilter, Self::Error> {
        let mut field_count = 0;
        if self.any.is_some() {
            field_count += 1;
        }
        if self.all.is_some() {
            field_count += 1;
        }
        if self.not.is_some() {
            field_count += 1;
        }
        if self.eq.is_some() {
            field_count += 1;
        }
        if self.member_of.is_some() {
            field_count += 1;
        }
        if self.member_of_id.is_some() {
            field_count += 1;
        }
        if field_count == 0 {
            return Err("No field specified in request filter".to_string());
        }
        if field_count > 1 {
            return Err("Multiple fields specified in request filter".to_string());
        }
        if let Some(e) = self.eq {
            return match map_user_field(&e.field.to_ascii_lowercase()) {
                UserFieldType::NoMatch => Err(format!("Unknown request filter: {}", &e.field)),
                UserFieldType::PrimaryField(UserColumn::UserId) => {
                    Ok(DomainRequestFilter::UserId(UserId::new(&e.value)))
                }
                UserFieldType::PrimaryField(column) => {
                    Ok(DomainRequestFilter::Equality(column, e.value))
                }
                UserFieldType::Attribute(column) => Ok(DomainRequestFilter::AttributeEquality(
                    column.to_owned(),
                    e.value,
                )),
            };
        }
        if let Some(c) = self.any {
            return Ok(DomainRequestFilter::Or(
                c.into_iter()
                    .map(TryInto::try_into)
                    .collect::<Result<Vec<_>, String>>()?,
            ));
        }
        if let Some(c) = self.all {
            return Ok(DomainRequestFilter::And(
                c.into_iter()
                    .map(TryInto::try_into)
                    .collect::<Result<Vec<_>, String>>()?,
            ));
        }
        if let Some(c) = self.not {
            return Ok(DomainRequestFilter::Not(Box::new((*c).try_into()?)));
        }
        if let Some(group) = self.member_of {
            return Ok(DomainRequestFilter::MemberOf(group));
        }
        if let Some(group_id) = self.member_of_id {
            return Ok(DomainRequestFilter::MemberOfId(GroupId(group_id)));
        }
        unreachable!();
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
        Ok(handler
            .get_user_details(&user_id)
            .instrument(span)
            .await
            .map(Into::into)?)
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
        Ok(handler
            .list_users(filters.map(TryInto::try_into).transpose()?, false)
            .instrument(span)
            .await
            .map(|v| v.into_iter().map(Into::into).collect())?)
    }

    async fn groups(context: &Context<Handler>) -> FieldResult<Vec<Group<Handler>>> {
        let span = debug_span!("[GraphQL query] groups");
        let handler = context
            .get_readonly_handler()
            .ok_or_else(field_error_callback(
                &span,
                "Unauthorized access to group list",
            ))?;
        Ok(handler
            .list_groups(None)
            .instrument(span)
            .await
            .map(|v| v.into_iter().map(Into::into).collect())?)
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
        Ok(handler
            .get_group_details(GroupId(group_id))
            .instrument(span)
            .await
            .map(Into::into)?)
    }
}

#[derive(PartialEq, Eq, Debug, Serialize, Deserialize)]
/// Represents a single user.
pub struct User<Handler: BackendHandler> {
    user: DomainUser,
    _phantom: std::marker::PhantomData<Box<Handler>>,
}

#[cfg(test)]
impl<Handler: BackendHandler> Default for User<Handler> {
    fn default() -> Self {
        Self {
            user: DomainUser::default(),
            _phantom: std::marker::PhantomData,
        }
    }
}

#[graphql_object(context = Context<Handler>)]
impl<Handler: BackendHandler> User<Handler> {
    fn id(&self) -> &str {
        self.user.user_id.as_str()
    }

    fn email(&self) -> &str {
        &self.user.email
    }

    fn display_name(&self) -> &str {
        self.user.display_name.as_deref().unwrap_or("")
    }

    fn first_name(&self) -> &str {
        self.user
            .attributes
            .iter()
            .find(|a| a.name == "first_name")
            .map(|a| a.value.unwrap())
            .unwrap_or("")
    }

    fn last_name(&self) -> &str {
        self.user
            .attributes
            .iter()
            .find(|a| a.name == "last_name")
            .map(|a| a.value.unwrap())
            .unwrap_or("")
    }

    fn avatar(&self) -> Option<String> {
        self.user
            .attributes
            .iter()
            .find(|a| a.name == "avatar")
            .map(|a| String::from(&a.value.unwrap::<JpegPhoto>()))
    }

    fn creation_date(&self) -> chrono::DateTime<chrono::Utc> {
        chrono::Utc.from_utc_datetime(&self.user.creation_date)
    }

    fn uuid(&self) -> &str {
        self.user.uuid.as_str()
    }

    /// The groups to which this user belongs.
    async fn groups(&self, context: &Context<Handler>) -> FieldResult<Vec<Group<Handler>>> {
        let span = debug_span!("[GraphQL query] user::groups");
        span.in_scope(|| {
            debug!(user_id = ?self.user.user_id);
        });
        let handler = context
            .get_readable_handler(&self.user.user_id)
            .expect("We shouldn't be able to get there without readable permission");
        Ok(handler
            .get_user_groups(&self.user.user_id)
            .instrument(span)
            .await
            .map(|set| set.into_iter().map(Into::into).collect())?)
    }
}

impl<Handler: BackendHandler> From<DomainUser> for User<Handler> {
    fn from(user: DomainUser) -> Self {
        Self {
            user,
            _phantom: std::marker::PhantomData,
        }
    }
}

impl<Handler: BackendHandler> From<DomainUserAndGroups> for User<Handler> {
    fn from(user: DomainUserAndGroups) -> Self {
        Self {
            user: user.user,
            _phantom: std::marker::PhantomData,
        }
    }
}

#[derive(PartialEq, Eq, Debug, Serialize, Deserialize)]
/// Represents a single group.
pub struct Group<Handler: BackendHandler> {
    group_id: i32,
    display_name: String,
    creation_date: chrono::NaiveDateTime,
    uuid: String,
    members: Option<Vec<String>>,
    _phantom: std::marker::PhantomData<Box<Handler>>,
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
        Ok(handler
            .list_users(
                Some(DomainRequestFilter::MemberOfId(GroupId(self.group_id))),
                false,
            )
            .instrument(span)
            .await
            .map(|v| v.into_iter().map(Into::into).collect())?)
    }
}

impl<Handler: BackendHandler> From<GroupDetails> for Group<Handler> {
    fn from(group_details: GroupDetails) -> Self {
        Self {
            group_id: group_details.group_id.0,
            display_name: group_details.display_name,
            creation_date: group_details.creation_date,
            uuid: group_details.uuid.into_string(),
            members: None,
            _phantom: std::marker::PhantomData,
        }
    }
}

impl<Handler: BackendHandler> From<DomainGroup> for Group<Handler> {
    fn from(group: DomainGroup) -> Self {
        Self {
            group_id: group.id.0,
            display_name: group.display_name,
            creation_date: group.creation_date,
            uuid: group.uuid.into_string(),
            members: Some(group.users.into_iter().map(UserId::into_string).collect()),
            _phantom: std::marker::PhantomData,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        domain::handler::MockTestBackendHandler, infra::access_control::ValidationResults,
    };
    use chrono::TimeZone;
    use juniper::{
        execute, graphql_value, DefaultScalarValue, EmptyMutation, EmptySubscription, GraphQLType,
        RootNode, Variables,
    };
    use mockall::predicate::eq;
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
            uuid
            groups {
              id
              creationDate
              uuid
            }
          }
        }"#;

        let mut mock = MockTestBackendHandler::new();
        mock.expect_get_user_details()
            .with(eq(UserId::new("bob")))
            .return_once(|_| {
                Ok(DomainUser {
                    user_id: UserId::new("bob"),
                    email: "bob@bobbers.on".to_string(),
                    creation_date: chrono::Utc.timestamp_millis_opt(42).unwrap().naive_utc(),
                    uuid: crate::uuid!("b1a2a3a4b1b2c1c2d1d2d3d4d5d6d7d8"),
                    ..Default::default()
                })
            });
        let mut groups = HashSet::new();
        groups.insert(GroupDetails {
            group_id: GroupId(3),
            display_name: "Bobbersons".to_string(),
            creation_date: chrono::Utc.timestamp_nanos(42).naive_utc(),
            uuid: crate::uuid!("a1a2a3a4b1b2c1c2d1d2d3d4d5d6d7d8"),
        });
        mock.expect_get_user_groups()
            .with(eq(UserId::new("bob")))
            .return_once(|_| Ok(groups));

        let context =
            Context::<MockTestBackendHandler>::new_for_tests(mock, ValidationResults::admin());

        let schema = schema(Query::<MockTestBackendHandler>::new());
        assert_eq!(
            execute(QUERY, None, &schema, &Variables::new(), &context).await,
            Ok((
                graphql_value!(
                {
                    "user": {
                        "id": "bob",
                        "email": "bob@bobbers.on",
                        "creationDate": "1970-01-01T00:00:00.042+00:00",
                        "uuid": "b1a2a3a4-b1b2-c1c2-d1d2-d3d4d5d6d7d8",
                        "groups": [{
                            "id": 3,
                            "creationDate": "1970-01-01T00:00:00.000000042+00:00",
                            "uuid": "a1a2a3a4-b1b2-c1c2-d1d2-d3d4d5d6d7d8"
                        }]
                    }
                }),
                vec![]
            ))
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
        mock.expect_list_users()
            .with(
                eq(Some(DomainRequestFilter::Or(vec![
                    DomainRequestFilter::UserId(UserId::new("bob")),
                    DomainRequestFilter::Equality(
                        UserColumn::Email,
                        "robert@bobbers.on".to_owned(),
                    ),
                    DomainRequestFilter::AttributeEquality(
                        "first_name".to_owned(),
                        "robert".to_owned(),
                    ),
                ]))),
                eq(false),
            )
            .return_once(|_, _| {
                Ok(vec![
                    DomainUserAndGroups {
                        user: DomainUser {
                            user_id: UserId::new("bob"),
                            email: "bob@bobbers.on".to_owned(),
                            ..Default::default()
                        },
                        groups: None,
                    },
                    DomainUserAndGroups {
                        user: DomainUser {
                            user_id: UserId::new("robert"),
                            email: "robert@bobbers.on".to_owned(),
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
}
