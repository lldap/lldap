use crate::domain::handler::{BackendHandler, GroupDetails, GroupId, UserId};
use juniper::{graphql_object, FieldResult, GraphQLInputObject};
use serde::{Deserialize, Serialize};
use tracing::{debug, debug_span, Instrument};

type DomainRequestFilter = crate::domain::handler::UserRequestFilter;
type DomainUser = crate::domain::handler::User;
type DomainGroup = crate::domain::handler::Group;
type DomainUserAndGroups = crate::domain::handler::UserAndGroups;
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
            if e.field.to_lowercase() == "uid" {
                return Ok(DomainRequestFilter::UserId(UserId::new(&e.value)));
            }
            return Ok(DomainRequestFilter::Equality(e.field, e.value));
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
impl<Handler: BackendHandler + Sync> Query<Handler> {
    fn api_version() -> &'static str {
        "1.0"
    }

    pub async fn user(context: &Context<Handler>, user_id: String) -> FieldResult<User<Handler>> {
        let span = debug_span!("[GraphQL query] user");
        span.in_scope(|| {
            debug!(?user_id);
        });
        let user_id = UserId::new(&user_id);
        if !context.validation_result.can_read(&user_id) {
            span.in_scope(|| debug!("Unauthorized"));
            return Err("Unauthorized access to user data".into());
        }
        Ok(context
            .handler
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
        if !context.validation_result.is_admin_or_readonly() {
            span.in_scope(|| debug!("Unauthorized"));
            return Err("Unauthorized access to user list".into());
        }
        Ok(context
            .handler
            .list_users(filters.map(TryInto::try_into).transpose()?, false)
            .instrument(span)
            .await
            .map(|v| v.into_iter().map(Into::into).collect())?)
    }

    async fn groups(context: &Context<Handler>) -> FieldResult<Vec<Group<Handler>>> {
        let span = debug_span!("[GraphQL query] groups");
        if !context.validation_result.is_admin_or_readonly() {
            span.in_scope(|| debug!("Unauthorized"));
            return Err("Unauthorized access to group list".into());
        }
        Ok(context
            .handler
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
        if !context.validation_result.is_admin_or_readonly() {
            span.in_scope(|| debug!("Unauthorized"));
            return Err("Unauthorized access to group data".into());
        }
        Ok(context
            .handler
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
impl<Handler: BackendHandler + Sync> User<Handler> {
    fn id(&self) -> &str {
        self.user.user_id.as_str()
    }

    fn email(&self) -> &str {
        &self.user.email
    }

    fn display_name(&self) -> &str {
        &self.user.display_name
    }

    fn first_name(&self) -> &str {
        &self.user.first_name
    }

    fn last_name(&self) -> &str {
        &self.user.last_name
    }

    fn creation_date(&self) -> chrono::DateTime<chrono::Utc> {
        self.user.creation_date
    }

    /// The groups to which this user belongs.
    async fn groups(&self, context: &Context<Handler>) -> FieldResult<Vec<Group<Handler>>> {
        let span = debug_span!("[GraphQL query] user::groups");
        span.in_scope(|| {
            debug!(user_id = ?self.user.user_id);
        });
        Ok(context
            .handler
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
    creation_date: chrono::DateTime<chrono::Utc>,
    members: Option<Vec<String>>,
    _phantom: std::marker::PhantomData<Box<Handler>>,
}

#[graphql_object(context = Context<Handler>)]
impl<Handler: BackendHandler + Sync> Group<Handler> {
    fn id(&self) -> i32 {
        self.group_id
    }
    fn display_name(&self) -> String {
        self.display_name.clone()
    }
    fn creation_date(&self) -> chrono::DateTime<chrono::Utc> {
        self.creation_date
    }
    /// The groups to which this user belongs.
    async fn users(&self, context: &Context<Handler>) -> FieldResult<Vec<User<Handler>>> {
        let span = debug_span!("[GraphQL query] group::users");
        span.in_scope(|| {
            debug!(name = %self.display_name);
        });
        if !context.validation_result.is_admin_or_readonly() {
            span.in_scope(|| debug!("Unauthorized"));
            return Err("Unauthorized access to group data".into());
        }
        Ok(context
            .handler
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
            members: Some(group.users.into_iter().map(UserId::into_string).collect()),
            _phantom: std::marker::PhantomData,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        domain::handler::{MockTestBackendHandler, UserRequestFilter},
        infra::auth_service::ValidationResults,
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
            groups {
              id
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
                    ..Default::default()
                })
            });
        let mut groups = HashSet::new();
        groups.insert(GroupDetails {
            group_id: GroupId(3),
            display_name: "Bobbersons".to_string(),
            creation_date: chrono::Utc.timestamp_nanos(42),
            uuid: crate::uuid!("a1a2a3a4b1b2c1c2d1d2d3d4d5d6d7d8"),
        });
        mock.expect_get_user_groups()
            .with(eq(UserId::new("bob")))
            .return_once(|_| Ok(groups));

        let context = Context::<MockTestBackendHandler> {
            handler: Box::new(mock),
            validation_result: ValidationResults::admin(),
        };

        let schema = schema(Query::<MockTestBackendHandler>::new());
        assert_eq!(
            execute(QUERY, None, &schema, &Variables::new(), &context).await,
            Ok((
                graphql_value!(
                {
                    "user": {
                        "id": "bob",
                        "email": "bob@bobbers.on",
                        "groups": [{"id": 3}]
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
              }}
            ]}) {
            id
            email
          }
        }"#;

        let mut mock = MockTestBackendHandler::new();
        mock.expect_list_users()
            .with(
                eq(Some(UserRequestFilter::Or(vec![
                    UserRequestFilter::Equality("id".to_string(), "bob".to_string()),
                    UserRequestFilter::Equality(
                        "email".to_string(),
                        "robert@bobbers.on".to_string(),
                    ),
                ]))),
                eq(false),
            )
            .return_once(|_, _| {
                Ok(vec![
                    DomainUserAndGroups {
                        user: DomainUser {
                            user_id: UserId::new("bob"),
                            email: "bob@bobbers.on".to_string(),
                            ..Default::default()
                        },
                        groups: None,
                    },
                    DomainUserAndGroups {
                        user: DomainUser {
                            user_id: UserId::new("robert"),
                            email: "robert@bobbers.on".to_string(),
                            ..Default::default()
                        },
                        groups: None,
                    },
                ])
            });

        let context = Context::<MockTestBackendHandler> {
            handler: Box::new(mock),
            validation_result: ValidationResults::admin(),
        };

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
