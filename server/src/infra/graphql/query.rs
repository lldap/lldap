use crate::domain::handler::{BackendHandler, GroupId, GroupIdAndName};
use juniper::{graphql_object, FieldResult, GraphQLInputObject};
use serde::{Deserialize, Serialize};
use std::convert::TryInto;

type DomainRequestFilter = crate::domain::handler::RequestFilter;
type DomainUser = crate::domain::handler::User;
type DomainGroup = crate::domain::handler::Group;
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
        if !context.validation_result.can_access(&user_id) {
            return Err("Unauthorized access to user data".into());
        }
        Ok(context
            .handler
            .get_user_details(&user_id)
            .await
            .map(Into::into)?)
    }

    async fn users(
        context: &Context<Handler>,
        #[graphql(name = "where")] filters: Option<RequestFilter>,
    ) -> FieldResult<Vec<User<Handler>>> {
        if !context.validation_result.is_admin {
            return Err("Unauthorized access to user list".into());
        }
        Ok(context
            .handler
            .list_users(filters.map(TryInto::try_into).transpose()?)
            .await
            .map(|v| v.into_iter().map(Into::into).collect())?)
    }

    async fn groups(context: &Context<Handler>) -> FieldResult<Vec<Group<Handler>>> {
        if !context.validation_result.is_admin {
            return Err("Unauthorized access to group list".into());
        }
        Ok(context
            .handler
            .list_groups()
            .await
            .map(|v| v.into_iter().map(Into::into).collect())?)
    }

    async fn group(context: &Context<Handler>, group_id: i32) -> FieldResult<Group<Handler>> {
        if !context.validation_result.is_admin {
            return Err("Unauthorized access to group data".into());
        }
        Ok(context
            .handler
            .get_group_details(GroupId(group_id))
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
        &self.user.user_id
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
        Ok(context
            .handler
            .get_user_groups(&self.user.user_id)
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

#[derive(PartialEq, Eq, Debug, Serialize, Deserialize)]
/// Represents a single group.
pub struct Group<Handler: BackendHandler> {
    group_id: i32,
    display_name: String,
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
    /// The groups to which this user belongs.
    async fn users(&self, context: &Context<Handler>) -> FieldResult<Vec<User<Handler>>> {
        if !context.validation_result.is_admin {
            return Err("Unauthorized access to group data".into());
        }
        Ok(context
            .handler
            .list_users(Some(DomainRequestFilter::MemberOfId(GroupId(
                self.group_id,
            ))))
            .await
            .map(|v| v.into_iter().map(Into::into).collect())?)
    }
}

impl<Handler: BackendHandler> From<GroupIdAndName> for Group<Handler> {
    fn from(group_id_and_name: GroupIdAndName) -> Self {
        Self {
            group_id: group_id_and_name.0 .0,
            display_name: group_id_and_name.1,
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
            members: Some(group.users.into_iter().map(Into::into).collect()),
            _phantom: std::marker::PhantomData,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{domain::handler::MockTestBackendHandler, infra::auth_service::ValidationResults};
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
            .with(eq("bob"))
            .return_once(|_| {
                Ok(DomainUser {
                    user_id: "bob".to_string(),
                    email: "bob@bobbers.on".to_string(),
                    ..Default::default()
                })
            });
        let mut groups = HashSet::new();
        groups.insert(GroupIdAndName(GroupId(3), "Bobbersons".to_string()));
        mock.expect_get_user_groups()
            .with(eq("bob"))
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
        use crate::domain::handler::RequestFilter;
        mock.expect_list_users()
            .with(eq(Some(RequestFilter::Or(vec![
                RequestFilter::Equality("id".to_string(), "bob".to_string()),
                RequestFilter::Equality("email".to_string(), "robert@bobbers.on".to_string()),
            ]))))
            .return_once(|_| {
                Ok(vec![
                    DomainUser {
                        user_id: "bob".to_string(),
                        email: "bob@bobbers.on".to_string(),
                        ..Default::default()
                    },
                    DomainUser {
                        user_id: "robert".to_string(),
                        email: "robert@bobbers.on".to_string(),
                        ..Default::default()
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
