use crate::domain::handler::BackendHandler;
use juniper::{graphql_object, FieldResult, GraphQLInputObject};
use lldap_model::{ListUsersRequest, UserDetailsRequest};
use serde::{Deserialize, Serialize};
use std::convert::TryInto;

use super::api::Context;

#[derive(PartialEq, Eq, Debug, GraphQLInputObject)]
/// A filter for requests, specifying a boolean expression based on field constraints. Only one of
/// the fields can be set at a time.
pub struct RequestFilter {
    any: Option<Vec<RequestFilter>>,
    all: Option<Vec<RequestFilter>>,
    not: Option<Box<RequestFilter>>,
    eq: Option<EqualityConstraint>,
}

impl TryInto<lldap_model::RequestFilter> for RequestFilter {
    type Error = String;
    fn try_into(self) -> Result<lldap_model::RequestFilter, Self::Error> {
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
        if field_count == 0 {
            return Err("No field specified in request filter".to_string());
        }
        if field_count > 1 {
            return Err("Multiple fields specified in request filter".to_string());
        }
        if let Some(e) = self.eq {
            return Ok(lldap_model::RequestFilter::Equality(e.field, e.value));
        }
        if let Some(c) = self.any {
            return Ok(lldap_model::RequestFilter::Or(
                c.into_iter()
                    .map(TryInto::try_into)
                    .collect::<Result<Vec<_>, String>>()?,
            ));
        }
        if let Some(c) = self.all {
            return Ok(lldap_model::RequestFilter::And(
                c.into_iter()
                    .map(TryInto::try_into)
                    .collect::<Result<Vec<_>, String>>()?,
            ));
        }
        if let Some(c) = self.not {
            return Ok(lldap_model::RequestFilter::Not(Box::new((*c).try_into()?)));
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
            .get_user_details(UserDetailsRequest { user_id })
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
            .list_users(ListUsersRequest {
                filters: match filters {
                    None => None,
                    Some(f) => Some(f.try_into()?),
                },
            })
            .await
            .map(|v| v.into_iter().map(Into::into).collect())?)
    }
}

#[derive(PartialEq, Eq, Debug, Serialize, Deserialize)]
/// Represents a single user.
pub struct User<Handler: BackendHandler> {
    user: lldap_model::User,
    _phantom: std::marker::PhantomData<Box<Handler>>,
}

impl<Handler: BackendHandler> Default for User<Handler> {
    fn default() -> Self {
        Self {
            user: lldap_model::User::default(),
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

    fn display_name(&self) -> Option<&String> {
        self.user.display_name.as_ref()
    }

    fn first_name(&self) -> Option<&String> {
        self.user.first_name.as_ref()
    }

    fn last_name(&self) -> Option<&String> {
        self.user.last_name.as_ref()
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

impl<Handler: BackendHandler> From<lldap_model::User> for User<Handler> {
    fn from(user: lldap_model::User) -> Self {
        Self {
            user,
            _phantom: std::marker::PhantomData,
        }
    }
}

#[derive(PartialEq, Eq, Debug, Serialize, Deserialize)]
/// Represents a single group.
pub struct Group<Handler: BackendHandler> {
    group_id: String,
    _phantom: std::marker::PhantomData<Box<Handler>>,
}

#[graphql_object(context = Context<Handler>)]
impl<Handler: BackendHandler + Sync> Group<Handler> {
    fn id(&self) -> String {
        self.group_id.clone()
    }
    /// The groups to which this user belongs.
    async fn users(&self, context: &Context<Handler>) -> FieldResult<Vec<User<Handler>>> {
        if !context.validation_result.is_admin {
            return Err("Unauthorized access to group data".into());
        }
        unimplemented!()
    }
}

impl<Handler: BackendHandler> From<String> for Group<Handler> {
    fn from(group_id: String) -> Self {
        Self {
            group_id,
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
            .with(eq(UserDetailsRequest {
                user_id: "bob".to_string(),
            }))
            .return_once(|_| {
                Ok(lldap_model::User {
                    user_id: "bob".to_string(),
                    email: "bob@bobbers.on".to_string(),
                    ..Default::default()
                })
            });
        let mut groups = HashSet::<String>::new();
        groups.insert("Bobbersons".to_string());
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
                        "groups": [{"id": "Bobbersons"}]
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
        use lldap_model::{RequestFilter, User};
        mock.expect_list_users()
            .with(eq(ListUsersRequest {
                filters: Some(RequestFilter::Or(vec![
                    RequestFilter::Equality("id".to_string(), "bob".to_string()),
                    RequestFilter::Equality("email".to_string(), "robert@bobbers.on".to_string()),
                ])),
            }))
            .return_once(|_| {
                Ok(vec![
                    User {
                        user_id: "bob".to_string(),
                        email: "bob@bobbers.on".to_string(),
                        ..Default::default()
                    },
                    User {
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
