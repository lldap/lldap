use crate::common::env;
use anyhow::{anyhow, Context, Result};
use graphql_client::GraphQLQuery;
use reqwest::blocking::Client;

pub type DateTimeUtc = chrono::DateTime<chrono::Utc>;

#[derive(GraphQLQuery)]
#[graphql(
    schema_path = "../schema.graphql",
    query_path = "tests/queries/add_user_to_group.graphql",
    response_derives = "Debug",
    variables_derives = "Debug,Clone",
    custom_scalars_module = "crate::common::graphql"
)]
pub struct AddUserToGroup;

#[derive(GraphQLQuery)]
#[graphql(
    schema_path = "../schema.graphql",
    query_path = "tests/queries/create_user.graphql",
    response_derives = "Debug",
    variables_derives = "Debug,Clone",
    custom_scalars_module = "crate::common::graphql"
)]
pub struct CreateUser;

#[derive(GraphQLQuery)]
#[graphql(
    schema_path = "../schema.graphql",
    query_path = "tests/queries/create_group.graphql",
    response_derives = "Debug",
    variables_derives = "Debug,Clone",
    custom_scalars_module = "crate::common::graphql"
)]
pub struct CreateGroup;

#[derive(GraphQLQuery)]
#[graphql(
    schema_path = "../schema.graphql",
    query_path = "tests/queries/list_users.graphql",
    response_derives = "Debug",
    custom_scalars_module = "crate::common::graphql"
)]
pub struct ListUsers;

#[derive(GraphQLQuery)]
#[graphql(
    schema_path = "../schema.graphql",
    query_path = "tests/queries/get_user_details.graphql",
    response_derives = "Debug",
    variables_derives = "Debug,Clone",
    custom_scalars_module = "crate::common::graphql"
)]
pub struct GetUserDetails;

#[derive(GraphQLQuery)]
#[graphql(
    schema_path = "../schema.graphql",
    query_path = "tests/queries/list_groups.graphql",
    response_derives = "Debug",
    custom_scalars_module = "crate::common::graphql"
)]
pub struct ListGroups;

#[derive(GraphQLQuery)]
#[graphql(
    schema_path = "../schema.graphql",
    query_path = "tests/queries/delete_group.graphql",
    response_derives = "Debug",
    custom_scalars_module = "crate::common::graphql"
)]
pub struct DeleteGroupQuery;

#[derive(GraphQLQuery)]
#[graphql(
    schema_path = "../schema.graphql",
    query_path = "tests/queries/delete_user.graphql",
    response_derives = "Debug",
    custom_scalars_module = "crate::common::graphql"
)]
pub struct DeleteUserQuery;

pub fn post<QueryType>(
    client: &Client,
    token: &String,
    variables: QueryType::Variables,
) -> Result<QueryType::ResponseData>
where
    QueryType: GraphQLQuery + 'static,
{
    let unwrap_graphql_response = |graphql_client::Response { data, errors, .. }| {
        data.ok_or_else(|| {
            anyhow!(
                "Errors: [{}]",
                errors
                    .unwrap_or_default()
                    .iter()
                    .map(ToString::to_string)
                    .collect::<Vec<_>>()
                    .join(", ")
            )
        })
    };
    let url = env::http_url() + "/api/graphql";
    let auth_header = format!("Bearer {}", token);
    client
        .post(url)
        .header(reqwest::header::AUTHORIZATION, auth_header)
        // Request body.
        .json(&QueryType::build_query(variables))
        .send()
        .context("while sending a request to the LLDAP server")?
        .error_for_status()
        .context("error from an LLDAP response")?
        // Parse response as Json.
        .json::<graphql_client::Response<QueryType::ResponseData>>()
        .context("while parsing backend response")
        .and_then(unwrap_graphql_response)
        .context("GraphQL error from an LLDAP response")
}
