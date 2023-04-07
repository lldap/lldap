use anyhow::{anyhow, bail, Context, Result};
use assert_cmd::prelude::*;
use graphql_client::GraphQLQuery;
use reqwest::blocking::{Client, ClientBuilder};
use std::collections::{HashMap, HashSet};
use std::process::{Child, Command};
use std::{env::var, fs::canonicalize, thread, time::Duration};

const DB_KEY: &str = "LLDAP_DATABASE_URL";

#[derive(GraphQLQuery)]
#[graphql(
    schema_path = "../schema.graphql",
    query_path = "tests/queries/add_user_to_group.graphql",
    response_derives = "Debug",
    variables_derives = "Debug,Clone",
    custom_scalars_module = "crate::infra::graphql"
)]
struct AddUserToGroup;

#[derive(GraphQLQuery)]
#[graphql(
    schema_path = "../schema.graphql",
    query_path = "tests/queries/create_user.graphql",
    response_derives = "Debug",
    variables_derives = "Debug,Clone",
    custom_scalars_module = "crate::infra::graphql"
)]
struct CreateUser;

#[derive(GraphQLQuery)]
#[graphql(
    schema_path = "../schema.graphql",
    query_path = "tests/queries/create_group.graphql",
    response_derives = "Debug",
    variables_derives = "Debug,Clone",
    custom_scalars_module = "crate::infra::graphql"
)]
struct CreateGroup;

#[derive(GraphQLQuery)]
#[graphql(
    schema_path = "../schema.graphql",
    query_path = "tests/queries/list_users.graphql",
    response_derives = "Debug",
    custom_scalars_module = "crate::infra::graphql"
)]
pub struct ListUsers;

#[derive(GraphQLQuery)]
#[graphql(
    schema_path = "../schema.graphql",
    query_path = "tests/queries/list_groups.graphql",
    response_derives = "Debug",
    custom_scalars_module = "crate::infra::graphql"
)]
struct ListGroups;

#[derive(GraphQLQuery)]
#[graphql(
    schema_path = "../schema.graphql",
    query_path = "tests/queries/delete_group.graphql",
    response_derives = "Debug",
    custom_scalars_module = "crate::infra::graphql"
)]
struct DeleteGroupQuery;

#[derive(GraphQLQuery)]
#[graphql(
    schema_path = "../schema.graphql",
    query_path = "tests/queries/delete_user.graphql",
    response_derives = "Debug",
    custom_scalars_module = "crate::infra::graphql"
)]
struct DeleteUserQuery;

#[derive(Clone)]
pub struct User {
    pub username: String,
    pub groups: Vec<String>,
}

impl User {
    pub fn new(username: &str, groups: Vec<&str>) -> Self {
        let username = username.to_string();
        let groups = groups.iter().map(|username| username.to_string()).collect();
        Self { username, groups }
    }
}

pub struct LLDAPFixture {
    token: String,
    client: Client,
    child: Child,
    users: HashSet<String>,
    groups: HashMap<String, i64>,
}

impl LLDAPFixture {
    pub fn new() -> Self {
        let mut cmd = Command::cargo_bin(env!("CARGO_PKG_NAME")).expect("cargo bin found");

        let path = canonicalize("..").expect("canonical path");
        let db_url = get_database_url();
        println!("Running from directory: {:?}", path);
        println!("Using database: {db_url}");
        cmd.current_dir(path.clone());
        cmd.env(DB_KEY, db_url);
        cmd.arg("run");
        cmd.arg("--verbose");
        let child = cmd.spawn().expect("Unable to start server");
        loop {
            let status = Command::cargo_bin(env!("CARGO_PKG_NAME"))
                .expect("cargo bin not found")
                .current_dir(path.clone())
                .arg("healthcheck")
                .status()
                .expect("healthcheck fail");
            if status.success() {
                break;
            }
            thread::sleep(Duration::from_millis(1000));
        }
        let client = ClientBuilder::new()
            .connect_timeout(std::time::Duration::from_secs(2))
            .timeout(std::time::Duration::from_secs(5))
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .expect("failed to make http client");
        let token = get_token(&client).expect("failed to get token");
        Self {
            client,
            token,
            child,
            users: HashSet::new(),
            groups: HashMap::new(),
        }
    }

    pub fn load_state(&mut self, state: &Vec<User>) {
        let mut users: HashSet<String> = HashSet::new();
        let mut groups: HashSet<String> = HashSet::new();
        for user in state {
            users.insert(user.username.clone());
            groups.extend(user.groups.clone());
        }
        for user in &users {
            self.add_user(user);
        }
        for group in &groups {
            self.add_group(group);
        }
        for User { username, groups } in state {
            for group in groups {
                self.add_user_to_group(username, group);
            }
        }
    }

    fn add_user(&mut self, user: &String) {
        post::<CreateUser>(
            &self.client,
            &self.token,
            create_user::Variables {
                user: create_user::CreateUserInput {
                    id: user.clone(),
                    email: format!("{}@lldap.test", user),
                    avatar: None,
                    display_name: None,
                    first_name: None,
                    last_name: None,
                },
            },
        )
        .expect("failed to add user");
        self.users.insert(user.clone());
    }

    fn add_group(&mut self, group: &String) {
        let id = post::<CreateGroup>(
            &self.client,
            &self.token,
            create_group::Variables {
                name: group.clone(),
            },
        )
        .expect("failed to add group")
        .create_group
        .id;
        self.groups.insert(group.clone(), id);
    }

    fn delete_user(&mut self, user: &String) {
        post::<DeleteUserQuery>(
            &self.client,
            &self.token,
            delete_user_query::Variables { user: user.clone() },
        )
        .expect("failed to delete user");
        self.users.remove(user);
    }

    fn delete_group(&mut self, group: &String) {
        let group_id = self.groups.get(group).unwrap();
        post::<DeleteGroupQuery>(
            &self.client,
            &self.token,
            delete_group_query::Variables {
                group_id: *group_id,
            },
        )
        .expect("failed to delete group");
        self.groups.remove(group);
    }

    fn add_user_to_group(&mut self, user: &String, group: &String) {
        let group_id = self.groups.get(group).unwrap();
        post::<AddUserToGroup>(
            &self.client,
            &self.token,
            add_user_to_group::Variables {
                user: user.clone(),
                group: *group_id,
            },
        )
        .expect("failed to add user to group");
    }
}

impl Drop for LLDAPFixture {
    fn drop(&mut self) {
        let users = self.users.clone();
        for user in users {
            self.delete_user(&user);
        }
        let groups = self.groups.clone();
        for group in groups.keys() {
            self.delete_group(group);
        }
        self.child
            .kill()
            .map_err(|err| println!("Failed to kill LLDAP: {:?}", err))
            .ok();
    }
}

fn get_database_url() -> String {
    let url = var(DB_KEY).ok();
    let url = url.unwrap_or("sqlite://e2e_test.db?mode=rwc".to_string());
    url.to_string()
}

pub fn get_ldap_url() -> String {
    let port = option_env!("LLDAP_LDAP_PORT");
    let port = port.unwrap_or("3890");
    let mut url = String::from("ldap://localhost:");
    url += port;
    url
}

pub fn get_http_url() -> String {
    let port = option_env!("LLDAP_HTTP_PORT");
    let port = port.unwrap_or("17170");
    let mut url = String::from("http://localhost:");
    url += port;
    url
}

pub fn get_admin_dn() -> String {
    let user = option_env!("LLDAP_LDAP_USER_DN");
    let user = user.unwrap_or("admin");
    user.to_string()
}

pub fn get_admin_password() -> String {
    let pass = option_env!("LLDAP_LDAP_USER_PASS");
    let pass = pass.unwrap_or("password");
    pass.to_string()
}

pub fn get_base_dn() -> String {
    let dn = option_env!("LLDAP_LDAP_BASE_DN");
    let dn = dn.unwrap_or("dc=example,dc=com");
    dn.to_string()
}

pub fn get_token(client: &Client) -> Result<String> {
    let username = get_admin_dn();
    let password = get_admin_password();
    let base_url = get_http_url();
    let response = client
        .post(format!("{base_url}/auth/simple/login"))
        .header(reqwest::header::CONTENT_TYPE, "application/json")
        .body(
            serde_json::to_string(&lldap_auth::login::ClientSimpleLoginRequest {
                username: username,
                password: password,
            })
            .expect("Failed to encode the username/password as json to log in"),
        )
        .send()?
        .error_for_status()?;
    Ok(serde_json::from_str::<lldap_auth::login::ServerLoginResponse>(&response.text()?)?.token)
}
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
    let url = get_http_url() + "/api/graphql";
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
