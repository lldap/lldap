use std::collections::{HashMap, HashSet};

use anyhow::{Context, Result, anyhow, bail};
use graphql_client::GraphQLQuery;
use requestty::{Question, prompt_one};
use reqwest::blocking::{Client, ClientBuilder};
use smallvec::SmallVec;

use crate::ldap::{LdapGroup, check_host_exists};

pub struct GraphQLClient {
    url: String,
    auth_header: reqwest::header::HeaderValue,
    client: Client,
}

impl GraphQLClient {
    fn new(url: String, auth_token: &str, client: Client) -> Result<Self> {
        Ok(Self {
            url: format!("{}/api/graphql", url),
            auth_header: format!("Bearer {}", auth_token).parse()?,
            client,
        })
    }

    pub fn post<QueryType>(
        &self,
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
        self.client
            .post(&self.url)
            .header(reqwest::header::AUTHORIZATION, &self.auth_header)
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
}

#[derive(Clone, Debug)]
pub struct User {
    pub user_input: create_user::CreateUserInput,
    pub password: Option<String>,
    pub dn: String,
}

impl User {
    // https://github.com/graphql-rust/graphql-client/issues/386
    pub fn new(
        user_input: create_user::CreateUserInput,
        password: Option<String>,
        dn: String,
    ) -> User {
        User {
            user_input,
            password,
            dn,
        }
    }
}

#[derive(GraphQLQuery)]
#[graphql(
    schema_path = "../schema.graphql",
    query_path = "queries/create_user.graphql",
    response_derives = "Debug",
    variables_derives = "Debug,Clone",
    custom_scalars_module = "crate::graphql"
)]
struct CreateUser;

pub type CreateUserInput = create_user::CreateUserInput;

#[derive(GraphQLQuery)]
#[graphql(
    schema_path = "../schema.graphql",
    query_path = "queries/create_group.graphql",
    response_derives = "Debug",
    variables_derives = "Debug,Clone",
    custom_scalars_module = "crate::graphql"
)]
struct CreateGroup;

#[derive(GraphQLQuery)]
#[graphql(
    schema_path = "../schema.graphql",
    query_path = "queries/list_users.graphql",
    response_derives = "Debug",
    custom_scalars_module = "crate::graphql"
)]
struct ListUsers;

#[derive(GraphQLQuery)]
#[graphql(
    schema_path = "../schema.graphql",
    query_path = "queries/list_groups.graphql",
    response_derives = "Debug",
    custom_scalars_module = "crate::graphql"
)]
struct ListGroups;

pub type LldapGroup = list_groups::ListGroupsGroups;

fn try_login(
    lldap_server: &str,
    username: &str,
    password: &str,
    client: &Client,
) -> Result<String> {
    let mut rng = rand::rngs::OsRng;
    use lldap_auth::login::*;
    use lldap_auth::opaque::client::login::*;
    let ClientLoginStartResult { state, message } =
        start_login(password, &mut rng).context("Could not initialize login")?;
    let req = ClientLoginStartRequest {
        username: username.into(),
        login_start_request: message,
    };
    let response = client
        .post(format!("{}/auth/opaque/login/start", lldap_server))
        .json(&req)
        .send()
        .context("while trying to login to LLDAP")?;
    if response.status().as_u16() == 409 {
        // The server signals an opaque-ke 0.7 password via a structured body
        // (`{"error_code":"opaque_v07_version"}`), not just the status code.
        // Match on it so an unrelated future 409 isn't mistaken for a legacy
        // password. This is the common state right after an LLDAP upgrade,
        // before the account's first interactive login.
        let body = response.text().unwrap_or_default();
        if body.contains("opaque_v07_version") {
            // Fall back to the v0.7 OPAQUE login flow, mirroring the web client.
            return try_login_v07(lldap_server, username, password, client);
        }
        bail!("Failed to start logging in to LLDAP: 409 ({body})");
    }
    if !response.status().is_success() {
        bail!(
            "Failed to start logging in to LLDAP: {}",
            response.status().as_str()
        );
    }
    let login_start_response = response.json::<lldap_auth::login::ServerLoginStartResponse>()?;
    let login_finish = finish_login(
        state,
        login_start_response.credential_response,
        password,
        &mut rng,
    )?;
    let req = ClientLoginFinishRequest {
        server_data: login_start_response.server_data,
        credential_finalization: login_finish.message,
    };
    let response = client
        .post(format!("{}/auth/opaque/login/finish", lldap_server))
        .json(&req)
        .send()?;
    if !response.status().is_success() {
        bail!(
            "Failed to finish logging in to LLDAP: {}",
            response.status().as_str()
        );
    }
    let json = serde_json::from_str::<lldap_auth::login::ServerLoginResponse>(&response.text()?)
        .context("Could not parse response")?;
    Ok(json.token)
}

/// Backward-compatible login for accounts whose password is still in the
/// opaque-ke 0.7 format. Mirrors the web client's `/auth/opaque/v07/login/*`
/// fallback: validate via the v0.7 handshake (the server re-registers the
/// password as v4.0 on success).
fn try_login_v07(
    lldap_server: &str,
    username: &str,
    password: &str,
    client: &Client,
) -> Result<String> {
    use base64::Engine;
    let b64 = base64::engine::general_purpose::STANDARD;

    let (state, message) = lldap_auth::v07::client_login_start(password)
        .map_err(|e| anyhow::anyhow!("Could not initialize v0.7 login: {e}"))?;
    let req = lldap_auth::login_base64::ClientLoginStartRequest {
        username: username.into(),
        login_start_request: b64.encode(&message),
    };
    let response = client
        .post(format!("{}/auth/opaque/v07/login/start", lldap_server))
        .json(&req)
        .send()
        .context("while trying to start v0.7 login to LLDAP")?;
    if !response.status().is_success() {
        bail!(
            "Failed to start v0.7 login to LLDAP: {}",
            response.status().as_str()
        );
    }
    let start_response = response.json::<lldap_auth::login_base64::ServerLoginStartResponse>()?;
    let server_response_bytes = b64
        .decode(&start_response.credential_response)
        .context("Could not decode v0.7 server response")?;
    let finalization = lldap_auth::v07::client_login_finish(state, &server_response_bytes)
        .map_err(|e| anyhow::anyhow!("Invalid username or password: {e}"))?;
    let req = lldap_auth::login_base64::ClientLoginFinishRequest {
        server_data: start_response.server_data,
        credential_finalization: b64.encode(&finalization),
    };
    let response = client
        .post(format!("{}/auth/opaque/v07/login/finish", lldap_server))
        .json(&req)
        .send()?;
    if !response.status().is_success() {
        bail!(
            "Failed to finish v0.7 login to LLDAP: {}",
            response.status().as_str()
        );
    }
    let json = serde_json::from_str::<lldap_auth::login::ServerLoginResponse>(&response.text()?)
        .context("Could not parse v0.7 login response")?;
    Ok(json.token)
}

pub fn get_lldap_user_and_password(
    lldap_server: &str,
    client: &Client,
    previous_username: Option<String>,
) -> Result<String> {
    let username = {
        let question = Question::input("lldap_username")
            .message("LLDAP_USERNAME (default=admin)")
            .default("admin")
            .auto_complete(|answer, _| {
                let mut answers = SmallVec::<[String; 1]>::new();
                if let Some(username) = &previous_username {
                    answers.push(username.clone());
                }
                answers.push(answer);
                answers
            })
            .build();
        let answer = prompt_one(question)?;
        answer.as_string().unwrap().to_owned()
    };
    let password = {
        let question = Question::password("lldap_password")
            .message("LLDAP_PASSWORD")
            .validate(|password, _| {
                if !password.is_empty() {
                    Ok(())
                } else {
                    Err("Empty password".to_owned())
                }
            })
            .build();
        let answer = prompt_one(question)?;
        answer.as_string().unwrap().to_owned()
    };
    match try_login(lldap_server, &username, &password, client) {
        Err(e) => {
            println!("Could not login: {:#?}", e);
            get_lldap_user_and_password(lldap_server, client, Some(username))
        }
        Ok(token) => Ok(token),
    }
}

pub fn get_lldap_client() -> Result<GraphQLClient> {
    let client = ClientBuilder::new()
        .connect_timeout(std::time::Duration::from_secs(2))
        .timeout(std::time::Duration::from_secs(5))
        .redirect(reqwest::redirect::Policy::none())
        .build()?;
    let lldap_server = get_lldap_server(&client)?;
    let token = get_lldap_user_and_password(&lldap_server, &client, None)?;
    println!("Successfully connected to LLDAP");
    GraphQLClient::new(lldap_server, &token, client)
}

pub fn insert_users_into_lldap(
    users: Vec<User>,
    existing_users: &mut Vec<String>,
    graphql_client: &GraphQLClient,
) -> Result<()> {
    let mut added_users_count = 0;
    let mut skip_all = false;
    for user in users {
        let uid = user.user_input.id.clone();
        loop {
            print!("Adding {}... ", &uid);
            match graphql_client
                .post::<CreateUser>(create_user::Variables {
                    user: user.user_input.clone(),
                })
                .context(format!("while creating user '{}'", uid))
            {
                Err(e) => {
                    println!("Error: {:#?}", e);
                    if skip_all {
                        break;
                    }
                    let question = requestty::Question::select("skip_user")
                        .message(format!("Error while adding user {}", &uid))
                        .choices(vec!["Skip", "Retry", "Skip all"])
                        .default_separator()
                        .choice("Abort")
                        .build();
                    let answer = prompt_one(question)?;
                    let choice = answer.as_list_item().unwrap();
                    match choice.text.as_str() {
                        "Skip" => break,
                        "Retry" => continue,
                        "Skip all" => {
                            skip_all = true;
                            break;
                        }
                        "Abort" => return Err(e),
                        _ => unreachable!(),
                    }
                }
                Ok(response) => {
                    println!("Done!");
                    added_users_count += 1;
                    existing_users.push(response.create_user.id);
                    break;
                }
            }
        }
    }
    println!("{} users successfully added", added_users_count);
    Ok(())
}

pub fn insert_groups_into_lldap(
    groups: &[LdapGroup],
    lldap_groups: &mut Vec<LldapGroup>,
    graphql_client: &GraphQLClient,
) -> Result<()> {
    let mut added_groups_count = 0;
    let mut skip_all = false;
    let existing_group_names =
        HashSet::<&str>::from_iter(lldap_groups.iter().map(|g| g.display_name.as_str()));
    let new_groups = groups
        .iter()
        .filter(|g| !existing_group_names.contains(g.name.as_str()))
        .collect::<Vec<_>>();
    for group in new_groups {
        let name = group.name.clone();
        loop {
            print!("Adding {}... ", &name);
            match graphql_client
                .post::<CreateGroup>(create_group::Variables { name: name.clone() })
                .context(format!("while creating group '{}'", &name))
            {
                Err(e) => {
                    println!("Error: {:#?}", e);
                    if skip_all {
                        break;
                    }
                    let question = requestty::Question::select("skip_group")
                        .message(format!("Error while adding group {}", &name))
                        .choices(vec!["Skip", "Retry", "Skip all"])
                        .default_separator()
                        .choice("Abort")
                        .build();
                    let answer = prompt_one(question)?;
                    let choice = answer.as_list_item().unwrap();
                    match choice.text.as_str() {
                        "Skip" => break,
                        "Retry" => continue,
                        "Skip all" => {
                            skip_all = true;
                            break;
                        }
                        "Abort" => return Err(e),
                        _ => unreachable!(),
                    }
                }
                Ok(response) => {
                    println!("Done!");
                    added_groups_count += 1;
                    lldap_groups.push(LldapGroup {
                        id: response.create_group.id,
                        display_name: group.name.clone(),
                        users: Vec::new(),
                    });
                    break;
                }
            }
        }
    }
    println!("{} groups successfully added", added_groups_count);
    Ok(())
}

pub fn get_lldap_users(graphql_client: &GraphQLClient) -> Result<Vec<String>> {
    Ok(graphql_client
        .post::<ListUsers>(list_users::Variables {})?
        .users
        .into_iter()
        .map(|u| u.id)
        .collect())
}

pub fn get_lldap_groups(graphql_client: &GraphQLClient) -> Result<Vec<LldapGroup>> {
    Ok(graphql_client
        .post::<ListGroups>(list_groups::Variables {})?
        .groups)
}

#[derive(GraphQLQuery)]
#[graphql(
    schema_path = "../schema.graphql",
    query_path = "queries/add_user_to_group.graphql",
    response_derives = "Debug",
    variables_derives = "Debug,Clone",
    custom_scalars_module = "crate::graphql"
)]
struct AddUserToGroup;

pub fn insert_group_memberships_into_lldap(
    ldap_users: &[User],
    ldap_groups: &[LdapGroup],
    existing_users: &[String],
    existing_groups: &[LldapGroup],
    graphql_client: &GraphQLClient,
) -> Result<()> {
    let existing_users = HashSet::<&str>::from_iter(existing_users.iter().map(String::as_str));
    let existing_groups = HashMap::<&str, &LldapGroup>::from_iter(
        existing_groups.iter().map(|g| (g.display_name.as_str(), g)),
    );
    let dn_resolver = HashMap::<&str, &str>::from_iter(
        ldap_users
            .iter()
            .map(|u| (u.dn.as_str(), u.user_input.id.as_str())),
    );
    let mut skip_all = false;
    let mut added_membership_count = 0;
    for group in ldap_groups {
        if let Some(lldap_group) = existing_groups.get(group.name.as_str()) {
            let lldap_members =
                HashSet::<&str>::from_iter(lldap_group.users.iter().map(|u| u.id.as_str()));
            let mut skip_group = false;
            for user in &group.members {
                let user = if let Some(id) = dn_resolver.get(user.as_str()) {
                    id
                } else {
                    continue;
                };
                if lldap_members.contains(user) || !existing_users.contains(user) {
                    continue;
                }
                loop {
                    print!("Adding '{}' to '{}'... ", &user, &group.name);
                    if let Err(e) = graphql_client
                        .post::<AddUserToGroup>(add_user_to_group::Variables {
                            user: user.to_string(),
                            group: lldap_group.id,
                        })
                        .context(format!(
                            "while adding user '{}' to group '{}'",
                            &user, &group.name
                        ))
                    {
                        println!("Error: {:#?}", e);
                        if skip_all || skip_group {
                            break;
                        }
                        let question = requestty::Question::select("skip_membership")
                            .message(format!(
                                "Error while adding '{}' to group '{}",
                                &user, &group.name
                            ))
                            .choices(vec!["Skip", "Retry", "Skip group", "Skip all"])
                            .default_separator()
                            .choice("Abort")
                            .build();
                        let answer = prompt_one(question)?;
                        let choice = answer.as_list_item().unwrap();
                        match choice.text.as_str() {
                            "Skip" => break,
                            "Retry" => continue,
                            "Skip group" => {
                                skip_group = true;
                                break;
                            }
                            "Skip all" => {
                                skip_all = true;
                                break;
                            }
                            "Abort" => return Err(e),
                            _ => unreachable!(),
                        }
                    } else {
                        println!("Done!");
                        added_membership_count += 1;
                        break;
                    }
                }
            }
        }
    }
    println!("{} memberships successfully added", added_membership_count);
    Ok(())
}

fn get_lldap_server(client: &Client) -> Result<String> {
    let http_protocols = &[("http://", 17170), ("https://", 17170)];
    let question = Question::input("lldap_url")
        .message("LLDAP_URL (http://...)")
        .auto_complete(|answer, _| {
            let mut answers = SmallVec::<[String; 1]>::new();
            if "http://".starts_with(&answer) {
                answers.push("http://".to_owned());
            }
            if "https://".starts_with(&answer) {
                answers.push("https://".to_owned());
            }
            answers.push(answer);
            answers
        })
        .validate(|url, _| {
            if let Some(url) = check_host_exists(url, http_protocols)? {
                client
                    .get(format!("{}/api/graphql", url))
                    .send()
                    .map_err(|e| format!("Host did not answer: {}", e))
                    .and_then(|response| {
                        if response.status() == reqwest::StatusCode::UNAUTHORIZED {
                            Ok(())
                        } else {
                            Err("Host doesn't seem to be an LLDAP server".to_owned())
                        }
                    })
            } else {
                Err(
                    "Could not resolve host (make sure it starts with 'http://' or 'https://')"
                        .to_owned(),
                )
            }
        })
        .build();
    let answer = prompt_one(question)?;
    Ok(
        check_host_exists(answer.as_string().unwrap(), http_protocols)
            .unwrap()
            .unwrap(),
    )
}
