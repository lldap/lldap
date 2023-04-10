use crate::common::auth::get_token;
use crate::common::env;
use crate::common::graphql::*;
use assert_cmd::prelude::*;
use reqwest::blocking::{Client, ClientBuilder};
use std::collections::{HashMap, HashSet};
use std::process::{Child, Command};
use std::{fs::canonicalize, thread, time::Duration};
use uuid::Uuid;

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
        let mut cmd = Command::cargo_bin(env!("CARGO_PKG_NAME")).expect("cargo bin not found");

        let path = canonicalize("..").expect("canonical path");
        let db_url = env::database_url();
        println!("Running from directory: {:?}", path);
        println!("Using database: {db_url}");
        cmd.current_dir(path.clone());
        cmd.env(env::DB_KEY, db_url);
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
        let token = get_token(&client);
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

pub fn new_id(prefix: Option<&str>) -> String {
    let id = Uuid::new_v4();
    let id = format!("{}-lldap-test", id.to_simple());
    match prefix {
        Some(prefix) => format!("{}{}", prefix, id),
        None => id,
    }
}
