use crate::common::{
    auth::get_token,
    env,
    graphql::{
        add_user_to_group, create_group, create_user, delete_group_query, delete_user_query, post,
        AddUserToGroup, CreateGroup, CreateUser, DeleteGroupQuery, DeleteUserQuery,
    },
};
use assert_cmd::prelude::*;
use nix::{
    sys::signal::{self, Signal},
    unistd::Pid,
};
use reqwest::blocking::{Client, ClientBuilder};
use std::collections::{HashMap, HashSet};
use std::process::{Child as ChildProcess, Command};
use std::{fs::canonicalize, thread, time::Duration};
use uuid::Uuid;

#[derive(Clone)]
pub struct User {
    pub username: String,
    pub groups: Vec<String>,
}

impl User {
    pub fn new(username: &str, groups: Vec<&str>) -> Self {
        let username = username.to_owned();
        let groups = groups.iter().map(|username| username.to_string()).collect();
        Self { username, groups }
    }
}

pub struct LLDAPFixture {
    token: String,
    client: Client,
    child: ChildProcess,
    users: HashSet<String>,
    groups: HashMap<String, i64>,
}

const MAX_HEALTHCHECK_ATTEMPS: u8 = 10;

impl LLDAPFixture {
    pub fn new() -> Self {
        let mut cmd = create_lldap_command();
        cmd.arg("run");
        cmd.arg("--verbose");
        let child = cmd.spawn().expect("Unable to start server");
        let mut started = false;
        for _ in 0..MAX_HEALTHCHECK_ATTEMPS {
            let status = create_lldap_command()
                .arg("healthcheck")
                .status()
                .expect("healthcheck fail");
            if status.success() {
                started = true;
                break;
            }
            thread::sleep(Duration::from_millis(1000));
        }
        assert!(started);
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

    fn add_group(&mut self, group: &str) {
        let id = post::<CreateGroup>(
            &self.client,
            &self.token,
            create_group::Variables {
                name: group.to_owned(),
            },
        )
        .expect("failed to add group")
        .create_group
        .id;
        self.groups.insert(group.to_owned(), id);
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

    fn add_user_to_group(&mut self, user: &str, group: &String) {
        let group_id = self.groups.get(group).unwrap();
        post::<AddUserToGroup>(
            &self.client,
            &self.token,
            add_user_to_group::Variables {
                user: user.to_owned(),
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
        let result = signal::kill(
            Pid::from_raw(self.child.id().try_into().unwrap()),
            Signal::SIGTERM,
        );
        if let Err(err) = result {
            println!("Failed to send kill signal: {:?}", err);
            let _ = self
                .child
                .kill()
                .map_err(|err| println!("Failed to kill LLDAP: {:?}", err));
            return;
        }

        for _ in 0..10 {
            let status = self.child.try_wait();
            if status.is_err() {}
            match status {
                Err(e) => {
                    println!(
                        "Failed to get status while waiting for graceful exit: {}",
                        e
                    );
                    break;
                }
                Ok(None) => {
                    println!("LLDAP still running, sleeping for 1 second.");
                }
                Ok(Some(status)) => {
                    if !status.success() {
                        println!("LLDAP exited with status {}", status)
                    }
                    return;
                }
            }
            thread::sleep(Duration::from_millis(1000));
        }
        println!("LLDAP alive after 10 seconds, forcing exit.");
        let _ = self
            .child
            .kill()
            .map_err(|err| println!("Failed to kill LLDAP: {:?}", err));
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

fn create_lldap_command() -> Command {
    let mut cmd = Command::cargo_bin(env!("CARGO_PKG_NAME")).expect("cargo bin not found");
    // This gives us the absolute path of the repo base instead of running it in server/
    let path = canonicalize("..").expect("canonical path");
    let db_url = env::database_url();
    cmd.current_dir(path);
    cmd.env(env::DB_KEY, db_url);
    cmd
}
