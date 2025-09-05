#![allow(clippy::uninlined_format_args)]

use std::collections::HashSet;

use anyhow::{Result, anyhow};
use requestty::{Question, prompt_one};

mod ldap;
mod lldap;

use ldap::LdapGroup;
use lldap::{LldapGroup, User};

fn ask_generic_confirmation(name: &str, message: &str) -> Result<bool> {
    let confirm = Question::confirm(name)
        .message(message)
        .default(true)
        .build();
    let answer = prompt_one(confirm)?;
    Ok(answer.as_bool().unwrap())
}

fn get_users_to_add(users: &[User], existing_users: &[String]) -> Result<Option<Vec<User>>> {
    let existing_users = HashSet::<&String>::from_iter(existing_users);
    let num_found_users = users.len();
    let input_users: Vec<_> = users
        .iter()
        .filter(|u| !existing_users.contains(&u.user_input.id))
        .map(User::clone)
        .collect();
    println!(
        "Found {} users, of which {} new users: [\n  {}\n]",
        num_found_users,
        input_users.len(),
        input_users
            .iter()
            .map(|u| format!(
                "\"{}\" ({})",
                &u.user_input.id,
                if u.password.is_some() {
                    "with password"
                } else {
                    "no password"
                }
            ))
            .collect::<Vec<_>>()
            .join(",\n  ")
    );
    if !input_users.is_empty()
        && ask_generic_confirmation(
            "proceed_users",
            "Do you want to proceed to add those users to LLDAP?",
        )?
    {
        Ok(Some(input_users))
    } else {
        Ok(None)
    }
}

fn should_insert_groups(
    input_groups: &[LdapGroup],
    existing_groups: &[LldapGroup],
) -> Result<bool> {
    let existing_group_names =
        HashSet::<&str>::from_iter(existing_groups.iter().map(|g| g.display_name.as_str()));
    let new_groups = input_groups
        .iter()
        .filter(|g| !existing_group_names.contains(g.name.as_str()));
    let num_new_groups = new_groups.clone().count();
    println!(
        "Found {} groups, of which {} new groups: [\n  {}\n]",
        input_groups.len(),
        num_new_groups,
        new_groups
            .map(|g| g.name.as_str())
            .collect::<Vec<_>>()
            .join(",\n  ")
    );
    Ok(num_new_groups != 0
        && ask_generic_confirmation(
            "proceed_groups",
            "Do you want to proceed to add those groups to LLDAP?",
        )?)
}

struct GroupList {
    ldap_groups: Vec<LdapGroup>,
    lldap_groups: Vec<LldapGroup>,
}

fn migrate_groups(
    graphql_client: &lldap::GraphQLClient,
    ldap_connection: &mut ldap::LdapClient,
) -> Result<Option<GroupList>> {
    Ok(
        if ask_generic_confirmation("should_import_groups", "Do you want to import groups?")? {
            let mut existing_groups = lldap::get_lldap_groups(graphql_client)?;
            let ldap_groups = ldap::get_groups(ldap_connection)?;
            if should_insert_groups(&ldap_groups, &existing_groups)? {
                lldap::insert_groups_into_lldap(
                    &ldap_groups,
                    &mut existing_groups,
                    graphql_client,
                )?;
            }
            Some(GroupList {
                ldap_groups,
                lldap_groups: existing_groups,
            })
        } else {
            None
        },
    )
}

struct UserList {
    lldap_users: Vec<String>,
    ldap_users: Vec<User>,
}

fn migrate_users(
    graphql_client: &lldap::GraphQLClient,
    ldap_connection: &mut ldap::LdapClient,
) -> Result<Option<UserList>> {
    Ok(
        if ask_generic_confirmation("should_import_users", "Do you want to import users?")? {
            let mut existing_users = lldap::get_lldap_users(graphql_client)?;
            let users = ldap::get_users(ldap_connection)?;
            if let Some(users_to_add) = get_users_to_add(&users, &existing_users)? {
                lldap::insert_users_into_lldap(users_to_add, &mut existing_users, graphql_client)?;
            }
            Some(UserList {
                lldap_users: existing_users,
                ldap_users: users,
            })
        } else {
            None
        },
    )
}

fn migrate_memberships(
    user_list: Option<UserList>,
    group_list: Option<GroupList>,
    graphql_client: lldap::GraphQLClient,
    ldap_connection: &mut ldap::LdapClient,
) -> Result<()> {
    let (ldap_users, existing_users) = user_list
        .map(
            |UserList {
                 ldap_users,
                 lldap_users,
             }| (Some(ldap_users), Some(lldap_users)),
        )
        .unwrap_or_default();
    let (ldap_groups, existing_groups) = group_list
        .map(
            |GroupList {
                 ldap_groups,
                 lldap_groups,
             }| (Some(ldap_groups), Some(lldap_groups)),
        )
        .unwrap_or_default();
    let ldap_users = ldap_users
        .ok_or_else(|| anyhow!("Missing LDAP users"))
        .or_else(|_| ldap::get_users(ldap_connection))?;
    let ldap_groups = ldap_groups
        .ok_or_else(|| anyhow!("Missing LDAP groups"))
        .or_else(|_| ldap::get_groups(ldap_connection))?;
    let existing_groups = existing_groups
        .ok_or_else(|| anyhow!("Missing LLDAP groups"))
        .or_else(|_| lldap::get_lldap_groups(&graphql_client))?;
    let existing_users = existing_users
        .ok_or_else(|| anyhow!("Missing LLDAP users"))
        .or_else(|_| lldap::get_lldap_users(&graphql_client))?;
    lldap::insert_group_memberships_into_lldap(
        &ldap_users,
        &ldap_groups,
        &existing_users,
        &existing_groups,
        &graphql_client,
    )?;
    Ok(())
}

fn main() -> Result<()> {
    println!(
        "The migration tool requires access to both the original LDAP \
         server and the HTTP API of the target LLDAP server."
    );
    if !ask_generic_confirmation("setup_ready", "Are you ready to start?")? {
        return Ok(());
    }
    let mut ldap_connection = ldap::get_ldap_connection()?;
    let graphql_client = lldap::get_lldap_client()?;
    let user_list = migrate_users(&graphql_client, &mut ldap_connection)?;
    let group_list = migrate_groups(&graphql_client, &mut ldap_connection)?;
    if ask_generic_confirmation(
        "should_import_memberships",
        "Do you want to import group memberships?",
    )? {
        migrate_memberships(user_list, group_list, graphql_client, &mut ldap_connection)?;
    }

    Ok(())
}
