use anyhow::{anyhow, Context, Result};
use ldap3::{ResultEntry, SearchEntry};
use requestty::{prompt_one, Question};
use smallvec::SmallVec;

use crate::lldap::User;

pub struct LdapClient {
    domain: String,
    connection: ldap3::LdapConn,
}

/// Checks if the URL starts with the protocol, and whether the host is valid (DNS and listening),
/// potentially with the given port. Returns the address + port that managed to connect, if any.
pub fn check_host_exists(
    url: &str,
    protocol_and_port: &[(&str, u16)],
) -> std::result::Result<Option<String>, String> {
    for (protocol, port) in protocol_and_port {
        if url.starts_with(protocol) {
            use std::net::ToSocketAddrs;
            let trimmed_url = url.trim_start_matches(protocol);
            return match trimmed_url.to_socket_addrs() {
                Ok(_) => Ok(Some(url.to_owned())),
                Err(_) => {
                    let new_url = format!("{}:{}", trimmed_url, port);
                    new_url
                        .to_socket_addrs()
                        .map_err(|_| format!("Could not resolve host: '{}'", trimmed_url))
                        .map(|_| Some(format!("{}{}", protocol, new_url)))
                }
            };
        }
    }
    Ok(None)
}

fn autocomplete_domain_suffix(input: String, domain: &str) -> SmallVec<[String; 1]> {
    let mut answers = SmallVec::<[String; 1]>::new();
    for part in input.split(',') {
        if !part.starts_with('d') {
            continue;
        }
        if domain.starts_with(part) {
            answers.push(input.clone() + domain.trim_start_matches(part));
        }
    }
    answers.push(input);
    answers
}

/// Asks the user for the URL of the LDAP server, and checks that a connection can be established.
/// Returns the LDAP URL.
fn get_ldap_url() -> Result<String> {
    let ldap_protocols = &[("ldap://", 389), ("ldaps://", 636)];
    let question = Question::input("ldap_url")
        .message("LDAP_URL (ldap://...)")
        .auto_complete(|answer, _| {
            let mut answers = SmallVec::<[String; 1]>::new();
            if "ldap://".starts_with(&answer) {
                answers.push("ldap://".to_owned());
            }
            if "ldaps://".starts_with(&answer) {
                answers.push("ldaps://".to_owned());
            }
            answers.push(answer);
            answers
        })
        .validate(|url, _| {
            if let Some(url) = check_host_exists(url, ldap_protocols)? {
                ldap3::LdapConn::new(&url)
                    .map_err(|e| format!("Could not connect to LDAP server: {}", e))?;
                Ok(())
            } else {
                Err("LDAP URL should start with 'ldap://' or 'ldaps://'".to_owned())
            }
        })
        .build();
    let answer = prompt_one(question)?;
    Ok(
        check_host_exists(answer.as_string().unwrap(), ldap_protocols)
            .unwrap()
            .unwrap(),
    )
}

/// Binds the LDAP connection by asking the user for the bind DN and password, and returns the bind
/// DN.
fn bind_ldap(
    ldap_connection: &mut ldap3::LdapConn,
    previous_binddn: Option<String>,
) -> Result<String> {
    let binddn = {
        let question = Question::input("ldap_binddn")
            .message("LDAP_BIND_DN (cn=...)")
            .validate(|dn, _| {
                if dn.contains(',') && dn.contains('=') {
                    Ok(())
                } else {
                    Err(
                        "Invalid bind DN, expected something like 'cn=admin,dc=example,dc=com'"
                            .to_owned(),
                    )
                }
            })
            .auto_complete(|answer, _| {
                let mut answers = SmallVec::<[String; 1]>::new();
                if let Some(binddn) = &previous_binddn {
                    answers.push(binddn.clone());
                }
                answers.push(answer);
                answers
            })
            .build();
        let answer = prompt_one(question)?;
        answer.as_string().unwrap().to_owned()
    };
    let password = {
        let question = Question::password("ldap_bind_password")
            .message("LDAP_BIND_PASSWORD")
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
    if let Err(e) = ldap_connection
        .simple_bind(&binddn, &password)
        .and_then(ldap3::LdapResult::success)
    {
        println!("Error connecting as '{}': {}", binddn, e);
        bind_ldap(ldap_connection, Some(binddn))
    } else {
        Ok(binddn)
    }
}

impl TryFrom<ResultEntry> for User {
    type Error = anyhow::Error;

    fn try_from(value: ResultEntry) -> Result<Self> {
        let entry = SearchEntry::construct(value);
        let get_required_attribute = |attr| {
            entry
                .attrs
                .get(attr)
                .ok_or_else(|| anyhow!("Missing {} for user", attr))
                .and_then(|u| -> Result<String> {
                    u.iter()
                        .next()
                        .map(String::to_owned)
                        .ok_or_else(|| anyhow!("Too many {}s", attr))
                })
        };
        let id = get_required_attribute("uid")
            .or_else(|_| get_required_attribute("sAMAccountName"))
            .or_else(|_| get_required_attribute("userPrincipalName"))?;
        let email = get_required_attribute("mail")
            .or_else(|_| get_required_attribute("rfc822mailbox"))
            .context(format!("for user '{}'", id))?;

        let get_optional_attribute = |attr: &str| {
            entry
                .attrs
                .get(attr)
                .and_then(|v| v.first().map(|s| s.as_str()))
                .filter(|s| !s.is_empty())
                .map(str::to_owned)
        };
        let last_name = get_optional_attribute("sn").or_else(|| get_optional_attribute("surname"));
        let display_name = get_optional_attribute("cn")
            .or_else(|| get_optional_attribute("commonName"))
            .or_else(|| get_optional_attribute("name"))
            .or_else(|| get_optional_attribute("displayName"));
        let first_name = get_optional_attribute("givenName");
        let avatar = entry
            .attrs
            .get("jpegPhoto")
            .map(|v| v.iter().map(|s| s.as_bytes().to_vec()).collect::<Vec<_>>())
            .or_else(|| entry.bin_attrs.get("jpegPhoto").cloned())
            .and_then(|v| v.into_iter().next().filter(|s| !s.is_empty()));
        let password =
            get_optional_attribute("userPassword").or_else(|| get_optional_attribute("password"));
        Ok(User::new(
            crate::lldap::CreateUserInput {
                id,
                email,
                display_name,
                first_name,
                last_name,
                avatar: avatar.map(base64::encode),
                attributes: None,
            },
            password,
            entry.dn,
        ))
    }
}

enum OuType {
    User,
    Group,
}

fn detect_ou(
    ldap_connection: &mut ldap3::LdapConn,
    domain: &str,
    for_type: OuType,
) -> Result<(Option<String>, Vec<String>), anyhow::Error> {
    let ous = ldap_connection
        .search(
            domain,
            ldap3::Scope::Subtree,
            "(objectClass=organizationalUnit)",
            vec!["dn"],
        )?
        .success()?
        .0;
    let mut detected_ou = None;
    let mut all_ous = Vec::new();
    for result_entry in ous {
        let dn = SearchEntry::construct(result_entry).dn;
        match for_type {
            OuType::User => {
                if dn.contains("user") || dn.contains("people") || dn.contains("person") {
                    detected_ou = Some(dn.clone());
                }
            }
            OuType::Group => {
                if dn.contains("group") {
                    detected_ou = Some(dn.clone());
                }
            }
        }
        all_ous.push(dn);
    }
    Ok((detected_ou, all_ous))
}

pub fn get_users(connection: &mut LdapClient) -> Result<Vec<User>, anyhow::Error> {
    let LdapClient {
        connection: ldap_connection,
        domain,
    } = connection;
    let domain = domain.as_str();
    let (maybe_user_ou, all_ous) = detect_ou(ldap_connection, domain, OuType::User)?;
    let user_ou = {
        let question = Question::input("ldap_user_ou")
            .message(format!(
                "Where are the users located (under '{}')? {}(LDAP_USERS_DN)",
                domain,
                maybe_user_ou
                    .as_ref()
                    .map(|ou| format!("Detected: {}", ou))
                    .unwrap_or_default()
            ))
            .validate(|dn, _| {
                if dn.contains('=') {
                    Ok(())
                } else {
                    Err(format!(
                        "Invalid bind DN, expected something like 'ou=people,{}'",
                        domain
                    ))
                }
            })
            .default(maybe_user_ou.unwrap_or_default())
            .auto_complete(|s, _| {
                let mut answers = autocomplete_domain_suffix(s, domain);
                answers.extend(all_ous.clone());
                answers
            })
            .build();
        let answer = prompt_one(question)?;
        let mut answer = answer.as_string().unwrap().to_owned();
        if !answer.ends_with(domain) {
            if !answer.is_empty() {
                answer += ",";
            }
            answer += domain;
        }
        answer
    };
    let users = ldap_connection
        .search(
            &user_ou,
            ldap3::Scope::Subtree,
            "(|(objectClass=inetOrgPerson)(objectClass=person)(objectClass=mailAccount)(objectClass=posixAccount)(objectClass=user)(objectClass=organizationalPerson))",
            vec![
                "uid",
                "sAMAccountName",
                "userPrincipalName",
                "mail",
                "rfc822mailbox",
                "givenName",
                "sn",
                "surname",
                "cn",
                "commonName",
                "displayName",
                "name",
                "userPassword",
            ],
        )?
        .success()?
        .0;
    users
        .into_iter()
        .map(TryFrom::try_from)
        .collect::<Result<Vec<User>>>()
}

#[derive(Debug)]
pub struct LdapGroup {
    pub name: String,
    pub members: Vec<String>,
}

impl TryFrom<ResultEntry> for LdapGroup {
    type Error = anyhow::Error;

    // https://github.com/graphql-rust/graphql-client/issues/386
    #[allow(non_snake_case)]
    fn try_from(value: ResultEntry) -> Result<Self> {
        let entry = SearchEntry::construct(value);
        let get_required_attribute = |attr| {
            entry
                .attrs
                .get(attr)
                .ok_or_else(|| anyhow!("Missing {} for user", attr))
                .and_then(|u| {
                    if u.len() > 1 {
                        Err(anyhow!("Too many {}s", attr))
                    } else {
                        Ok(u.first().unwrap().to_owned())
                    }
                })
        };
        let name = get_required_attribute("cn")
            .or_else(|_| get_required_attribute("commonName"))
            .or_else(|_| get_required_attribute("displayName"))
            .or_else(|_| get_required_attribute("name"))?;

        let get_repeated_attribute = |attr: &str| entry.attrs.get(attr).map(|v| v.to_owned());
        let members = get_repeated_attribute("member")
            .or_else(|| get_repeated_attribute("uniqueMember"))
            .unwrap_or_default();
        Ok(LdapGroup { name, members })
    }
}

pub fn get_groups(connection: &mut LdapClient) -> Result<Vec<LdapGroup>> {
    let LdapClient {
        connection: ldap_connection,
        domain,
    } = connection;
    let domain = domain.as_str();
    let (maybe_group_ou, all_ous) = detect_ou(ldap_connection, domain, OuType::Group)?;
    let group_ou = {
        let question = Question::input("ldap_group_ou")
            .message(format!(
                "Where are the groups located (under '{}')? {}(LDAP_GROUPS_DN)",
                domain,
                maybe_group_ou
                    .as_ref()
                    .map(|ou| format!("Detected: {}", ou))
                    .unwrap_or_default()
            ))
            .validate(|dn, _| {
                if dn.contains('=') {
                    Ok(())
                } else {
                    Err(format!(
                        "Invalid bind DN, expected something like 'ou=groups,{}'",
                        domain
                    ))
                }
            })
            .default(maybe_group_ou.unwrap_or_default())
            .auto_complete(|s, _| {
                let mut answers = autocomplete_domain_suffix(s, domain);
                answers.extend(all_ous.clone());
                answers
            })
            .build();
        let answer = prompt_one(question)?;
        let mut answer = answer.as_string().unwrap().to_owned();
        if !answer.ends_with(domain) {
            if !answer.is_empty() {
                answer += ",";
            }
            answer += domain;
        }
        answer
    };
    let groups = ldap_connection
        .search(
            &group_ou,
            ldap3::Scope::Subtree,
            "(|(objectClass=group)(objectClass=groupOfNames)(objectClass=groupOfUniqueNames))",
            vec![
                "cn",
                "commonName",
                "displayName",
                "name",
                "member",
                "uniqueMember",
            ],
        )?
        .success()?
        .0;
    let input_groups = groups
        .into_iter()
        .map(TryFrom::try_from)
        .collect::<Result<Vec<LdapGroup>>>()?;
    Ok(input_groups)
}

pub fn get_ldap_connection() -> Result<LdapClient, anyhow::Error> {
    let url = get_ldap_url()?;
    let mut ldap_connection = ldap3::LdapConn::new(&url)?;
    println!("Server found");
    let bind_dn = bind_ldap(&mut ldap_connection, None)?;
    println!("Connection established");
    let domain = &bind_dn[(bind_dn.find(",dc=").expect("Could not find domain?!") + 1)..];
    // domain is 'dc=example,dc=com'
    Ok(LdapClient {
        connection: ldap_connection,
        domain: domain.to_owned(),
    })
}
