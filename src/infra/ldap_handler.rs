use crate::domain::handler::{BackendHandler, ListUsersRequest, User};
use anyhow::{bail, Result};
use ldap3_server::simple::*;

fn make_dn_pair<'a, I>(mut iter: I) -> Result<(String, String)>
where
    I: Iterator<Item = String>,
{
    let pair = (
        iter.next()
            .ok_or(anyhow::Error::msg("Empty DN element"))?
            .clone(),
        iter.next()
            .ok_or(anyhow::Error::msg("Missing DN value"))?
            .clone(),
    );
    if let Some(e) = iter.next() {
        bail!(
            r#"Too many elements in distinguished name: "{:?}", "{:?}", "{:?}""#,
            pair.0,
            pair.1,
            e
        )
    }
    Ok(pair)
}

fn parse_distinguished_name(dn: &str) -> Result<Vec<(String, String)>> {
    dn.split(",")
        .map(|s| make_dn_pair(s.split("=").map(String::from)))
        .collect()
}

fn make_ldap_search_result_entry(user: User, base_dn_str: &str) -> LdapSearchResultEntry {
    LdapSearchResultEntry {
        dn: format!("cn={},{}", user.user_id, base_dn_str),
        attributes: vec![
            LdapPartialAttribute {
                atype: "objectClass".to_string(),
                vals: vec![
                    "inetOrgPerson".to_string(),
                    "posixAccount".to_string(),
                    "mailAccount".to_string(),
                ],
            },
            LdapPartialAttribute {
                atype: "uid".to_string(),
                vals: vec![user.user_id],
            },
            LdapPartialAttribute {
                atype: "mail".to_string(),
                vals: vec![user.email],
            },
            LdapPartialAttribute {
                atype: "givenName".to_string(),
                vals: vec![user.first_name],
            },
            LdapPartialAttribute {
                atype: "sn".to_string(),
                vals: vec![user.last_name],
            },
            LdapPartialAttribute {
                atype: "cn".to_string(),
                vals: vec![user.display_name],
            },
        ],
    }
}

fn is_subtree(subtree: &Vec<(String, String)>, base_tree: &Vec<(String, String)>) -> bool {
    if subtree.len() < base_tree.len() {
        return false;
    }
    let size_diff = subtree.len() - base_tree.len();
    for i in 0..base_tree.len() {
        if subtree[size_diff + i] != base_tree[i] {
            return false;
        }
    }
    true
}

pub struct LdapHandler<Backend: BackendHandler> {
    dn: String,
    backend_handler: Backend,
    pub base_dn: Vec<(String, String)>,
    base_dn_str: String,
}

impl<Backend: BackendHandler> LdapHandler<Backend> {
    pub fn new(backend_handler: Backend, ldap_base_dn: String) -> Self {
        Self {
            dn: "Unauthenticated".to_string(),
            backend_handler,
            base_dn: parse_distinguished_name(&ldap_base_dn).expect(&format!(
                "Invalid value for ldap_base_dn in configuration: {}",
                ldap_base_dn
            )),
            base_dn_str: ldap_base_dn,
        }
    }

    pub fn do_bind(&mut self, sbr: &SimpleBindRequest) -> LdapMsg {
        match self
            .backend_handler
            .bind(crate::domain::handler::BindRequest {
                name: sbr.dn.clone(),
                password: sbr.pw.clone(),
            }) {
            Ok(()) => {
                self.dn = sbr.dn.clone();
                sbr.gen_success()
            }
            Err(_) => sbr.gen_invalid_cred(),
        }
    }

    pub fn do_search(&mut self, lsr: &SearchRequest) -> Vec<LdapMsg> {
        let dn_parts = match parse_distinguished_name(&lsr.base) {
            Ok(dn) => dn,
            Err(_) => {
                return vec![lsr.gen_error(
                    LdapResultCode::OperationsError,
                    format!(r#"Could not parse base DN: "{}""#, lsr.base),
                )]
            }
        };
        if !is_subtree(&dn_parts, &self.base_dn) {
            return vec![lsr.gen_success()];
        }
        let users = match self.backend_handler.list_users(ListUsersRequest {
            attrs: lsr.attrs.clone(),
        }) {
            Ok(users) => users,
            Err(e) => {
                return vec![lsr.gen_error(
                    LdapResultCode::Other,
                    format!(r#"Error during search for "{}": {}"#, lsr.base, e),
                )]
            }
        };
        let mut res = users
            .into_iter()
            .map(|u| lsr.gen_result_entry(make_ldap_search_result_entry(u, &self.base_dn_str)))
            .collect::<Vec<_>>();
        res.push(lsr.gen_success());
        res
    }

    pub fn do_whoami(&mut self, wr: &WhoamiRequest) -> LdapMsg {
        if self.dn == "Unauthenticated" {
            wr.gen_operror("Unauthenticated")
        } else {
            wr.gen_success(format!("dn: {}", self.dn).as_str())
        }
    }

    pub fn handle_ldap_message(&mut self, server_op: ServerOps) -> Option<Vec<LdapMsg>> {
        let result = match server_op {
            ServerOps::SimpleBind(sbr) => vec![self.do_bind(&sbr)],
            ServerOps::Search(sr) => self.do_search(&sr),
            ServerOps::Unbind(_) => {
                // No need to notify on unbind (per rfc4511)
                return None;
            }
            ServerOps::Whoami(wr) => vec![self.do_whoami(&wr)],
        };
        Some(result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::handler::MockTestBackendHandler;
    use chrono::NaiveDateTime;
    use mockall::predicate::eq;

    #[test]
    fn test_bind() {
        let mut mock = MockTestBackendHandler::new();
        mock.expect_bind()
            .with(eq(crate::domain::handler::BindRequest {
                name: "test".to_string(),
                password: "pass".to_string(),
            }))
            .times(1)
            .return_once(|_| Ok(()));
        let mut ldap_handler = LdapHandler::new(mock, "dc=example,dc=com".to_string());

        let request = WhoamiRequest { msgid: 1 };
        assert_eq!(
            ldap_handler.do_whoami(&request),
            request.gen_operror("Unauthenticated")
        );

        let request = SimpleBindRequest {
            msgid: 2,
            dn: "test".to_string(),
            pw: "pass".to_string(),
        };
        assert_eq!(ldap_handler.do_bind(&request), request.gen_success());

        let request = WhoamiRequest { msgid: 3 };
        assert_eq!(
            ldap_handler.do_whoami(&request),
            request.gen_success("dn: test")
        );
    }

    #[test]
    fn test_is_subtree() {
        let subtree1 = vec![
            ("ou".to_string(), "people".to_string()),
            ("dc".to_string(), "example".to_string()),
            ("dc".to_string(), "com".to_string()),
        ];
        let root = vec![
            ("dc".to_string(), "example".to_string()),
            ("dc".to_string(), "com".to_string()),
        ];
        assert!(is_subtree(&subtree1, &root));
        assert!(!is_subtree(&vec![], &root));
    }

    #[test]
    fn test_parse_distinguished_name() {
        let parsed_dn = vec![
            ("ou".to_string(), "people".to_string()),
            ("dc".to_string(), "example".to_string()),
            ("dc".to_string(), "com".to_string()),
        ];
        assert_eq!(
            parse_distinguished_name("ou=people,dc=example,dc=com").expect("parsing failed"),
            parsed_dn
        );
    }

    #[test]
    fn test_search() {
        let mut mock = MockTestBackendHandler::new();
        mock.expect_bind().return_once(|_| Ok(()));
        mock.expect_list_users()
            .with(eq(ListUsersRequest { attrs: vec![] }))
            .times(1)
            .return_once(|_| {
                Ok(vec![
                    User {
                        user_id: "bob_1".to_string(),
                        email: "bob@bobmail.bob".to_string(),
                        display_name: "Bôb Böbberson".to_string(),
                        first_name: "Bôb".to_string(),
                        last_name: "Böbberson".to_string(),
                        creation_date: NaiveDateTime::from_timestamp(1_000_000_000, 0),
                    },
                    User {
                        user_id: "jim".to_string(),
                        email: "jim@cricket.jim".to_string(),
                        display_name: "Jimminy Cricket".to_string(),
                        first_name: "Jim".to_string(),
                        last_name: "Cricket".to_string(),
                        creation_date: NaiveDateTime::from_timestamp(1_003_000_000, 0),
                    },
                ])
            });
        let mut ldap_handler = LdapHandler::new(mock, "dc=example,dc=com".to_string());
        let request = SimpleBindRequest {
            msgid: 1,
            dn: "test".to_string(),
            pw: "pass".to_string(),
        };
        assert_eq!(ldap_handler.do_bind(&request), request.gen_success());
        let request = SearchRequest {
            msgid: 2,
            base: "ou=people,dc=example,dc=com".to_string(),
            scope: LdapSearchScope::Base,
            filter: LdapFilter::And(vec![]),
            attrs: vec![],
        };
        assert_eq!(
            ldap_handler.do_search(&request),
            vec![
                request.gen_result_entry(LdapSearchResultEntry {
                    dn: "cn=bob_1,dc=example,dc=com".to_string(),
                    attributes: vec![
                        LdapPartialAttribute {
                            atype: "objectClass".to_string(),
                            vals: vec!["inetOrgPerson".to_string(), "posixAccount".to_string(), "mailAccount".to_string()]
                        },
                        LdapPartialAttribute {
                            atype: "uid".to_string(),
                            vals: vec!["bob_1".to_string()]
                        },
                        LdapPartialAttribute {
                            atype: "mail".to_string(),
                            vals: vec!["bob@bobmail.bob".to_string()]
                        },
                        LdapPartialAttribute {
                            atype: "givenName".to_string(),
                            vals: vec!["Bôb".to_string()]
                        },
                        LdapPartialAttribute {
                            atype: "sn".to_string(),
                            vals: vec!["Böbberson".to_string()]
                        },
                        LdapPartialAttribute {
                            atype: "cn".to_string(),
                            vals: vec!["Bôb Böbberson".to_string()]
                        }
                    ],
                }),
                request.gen_result_entry(LdapSearchResultEntry {
                    dn: "cn=jim,dc=example,dc=com".to_string(),
                    attributes: vec![
                        LdapPartialAttribute {
                            atype: "objectClass".to_string(),
                            vals: vec!["inetOrgPerson".to_string(), "posixAccount".to_string(), "mailAccount".to_string()]
                        },
                        LdapPartialAttribute {
                            atype: "uid".to_string(),
                            vals: vec!["jim".to_string()]
                        },
                        LdapPartialAttribute {
                            atype: "mail".to_string(),
                            vals: vec!["jim@cricket.jim".to_string()]
                        },
                        LdapPartialAttribute {
                            atype: "givenName".to_string(),
                            vals: vec!["Jim".to_string()]
                        },
                        LdapPartialAttribute {
                            atype: "sn".to_string(),
                            vals: vec!["Cricket".to_string()]
                        },
                        LdapPartialAttribute {
                            atype: "cn".to_string(),
                            vals: vec!["Jimminy Cricket".to_string()]
                        }
                    ],
                }),
                request.gen_success()
            ]
        );
    }
}
