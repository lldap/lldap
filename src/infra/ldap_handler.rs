use crate::domain::handler::BackendHandler;
use ldap3_server::simple::*;

pub struct LdapHandler<Backend: BackendHandler> {
    dn: String,
    backend_handler: Backend,
}

impl<Backend: BackendHandler> LdapHandler<Backend> {
    pub fn new(backend_handler: Backend) -> Self {
        Self {
            dn: "Unauthenticated".to_string(),
            backend_handler,
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
        vec![
            lsr.gen_result_entry(LdapSearchResultEntry {
                dn: "cn=hello,dc=example,dc=com".to_string(),
                attributes: vec![
                    LdapPartialAttribute {
                        atype: "objectClass".to_string(),
                        vals: vec!["cursed".to_string()],
                    },
                    LdapPartialAttribute {
                        atype: "cn".to_string(),
                        vals: vec!["hello".to_string()],
                    },
                ],
            }),
            lsr.gen_result_entry(LdapSearchResultEntry {
                dn: "cn=world,dc=example,dc=com".to_string(),
                attributes: vec![
                    LdapPartialAttribute {
                        atype: "objectClass".to_string(),
                        vals: vec!["cursed".to_string()],
                    },
                    LdapPartialAttribute {
                        atype: "cn".to_string(),
                        vals: vec!["world".to_string()],
                    },
                ],
            }),
            lsr.gen_success(),
        ]
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
    use mockall::{mock, predicate::*};

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
        let mut ldap_handler = LdapHandler::new(mock);

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
}
