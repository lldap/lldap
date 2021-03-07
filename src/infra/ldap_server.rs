use crate::infra::configuration::Configuration;
use actix_rt::net::TcpStream;
use actix_server::ServerBuilder;
use actix_service::{fn_service, pipeline_factory};
use anyhow::Result;
use futures_util::future::ok;
use log::*;

use ldap3_server::simple::*;
use ldap3_server::LdapCodec;

pub struct LdapSession {
    dn: String,
}

impl LdapSession {
    pub fn do_bind(&mut self, sbr: &SimpleBindRequest) -> LdapMsg {
        if sbr.dn == "cn=Directory Manager" && sbr.pw == "password" {
            self.dn = sbr.dn.to_string();
            sbr.gen_success()
        } else if sbr.dn == "" && sbr.pw == "" {
            self.dn = "Anonymous".to_string();
            sbr.gen_success()
        } else {
            sbr.gen_invalid_cred()
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
        wr.gen_success(format!("dn: {}", self.dn).as_str())
    }
}

pub fn build_ldap_server(
    config: &Configuration,
    server_builder: ServerBuilder,
) -> Result<ServerBuilder> {
    use futures_util::SinkExt;
    use futures_util::StreamExt;
    use std::convert::TryFrom;
    use tokio_util::codec::{FramedRead, FramedWrite};

    Ok(
        server_builder.bind("ldap", ("0.0.0.0", config.ldap_port), move || {
            pipeline_factory(fn_service(move |mut stream: TcpStream| async {
                // Configure the codec etc.
                let (r, w) = stream.split();
                let mut reqs = FramedRead::new(r, LdapCodec);
                let mut resp = FramedWrite::new(w, LdapCodec);

                let mut session = LdapSession {
                    dn: "Anonymous".to_string(),
                };

                while let Some(msg) = reqs.next().await {
                    let server_op = match msg
                        .map_err(|_e| ())
                        .and_then(|msg| ServerOps::try_from(msg))
                    {
                        Ok(a_value) => a_value,
                        Err(an_error) => {
                            let _err = resp
                                .send(DisconnectionNotice::gen(
                                    LdapResultCode::Other,
                                    "Internal Server Error",
                                ))
                                .await;
                            let _err = resp.flush().await;
                            return Err(format!("Internal server error: {:?}", an_error));
                        }
                    };
                }

                Ok(stream)
            }))
            .map_err(|err| error!("Service Error: {:?}", err))
            // catch
            .and_then(move |_| {
                // finally
                ok(())
            })
        })?,
    )
}
