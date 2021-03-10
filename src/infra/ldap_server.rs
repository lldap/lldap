use crate::infra::configuration::Configuration;
use actix_rt::net::TcpStream;
use actix_server::ServerBuilder;
use actix_service::{fn_service, pipeline_factory};
use anyhow::bail;
use anyhow::Result;
use futures_util::future::ok;
use log::*;
use sqlx::any::AnyPool;
use tokio::net::tcp::WriteHalf;
use tokio_util::codec::{FramedRead, FramedWrite};

use ldap3_server::simple::*;
use ldap3_server::LdapCodec;

pub struct LdapSession {
    dn: String,
    sql_pool: AnyPool,
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

async fn handle_incoming_message(
    msg: Result<LdapMsg, std::io::Error>,
    resp: &mut FramedWrite<WriteHalf<'_>, LdapCodec>,
    session: &mut LdapSession,
) -> Result<bool> {
    use futures_util::SinkExt;
    use std::convert::TryFrom;
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
            bail!("Internal server error: {:?}", an_error);
        }
    };

    match session.handle_ldap_message(server_op) {
        None => return Ok(false),
        Some(result) => {
            for rmsg in result.into_iter() {
                if let Err(e) = resp.send(rmsg).await {
                    bail!("Error while sending a response: {:?}", e);
                }
            }

            if let Err(e) = resp.flush().await {
                bail!("Error while flushing responses: {:?}", e);
            }
        }
    }
    Ok(true)
}

pub fn build_ldap_server(
    config: &Configuration,
    sql_pool: AnyPool,
    server_builder: ServerBuilder,
) -> Result<ServerBuilder> {
    use futures_util::StreamExt;

    Ok(
        server_builder.bind("ldap", ("0.0.0.0", config.ldap_port), move || {
            let sql_pool = sql_pool.clone();
            pipeline_factory(fn_service(move |mut stream: TcpStream| {
                let sql_pool = sql_pool.clone();
                async move {
                    // Configure the codec etc.
                    let (r, w) = stream.split();
                    let mut requests = FramedRead::new(r, LdapCodec);
                    let mut resp = FramedWrite::new(w, LdapCodec);

                    let mut session = LdapSession {
                        dn: "Anonymous".to_string(),
                        sql_pool,
                    };

                    while let Some(msg) = requests.next().await {
                        if !handle_incoming_message(msg, &mut resp, &mut session).await? {
                            break;
                        }
                    }

                    Ok(stream)
                }
            }))
            .map_err(|err: anyhow::Error| error!("Service Error: {:?}", err))
            // catch
            .and_then(move |_| {
                // finally
                ok(())
            })
        })?,
    )
}
