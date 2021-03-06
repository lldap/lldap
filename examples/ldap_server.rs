use tokio::net::{TcpListener, TcpStream};
// use tokio::stream::StreamExt;
use futures::SinkExt;
use futures::StreamExt;
use std::convert::TryFrom;
use std::net;
use std::str::FromStr;
use tokio_util::codec::{FramedRead, FramedWrite};

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

async fn handle_client(socket: TcpStream, _paddr: net::SocketAddr) {
    // Configure the codec etc.
    let (r, w) = tokio::io::split(socket);
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
            Ok(v) => v,
            Err(_) => {
                let _err = resp
                    .send(DisconnectionNotice::gen(
                        LdapResultCode::Other,
                        "Internal Server Error",
                    ))
                    .await;
                let _err = resp.flush().await;
                return;
            }
        };

        let result = match server_op {
            ServerOps::SimpleBind(sbr) => vec![session.do_bind(&sbr)],
            ServerOps::Search(sr) => session.do_search(&sr),
            ServerOps::Unbind(_) => {
                // No need to notify on unbind (per rfc4511)
                return;
            }
            ServerOps::Whoami(wr) => vec![session.do_whoami(&wr)],
        };

        for rmsg in result.into_iter() {
            if let Err(_) = resp.send(rmsg).await {
                return;
            }
        }

        if let Err(_) = resp.flush().await {
            return;
        }
    }
    // Client disconnected
}

async fn acceptor(listener: Box<TcpListener>) {
    println!("start function");
    loop {
        println!("loop");
        match listener.accept().await {
            Ok((socket, paddr)) => {
                println!("OK listener");
                tokio::spawn(handle_client(socket, paddr));
            }
            Err(_e) => {
                println!("Err listener");
                //pass
            }
        }
    }
}

#[tokio::main]
async fn main() -> () {
    let addr = net::SocketAddr::from_str("0.0.0.0:12345").unwrap();
    let listener = Box::new(TcpListener::bind(&addr).await.unwrap());

    // Initiate the acceptor task.
    let _handle = tokio::spawn(async move {
        println!("inside tokio");
        acceptor(listener).await
    })
    .await
    .expect("tokio should start");

    println!("started ldap://127.0.0.1:12345 ...");
    tokio::signal::ctrl_c().await.unwrap();
}
