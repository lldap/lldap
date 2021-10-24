use crate::domain::handler::{BackendHandler, LoginHandler};
use crate::infra::configuration::Configuration;
use crate::infra::ldap_handler::LdapHandler;
use actix_rt::net::TcpStream;
use actix_server::ServerBuilder;
use actix_service::{fn_service, ServiceFactoryExt};
use anyhow::{anyhow, bail, Result};
use futures_util::future::ok;
use ldap3_server::{proto::LdapMsg, LdapCodec};
use log::*;
use tokio::net::tcp::WriteHalf;
use tokio_util::codec::{FramedRead, FramedWrite};

async fn handle_incoming_message<Backend>(
    msg: Result<LdapMsg, std::io::Error>,
    resp: &mut FramedWrite<WriteHalf<'_>, LdapCodec>,
    session: &mut LdapHandler<Backend>,
) -> Result<bool>
where
    Backend: BackendHandler + LoginHandler,
{
    use futures_util::SinkExt;
    let msg = msg.map_err(|e| anyhow!("Error while receiving LDAP op: {:#}", e))?;
    match session.handle_ldap_message(msg.op).await {
        None => return Ok(false),
        Some(result) => {
            for result_op in result.into_iter() {
                if let Err(e) = resp
                    .send(LdapMsg {
                        msgid: msg.msgid,
                        op: result_op,
                        ctrl: vec![],
                    })
                    .await
                {
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

pub fn build_ldap_server<Backend>(
    config: &Configuration,
    backend_handler: Backend,
    server_builder: ServerBuilder,
) -> Result<ServerBuilder>
where
    Backend: BackendHandler + LoginHandler + 'static,
{
    use futures_util::StreamExt;

    let ldap_base_dn = config.ldap_base_dn.clone();
    let ldap_user_dn = config.ldap_user_dn.clone();
    Ok(
        server_builder.bind("ldap", ("0.0.0.0", config.ldap_port), move || {
            let backend_handler = backend_handler.clone();
            let ldap_base_dn = ldap_base_dn.clone();
            let ldap_user_dn = ldap_user_dn.clone();
            fn_service(move |mut stream: TcpStream| {
                let backend_handler = backend_handler.clone();
                let ldap_base_dn = ldap_base_dn.clone();
                let ldap_user_dn = ldap_user_dn.clone();
                async move {
                    // Configure the codec etc.
                    let (r, w) = stream.split();
                    let mut requests = FramedRead::new(r, LdapCodec);
                    let mut resp = FramedWrite::new(w, LdapCodec);

                    let mut session = LdapHandler::new(backend_handler, ldap_base_dn, ldap_user_dn);

                    while let Some(msg) = requests.next().await {
                        if !handle_incoming_message(msg, &mut resp, &mut session).await? {
                            break;
                        }
                    }

                    Ok(stream)
                }
            })
            .map_err(|err: anyhow::Error| error!("Service Error: {:?}", err))
            // catch
            .and_then(move |_| {
                // finally
                ok(())
            })
        })?,
    )
}
