use crate::infra::configuration::Configuration;
use actix_rt::net::TcpStream;
use actix_server::Server;
use actix_service::pipeline_factory;
use anyhow::Result;
use futures_util::future::ok;
use log::*;
use std::sync::Arc;

pub fn init(config: Configuration) -> Result<()> {
    debug!("TCP: init");
    actix::run(run_tcp_server(config))?;

    Ok(())
}

async fn run_tcp_server(config: Configuration) {
    use std::sync::atomic::AtomicUsize;
    use std::sync::atomic::Ordering;
    use tokio::io::AsyncReadExt;
    use tokio::io::AsyncWriteExt;

    let count = Arc::new(AtomicUsize::new(0));

    Server::build()
        .bind("test-tcp", ("0.0.0.0", config.ldap_port), move || {
            let count = Arc::clone(&count);
            let num2 = Arc::clone(&count);

            pipeline_factory(move |mut stream: TcpStream| {
                let count = Arc::clone(&count);
                async move {
                    let num = count.fetch_add(1, Ordering::SeqCst);
                    let num = num + 1;

                    let mut size: usize = 0;
                    let mut buf = Vec::with_capacity(4096);

                    loop {
                        match stream.read_buf(&mut buf).await {
                            // end of stream; bail from loop
                            Ok(0) => break,

                            // more bytes to process
                            Ok(bytes_read) => {
                                info!("[{}] read {} bytes", num, bytes_read);
                                stream.write_all(&buf[size..]).await.unwrap();
                                size += bytes_read;
                            }

                            // stream error; bail from loop with error
                            Err(err) => {
                                error!("Stream Error: {:?}", err);
                                return Err(());
                            }
                        }
                    }

                    // send data down service pipeline
                    Ok((buf, size))
                }
            })
            .map_err(|err| error!("Service Error: {:?}", err))
            .and_then(move |(_, size)| {
                let num = num2.load(Ordering::SeqCst);
                info!("[{}] total bytes read: {}", num, size);
                ok(size)
            })
        })
        .unwrap()
        .workers(1)
        .run()
        .await
        .unwrap();
}
