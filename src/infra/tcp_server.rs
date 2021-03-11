use crate::domain::handler::*;
use crate::infra::configuration::Configuration;
use actix_rt::net::TcpStream;
use actix_server::ServerBuilder;
use actix_service::pipeline_factory;
use anyhow::{Context, Result};
use futures_util::future::ok;
use log::*;
use std::sync::Arc;

pub fn build_tcp_server<Backend>(
    config: &Configuration,
    backend_handler: Backend,
    server_builder: ServerBuilder,
) -> Result<ServerBuilder>
where
    Backend: BackendHandler + 'static,
{
    use std::sync::atomic::AtomicUsize;
    use std::sync::atomic::Ordering;
    use tokio::io::AsyncReadExt;
    use tokio::io::AsyncWriteExt;

    let count = Arc::new(AtomicUsize::new(0));

    Ok(server_builder
        .bind("http", ("0.0.0.0", config.http_port), move || {
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
        .with_context(|| {
            format!(
                "While bringing up the TCP server with port {}",
                config.http_port
            )
        })?)
}
