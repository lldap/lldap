#[cfg(test)]
pub fn init_for_tests() {
    if let Err(e) = tracing_subscriber::FmtSubscriber::builder()
        .with_max_level(tracing::Level::DEBUG)
        .with_test_writer()
        .try_init()
    {
        log::warn!("Could not set up test logging: {:#}", e);
    }
}
