mod infra;

fn main() {
    let config = infra::configuration::init();
    let cli_opts = infra::cli::init();
    println!("Hello, world! Config: {:?}, CLI: {:?}", config, cli_opts);
}
