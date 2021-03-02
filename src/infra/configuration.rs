use anyhow::Result;
use figment::{
    providers::{Env, Format, Serialized, Toml},
    Figment,
};
use serde::{Deserialize, Serialize};

use crate::infra::cli::CLIOpts;

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Configuration {
    pub log_level_verbose: bool,
    pub secret_pepper: String,
    pub some_text: String,
}

impl Configuration {
    fn from_cli(cli_opts: CLIOpts) -> Self {
        Configuration {
            log_level_verbose: cli_opts.verbose,
            secret_pepper: String::from("secretsecretpepper"),
            some_text: String::new(),
        }
    }
}

pub fn init(cli_opts: CLIOpts) -> Result<Configuration> {
    // FIXME cli arguments are less prioritary than toml config file or env... Not good.
    let config: Configuration = Figment::from(Serialized::defaults(Configuration::from_cli(
        cli_opts.clone(),
    )))
    .merge(Toml::file(cli_opts.config_file))
    .merge(Env::prefixed("LLDAP_"))
    .extract()?;

    Ok(config)
}
