use anyhow::Result;
use figment::{
    providers::{Env, Format, Serialized, Toml},
    util::map,
    Figment,
};
use serde::{Deserialize, Serialize};

use crate::infra::cli::CLIOpts;

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Configuration {
    pub verbose: bool,
    pub secret_pepper: String,
    pub some_text: String,
}

impl Default for Configuration {
    fn default() -> Self {
        Configuration {
            verbose: false,
            secret_pepper: String::from("secretsecretpepper"),
            some_text: String::new(),
        }
    }
}

impl Configuration {
    fn from_cli(cli_opts: CLIOpts) -> Figment {
        let mut config_opts_from_cli = map!();

        // XXX only add the option if given so that the `false` value don't override a
        // previous configuration
        if cli_opts.verbose {
            config_opts_from_cli.insert("verbose", true);
        }

        Figment::new().join(Serialized::defaults(config_opts_from_cli))
    }
}

pub fn init(cli_opts: CLIOpts) -> Result<Configuration> {
    let config_file = cli_opts.config_file.clone();

    let config: Configuration = Figment::from(Serialized::defaults(Configuration::default()))
        .merge(Toml::file(config_file))
        .merge(Env::prefixed("LLDAP_"))
        .merge(Configuration::from_cli(cli_opts))
        .extract()?;

    Ok(config)
}
