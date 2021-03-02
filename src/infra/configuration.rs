use anyhow::Result;
use figment::{
    providers::{Env, Format, Serialized, Toml},
    Figment,
};
use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize, Serialize)]
pub struct Configuration {
    secret_pepper: String,
    some_text: String,
}

impl Default for Configuration {
    fn default() -> Self {
        Configuration {
            secret_pepper: String::from("secretsecretpepper"),
            some_text: String::new(),
        }
    }
}

pub fn init() -> Result<Configuration> {
    let config: Configuration = Figment::from(Serialized::defaults(Configuration::default()))
        .merge(Toml::file("lldap_config.toml"))
        .merge(Env::prefixed("LLDAP_"))
        .extract()?;

    Ok(config)
}
