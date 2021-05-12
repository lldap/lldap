use anyhow::Result;
use figment::{
    providers::{Env, Format, Serialized, Toml},
    Figment,
};
use serde::{Deserialize, Serialize};

use crate::infra::cli::CLIOpts;

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Configuration {
    pub ldap_port: u16,
    pub ldaps_port: u16,
    pub http_port: u16,
    pub secret_pepper: String,
    pub jwt_secret: String,
    pub ldap_base_dn: String,
    pub ldap_user_dn: String,
    pub ldap_user_pass: String,
    pub database_url: String,
    pub verbose: bool,
}

impl Default for Configuration {
    fn default() -> Self {
        Configuration {
            ldap_port: 3890,
            ldaps_port: 6360,
            http_port: 17170,
            secret_pepper: String::from("secretsecretpepper"),
            jwt_secret: String::from("secretjwtsecret"),
            ldap_base_dn: String::from("dc=example,dc=com"),
            ldap_user_dn: String::from("cn=admin,dc=example,dc=com"),
            ldap_user_pass: String::from("password"),
            database_url: String::from("sqlite://users.db?mode=rwc"),
            verbose: false,
        }
    }
}

impl Configuration {
    fn merge_with_cli(mut self: Configuration, cli_opts: CLIOpts) -> Configuration {
        if cli_opts.verbose {
            self.verbose = true;
        }

        if let Some(port) = cli_opts.ldap_port {
            self.ldap_port = port;
        }

        if let Some(port) = cli_opts.ldaps_port {
            self.ldaps_port = port;
        }

        self
    }
}

pub fn init(cli_opts: CLIOpts) -> Result<Configuration> {
    let config_file = cli_opts.config_file.clone();

    let config: Configuration = Figment::from(Serialized::defaults(Configuration::default()))
        .merge(Toml::file(config_file))
        .merge(Env::prefixed("LLDAP_"))
        .extract()?;

    let config = config.merge_with_cli(cli_opts);
    Ok(config)
}
