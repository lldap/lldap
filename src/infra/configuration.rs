use anyhow::{anyhow, Result};
use figment::{
    providers::{Env, Format, Serialized, Toml},
    Figment,
};
use lldap_model::{opaque, opaque::KeyPair};
use serde::{Deserialize, Serialize};

use crate::infra::cli::CLIOpts;

#[derive(Clone, Debug, Deserialize, Serialize, derive_builder::Builder)]
#[builder(
    pattern = "owned",
    default = "Configuration::default()",
    build_fn(name = "private_build", validate = "Self::validate")
)]
pub struct Configuration {
    pub ldap_port: u16,
    pub ldaps_port: u16,
    pub http_port: u16,
    pub jwt_secret: String,
    pub ldap_base_dn: String,
    pub ldap_user_dn: String,
    pub ldap_user_pass: String,
    pub database_url: String,
    pub verbose: bool,
    pub key_file: String,
    #[serde(skip)]
    #[builder(field(private), setter(strip_option))]
    server_keys: Option<KeyPair>,
}

impl ConfigurationBuilder {
    #[cfg(test)]
    pub fn build(self) -> Result<Configuration> {
        let server_keys = get_server_keys(self.key_file.as_deref().unwrap_or("server_key"))?;
        Ok(self.server_keys(server_keys).private_build()?)
    }

    fn validate(&self) -> Result<(), String> {
        if self.server_keys.is_none() {
            Err("Don't use `private_build`, use `build` instead".to_string())
        } else {
            Ok(())
        }
    }
}

impl Configuration {
    pub fn get_server_keys(&self) -> &KeyPair {
        self.server_keys.as_ref().unwrap()
    }

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

    pub(super) fn default() -> Self {
        Configuration {
            ldap_port: 3890,
            ldaps_port: 6360,
            http_port: 17170,
            jwt_secret: String::from("secretjwtsecret"),
            ldap_base_dn: String::from("dc=example,dc=com"),
            // cn=admin,dc=example,dc=com
            ldap_user_dn: String::from("admin"),
            ldap_user_pass: String::from("password"),
            database_url: String::from("sqlite://users.db?mode=rwc"),
            verbose: false,
            key_file: String::from("server_key"),
            server_keys: None,
        }
    }
}

fn get_server_keys(file_path: &str) -> Result<KeyPair> {
    use opaque_ke::ciphersuite::CipherSuite;
    use std::path::Path;
    let path = Path::new(file_path);
    if path.exists() {
        let bytes = std::fs::read(file_path)
            .map_err(|e| anyhow!("Could not read key file `{}`: {}", file_path, e))?;
        Ok(KeyPair::from_private_key_slice(&bytes)?)
    } else {
        let mut rng = rand::rngs::OsRng;
        let keypair = opaque::DefaultSuite::generate_random_keypair(&mut rng);
        std::fs::write(path, keypair.private().as_slice()).map_err(|e| {
            anyhow!(
                "Could not write the generated server keys to file `{}`: {}",
                file_path,
                e
            )
        })?;
        Ok(keypair)
    }
}

pub fn init(cli_opts: CLIOpts) -> Result<Configuration> {
    let config_file = cli_opts.config_file.clone();

    let config: Configuration = Figment::from(Serialized::defaults(Configuration::default()))
        .merge(Toml::file(config_file))
        .merge(Env::prefixed("LLDAP_"))
        .extract()?;

    let mut config = config.merge_with_cli(cli_opts);
    config.server_keys = Some(get_server_keys(&config.key_file)?);
    Ok(config)
}
