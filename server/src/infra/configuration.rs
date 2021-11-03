use crate::infra::cli::RunOpts;
use anyhow::{Context, Result};
use figment::{
    providers::{Env, Format, Serialized, Toml},
    Figment,
};
use lettre::message::Mailbox;
use lldap_auth::opaque::{server::ServerSetup, KeyPair};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Deserialize, Serialize, derive_builder::Builder)]
#[builder(pattern = "owned")]
pub struct MailOptions {
    #[builder(default = "false")]
    pub enable_password_reset: bool,
    #[builder(default = "None")]
    pub from: Option<Mailbox>,
    #[builder(default = "None")]
    pub reply_to: Option<Mailbox>,
    #[builder(default = r#""localhost".to_string()"#)]
    pub server: String,
    #[builder(default = "587")]
    pub port: u16,
    #[builder(default = r#""admin".to_string()"#)]
    pub user: String,
    #[builder(default = r#""".to_string()"#)]
    pub password: String,
    #[builder(default = "true")]
    pub tls_required: bool,
}

impl std::default::Default for MailOptions {
    fn default() -> Self {
        MailOptionsBuilder::default().build().unwrap()
    }
}

#[derive(Clone, Debug, Deserialize, Serialize, derive_builder::Builder)]
#[builder(
    pattern = "owned",
    build_fn(name = "private_build", validate = "Self::validate")
)]
pub struct Configuration {
    #[builder(default = "3890")]
    pub ldap_port: u16,
    #[builder(default = "6360")]
    pub ldaps_port: u16,
    #[builder(default = "17170")]
    pub http_port: u16,
    #[builder(default = r#"String::from("secretjwtsecret")"#)]
    pub jwt_secret: String,
    #[builder(default = r#"String::from("dc=example,dc=com")"#)]
    pub ldap_base_dn: String,
    #[builder(default = r#"String::from("admin")"#)]
    pub ldap_user_dn: String,
    #[builder(default = r#"String::from("password")"#)]
    pub ldap_user_pass: String,
    #[builder(default = r#"String::from("sqlite://users.db?mode=rwc")"#)]
    pub database_url: String,
    #[builder(default = "false")]
    pub verbose: bool,
    #[builder(default = r#"String::from("server_key")"#)]
    pub key_file: String,
    #[builder(default)]
    pub smtp_options: MailOptions,
    #[serde(skip)]
    #[builder(field(private), setter(strip_option))]
    server_setup: Option<ServerSetup>,
}

impl std::default::Default for Configuration {
    fn default() -> Self {
        ConfigurationBuilder::default().build().unwrap()
    }
}

impl ConfigurationBuilder {
    pub fn build(self) -> Result<Configuration> {
        let server_setup = get_server_setup(self.key_file.as_deref().unwrap_or("server_key"))?;
        Ok(self.server_setup(server_setup).private_build()?)
    }

    fn validate(&self) -> Result<(), String> {
        if self.server_setup.is_none() {
            Err("Don't use `private_build`, use `build` instead".to_string())
        } else {
            Ok(())
        }
    }
}

impl Configuration {
    pub fn get_server_setup(&self) -> &ServerSetup {
        self.server_setup.as_ref().unwrap()
    }

    pub fn get_server_keys(&self) -> &KeyPair {
        self.get_server_setup().keypair()
    }

    fn merge_with_cli(mut self: Configuration, cli_opts: RunOpts) -> Configuration {
        if cli_opts.verbose {
            self.verbose = true;
        }

        if let Some(port) = cli_opts.ldap_port {
            self.ldap_port = port;
        }

        if let Some(port) = cli_opts.ldaps_port {
            self.ldaps_port = port;
        }

        if let Some(port) = cli_opts.http_port {
            self.http_port = port;
        }

        self
    }
}

fn get_server_setup(file_path: &str) -> Result<ServerSetup> {
    use std::path::Path;
    let path = Path::new(file_path);
    if path.exists() {
        let bytes =
            std::fs::read(file_path).context(format!("Could not read key file `{}`", file_path))?;
        Ok(ServerSetup::deserialize(&bytes)?)
    } else {
        let mut rng = rand::rngs::OsRng;
        let server_setup = ServerSetup::new(&mut rng);
        std::fs::write(path, server_setup.serialize()).context(format!(
            "Could not write the generated server setup to file `{}`",
            file_path,
        ))?;
        Ok(server_setup)
    }
}

pub fn init(cli_opts: RunOpts) -> Result<Configuration> {
    let config_file = cli_opts.config_file.clone();

    println!("Loading configuration from {}", cli_opts.config_file);

    let config: Configuration = Figment::from(Serialized::defaults(
        ConfigurationBuilder::default().build().unwrap(),
    ))
    .merge(Toml::file(config_file))
    .merge(Env::prefixed("LLDAP_").split("__"))
    .extract()?;

    let mut config = config.merge_with_cli(cli_opts);
    config.server_setup = Some(get_server_setup(&config.key_file)?);
    if config.jwt_secret == "secretjwtsecret" {
        println!("WARNING: Default JWT secret used! This is highly unsafe and can allow attackers to log in as admin.");
    }
    if config.ldap_user_pass == "password" {
        println!("WARNING: Unsecure default admin password is used.");
    }
    Ok(config)
}
