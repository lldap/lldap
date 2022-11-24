use crate::{
    domain::handler::UserId,
    infra::cli::{GeneralConfigOpts, LdapsOpts, RunOpts, SmtpEncryption, SmtpOpts, TestEmailOpts},
};
use anyhow::{Context, Result};
use figment::{
    providers::{Env, Format, Serialized, Toml},
    Figment,
};
use lettre::message::Mailbox;
use lldap_auth::opaque::{server::ServerSetup, KeyPair};
use secstr::SecUtf8;
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
    #[builder(default = r#"SecUtf8::from("")"#)]
    pub password: SecUtf8,
    #[builder(default = "SmtpEncryption::TLS")]
    pub smtp_encryption: SmtpEncryption,
    /// Deprecated.
    #[builder(default = "None")]
    pub tls_required: Option<bool>,
}

impl std::default::Default for MailOptions {
    fn default() -> Self {
        MailOptionsBuilder::default().build().unwrap()
    }
}

#[derive(Clone, Debug, Deserialize, Serialize, derive_builder::Builder)]
#[builder(pattern = "owned")]
pub struct LdapsOptions {
    #[builder(default = "false")]
    pub enabled: bool,
    #[builder(default = "6360")]
    pub port: u16,
    #[builder(default = r#"String::from("cert.pem")"#)]
    pub cert_file: String,
    #[builder(default = r#"String::from("key.pem")"#)]
    pub key_file: String,
}

impl std::default::Default for LdapsOptions {
    fn default() -> Self {
        LdapsOptionsBuilder::default().build().unwrap()
    }
}

#[derive(Clone, Debug, Deserialize, Serialize, derive_builder::Builder)]
#[builder(pattern = "owned", build_fn(name = "private_build"))]
pub struct Configuration {
    #[builder(default = r#"String::from("0.0.0.0")"#)]
    pub ldap_host: String,
    #[builder(default = "3890")]
    pub ldap_port: u16,
    #[builder(default = r#"String::from("0.0.0.0")"#)]
    pub api_host: String,
    #[builder(default = "17170")]
    pub http_port: u16,
    #[builder(default = r#"SecUtf8::from("secretjwtsecret")"#)]
    pub jwt_secret: SecUtf8,
    #[builder(default = r#"String::from("dc=example,dc=com")"#)]
    pub ldap_base_dn: String,
    #[builder(default = r#"UserId::new("admin")"#)]
    pub ldap_user_dn: UserId,
    #[builder(default = r#"String::default()"#)]
    pub ldap_user_email: String,
    #[builder(default = r#"SecUtf8::from("password")"#)]
    pub ldap_user_pass: SecUtf8,
    #[builder(default = r#"String::from("sqlite://users.db?mode=rwc")"#)]
    pub database_url: String,
    #[builder(default)]
    pub ignored_user_attributes: Vec<String>,
    #[builder(default)]
    pub ignored_group_attributes: Vec<String>,
    #[builder(default = "false")]
    pub verbose: bool,
    #[builder(default = r#"String::from("server_key")"#)]
    pub key_file: String,
    #[builder(default)]
    pub smtp_options: MailOptions,
    #[builder(default)]
    pub ldaps_options: LdapsOptions,
    #[builder(default = r#"String::from("http://localhost")"#)]
    pub http_url: String,
    #[serde(skip)]
    #[builder(field(private), default = "None")]
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
        Ok(self.server_setup(Some(server_setup)).private_build()?)
    }

    #[cfg(test)]
    pub fn for_tests() -> Configuration {
        ConfigurationBuilder::default()
            .verbose(true)
            .server_setup(Some(generate_random_private_key()))
            .private_build()
            .unwrap()
    }
}

impl Configuration {
    pub fn get_server_setup(&self) -> &ServerSetup {
        self.server_setup.as_ref().unwrap()
    }

    pub fn get_server_keys(&self) -> &KeyPair {
        self.get_server_setup().keypair()
    }
}

fn generate_random_private_key() -> ServerSetup {
    let mut rng = rand::rngs::OsRng;
    ServerSetup::new(&mut rng)
}

fn write_to_readonly_file(path: &std::path::Path, buffer: &[u8]) -> Result<()> {
    use std::{fs::File, io::Write};
    assert!(!path.exists());
    let mut file = File::create(path)?;
    let mut permissions = file.metadata()?.permissions();
    permissions.set_readonly(true);
    if cfg!(unix) {
        use std::os::unix::fs::PermissionsExt;
        permissions.set_mode(0o400);
    }
    file.set_permissions(permissions)?;
    Ok(file.write_all(buffer)?)
}

fn get_server_setup(file_path: &str) -> Result<ServerSetup> {
    use std::fs::read;
    let path = std::path::Path::new(file_path);
    if path.exists() {
        let bytes = read(file_path).context(format!("Could not read key file `{}`", file_path))?;
        Ok(ServerSetup::deserialize(&bytes)?)
    } else {
        let server_setup = generate_random_private_key();
        write_to_readonly_file(path, &server_setup.serialize()).context(format!(
            "Could not write the generated server setup to file `{}`",
            file_path,
        ))?;
        Ok(server_setup)
    }
}

pub trait ConfigOverrider {
    fn override_config(&self, config: &mut Configuration);
}

pub trait TopLevelCommandOpts {
    fn general_config(&self) -> &GeneralConfigOpts;
}

impl TopLevelCommandOpts for RunOpts {
    fn general_config(&self) -> &GeneralConfigOpts {
        &self.general_config
    }
}

impl TopLevelCommandOpts for TestEmailOpts {
    fn general_config(&self) -> &GeneralConfigOpts {
        &self.general_config
    }
}

impl ConfigOverrider for RunOpts {
    fn override_config(&self, config: &mut Configuration) {
        self.general_config.override_config(config);

        if let Some(path) = self.server_key_file.as_ref() {
            config.key_file = path.to_string();
        }

        if let Some(port) = self.ldap_port {
            config.ldap_port = port;
        }

        if let Some(port) = self.http_port {
            config.http_port = port;
        }

        if let Some(url) = self.http_url.as_ref() {
            config.http_url = url.to_string();
        }
        self.smtp_opts.override_config(config);
        self.ldaps_opts.override_config(config);
    }
}

impl ConfigOverrider for TestEmailOpts {
    fn override_config(&self, config: &mut Configuration) {
        self.general_config.override_config(config);
        self.smtp_opts.override_config(config);
    }
}

impl ConfigOverrider for LdapsOpts {
    fn override_config(&self, config: &mut Configuration) {
        if let Some(enabled) = self.ldaps_enabled {
            config.ldaps_options.enabled = enabled;
        }
        if let Some(port) = self.ldaps_port {
            config.ldaps_options.port = port;
        }
        if let Some(path) = self.ldaps_cert_file.as_ref() {
            config.ldaps_options.cert_file = path.clone();
        }
        if let Some(path) = self.ldaps_key_file.as_ref() {
            config.ldaps_options.key_file = path.clone();
        }
    }
}

impl ConfigOverrider for GeneralConfigOpts {
    fn override_config(&self, config: &mut Configuration) {
        if self.verbose {
            config.verbose = true;
        }
    }
}

impl ConfigOverrider for SmtpOpts {
    fn override_config(&self, config: &mut Configuration) {
        if let Some(from) = &self.smtp_from {
            config.smtp_options.from = Some(from.clone());
        }
        if let Some(reply_to) = &self.smtp_reply_to {
            config.smtp_options.reply_to = Some(reply_to.clone());
        }
        if let Some(server) = &self.smtp_server {
            config.smtp_options.server = server.clone();
        }
        if let Some(port) = self.smtp_port {
            config.smtp_options.port = port;
        }
        if let Some(user) = &self.smtp_user {
            config.smtp_options.user = user.clone();
        }
        if let Some(password) = &self.smtp_password {
            config.smtp_options.password = SecUtf8::from(password.clone());
        }
        if let Some(tls_required) = self.smtp_tls_required {
            config.smtp_options.tls_required = Some(tls_required);
        }
    }
}

pub fn init<C>(overrides: C) -> Result<Configuration>
where
    C: TopLevelCommandOpts + ConfigOverrider,
{
    let config_file = overrides.general_config().config_file.clone();

    println!(
        "Loading configuration from {}",
        overrides.general_config().config_file
    );

    use figment_file_provider_adapter::FileAdapter;
    let ignore_keys = ["key_file", "cert_file"];
    let mut config: Configuration = Figment::from(Serialized::defaults(
        ConfigurationBuilder::default().private_build().unwrap(),
    ))
    .merge(FileAdapter::wrap(Toml::file(config_file)).ignore(&ignore_keys))
    .merge(FileAdapter::wrap(Env::prefixed("LLDAP_").split("__")).ignore(&ignore_keys))
    .extract()?;

    overrides.override_config(&mut config);
    if config.verbose {
        println!("Configuration: {:#?}", &config);
    }
    config.server_setup = Some(get_server_setup(&config.key_file)?);
    if config.jwt_secret == SecUtf8::from("secretjwtsecret") {
        println!("WARNING: Default JWT secret used! This is highly unsafe and can allow attackers to log in as admin.");
    }
    if config.ldap_user_pass == SecUtf8::from("password") {
        println!("WARNING: Unsecure default admin password is used.");
    }
    if config.smtp_options.tls_required.is_some() {
        println!("DEPRECATED: smtp_options.tls_required field is deprecated, it never did anything. You can replace it with smtp_options.smtp_encryption.");
    }
    Ok(config)
}
