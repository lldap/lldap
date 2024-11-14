use std::collections::HashSet;

use crate::{
    domain::{
        sql_tables::{ConfigLocation, PrivateKeyHash, PrivateKeyInfo, PrivateKeyLocation},
        types::{AttributeName, UserId},
    },
    infra::{
        cli::{
            GeneralConfigOpts, LdapsOpts, RunOpts, SmtpEncryption, SmtpOpts, TestEmailOpts,
            TrueFalseAlways,
        },
        database_string::DatabaseUrl,
    },
};
use anyhow::{bail, Context, Result};
use figment::{
    providers::{Env, Format, Serialized, Toml},
    Figment,
};
use figment_file_provider_adapter::FileAdapter;
use lldap_auth::opaque::{server::ServerSetup, KeyPair};
use secstr::SecUtf8;
use serde::{Deserialize, Serialize};
use url::Url;

#[derive(
    Clone, Deserialize, Serialize, derive_more::FromStr, derive_more::Debug, derive_more::Display,
)]
#[debug(r#""{_0}""#)]
#[display("{_0}")]
pub struct Mailbox(pub lettre::message::Mailbox);

#[derive(Clone, derive_more::Debug, Deserialize, Serialize, derive_builder::Builder)]
#[builder(pattern = "owned")]
pub struct MailOptions {
    #[builder(default = "false")]
    pub enable_password_reset: bool,
    #[builder(default)]
    pub from: Option<Mailbox>,
    #[builder(default = "None")]
    pub reply_to: Option<Mailbox>,
    #[builder(default = r#""localhost".to_string()"#)]
    pub server: String,
    #[builder(default = "587")]
    pub port: u16,
    #[builder(default)]
    pub user: String,
    #[builder(default = r#"SecUtf8::from("")"#)]
    pub password: SecUtf8,
    #[builder(default = "SmtpEncryption::Tls")]
    pub smtp_encryption: SmtpEncryption,
    /// Deprecated.
    #[debug(skip)]
    #[serde(skip)]
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

#[derive(Clone, Deserialize, Serialize, derive_more::Debug)]
#[debug(r#""{_0}""#)]
pub struct HttpUrl(pub Url);

#[derive(Clone, Deserialize, Serialize, derive_builder::Builder, derive_more::Debug)]
#[builder(pattern = "owned", build_fn(name = "private_build"))]
pub struct Configuration {
    #[builder(default = r#"String::from("0.0.0.0")"#)]
    pub ldap_host: String,
    #[builder(default = "3890")]
    pub ldap_port: u16,
    #[builder(default = r#"String::from("0.0.0.0")"#)]
    pub http_host: String,
    #[builder(default = "17170")]
    pub http_port: u16,
    #[builder(default = r#"SecUtf8::from("secretjwtsecret")"#)]
    pub jwt_secret: SecUtf8,
    #[builder(default = r#"String::from("dc=example,dc=com")"#)]
    pub ldap_base_dn: String,
    #[builder(default = r#"UserId::new("admin")"#)]
    pub ldap_user_dn: UserId,
    #[builder(default)]
    pub ldap_user_email: String,
    #[builder(default = r#"SecUtf8::from("password")"#)]
    pub ldap_user_pass: SecUtf8,
    #[builder(default)]
    pub force_ldap_user_pass_reset: TrueFalseAlways,
    #[builder(default = "false")]
    pub force_update_private_key: bool,
    #[builder(default = r#"DatabaseUrl::from("sqlite://users.db?mode=rwc")"#)]
    pub database_url: DatabaseUrl,
    #[builder(default)]
    pub ignored_user_attributes: Vec<AttributeName>,
    #[builder(default)]
    pub ignored_group_attributes: Vec<AttributeName>,
    #[builder(default = "false")]
    pub verbose: bool,
    #[builder(default = r#"String::from("server_key")"#)]
    pub key_file: String,
    // We want an Option to see whether there is a value or not, since the value is printed as
    // "***SECRET***".
    #[builder(default)]
    pub key_seed: Option<SecUtf8>,
    #[builder(default)]
    pub smtp_options: MailOptions,
    #[builder(default)]
    pub ldaps_options: LdapsOptions,
    #[builder(default = r#"HttpUrl(Url::parse("http://localhost").unwrap())"#)]
    pub http_url: HttpUrl,
    #[debug(skip)]
    #[serde(skip)]
    #[builder(field(private), default = "None")]
    server_setup: Option<ServerSetupConfig>,
}

impl std::default::Default for Configuration {
    fn default() -> Self {
        ConfigurationBuilder::default().build().unwrap()
    }
}

impl ConfigurationBuilder {
    pub fn build(self) -> Result<Configuration> {
        let server_setup = get_server_setup(
            self.key_file.as_deref().unwrap_or("server_key"),
            self.key_seed
                .as_ref()
                .and_then(|o| o.as_ref())
                .map(SecUtf8::unsecure)
                .unwrap_or_default(),
            PrivateKeyLocation::Default,
        )?;
        Ok(self.server_setup(Some(server_setup)).private_build()?)
    }

    #[cfg(test)]
    pub fn for_tests() -> Configuration {
        ConfigurationBuilder::default()
            .verbose(true)
            .server_setup(Some(ServerSetupConfig {
                server_setup: generate_random_private_key(),
                private_key_location: PrivateKeyLocation::Tests,
            }))
            .private_build()
            .unwrap()
    }
}

fn stable_hash(val: &[u8]) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(val);
    hasher.finalize().into()
}

impl Configuration {
    pub fn get_server_setup(&self) -> &ServerSetup {
        &self.server_setup.as_ref().unwrap().server_setup
    }

    pub fn get_server_keys(&self) -> &KeyPair {
        self.get_server_setup().keypair()
    }

    pub fn get_private_key_info(&self) -> PrivateKeyInfo {
        PrivateKeyInfo {
            private_key_hash: PrivateKeyHash(stable_hash(self.get_server_keys().private())),
            private_key_location: self
                .server_setup
                .as_ref()
                .unwrap()
                .private_key_location
                .clone(),
        }
    }
}

/// Returns whether the private key is entirely new.
pub fn compare_private_key_hashes(
    previous_info: Option<&PrivateKeyInfo>,
    private_key_info: &PrivateKeyInfo,
) -> Result<bool> {
    match previous_info {
        None => Ok(true),
        Some(previous_info) => {
            if previous_info.private_key_hash == private_key_info.private_key_hash {
                Ok(false)
            } else {
                match (
                    &previous_info.private_key_location,
                    &private_key_info.private_key_location,
                ) {
                    (
                        PrivateKeyLocation::KeyFile(old_location, file_path),
                        PrivateKeyLocation::KeySeed(new_location),
                    ) => {
                        bail!("The private key is configured to be generated from a seed (from {new_location:?}), but it used to come from the file {file_path:?} (defined in {old_location:?}). Did you just upgrade from <=v0.4 to >=v0.5? The key seed was not supported, revert to just using the file.");
                    }
                    (PrivateKeyLocation::Default, PrivateKeyLocation::KeySeed(new_location)) => {
                        bail!("The private key is configured to be generated from a seed (from {new_location:?}), but it used to come from default key file \"server_key\". Did you just upgrade from <=v0.4 to >=v0.5? The key seed was not yet supported, revert to just using the file.");
                    }
                    (
                        PrivateKeyLocation::KeyFile(old_location, old_path),
                        PrivateKeyLocation::KeyFile(new_location, new_path),
                    ) => {
                        if old_path == new_path {
                            bail!("The contents of the private key file from {old_path:?} have changed. This usually means that the file was deleted and re-created. If using docker, make sure that the folder is made persistent (by mounting a volume or a directory). If you have several instances of LLDAP, make sure they share the same file (or switch to a key seed).");
                        } else {
                            bail!("The private key file used to be {old_path:?} (defined in {old_location:?}), but now is {new_path:?} (defined in {new_location:?}. Make sure to copy the old file in the new location.");
                        }
                    }
                    (old_location, new_location) => {
                        bail!("The private key has changed. It used to come from {old_location:?}, but now it comes from {new_location:?}.");
                    }
                }
            }
        }
    }
}

fn generate_random_private_key() -> ServerSetup {
    let mut rng = rand::rngs::OsRng;
    ServerSetup::new(&mut rng)
}

#[cfg(unix)]
fn set_mode(permissions: &mut std::fs::Permissions) {
    use std::os::unix::fs::PermissionsExt;
    permissions.set_mode(0o400);
}

#[cfg(not(unix))]
fn set_mode(_: &mut std::fs::Permissions) {}

fn write_to_readonly_file(path: &std::path::Path, buffer: &[u8]) -> Result<()> {
    use std::{fs::File, io::Write};
    assert!(!path.exists());
    let mut file = File::create(path)?;
    let mut permissions = file.metadata()?.permissions();
    permissions.set_readonly(true);
    set_mode(&mut permissions);
    file.set_permissions(permissions)?;
    Ok(file.write_all(buffer)?)
}

#[derive(Debug, Clone)]
pub struct ServerSetupConfig {
    server_setup: ServerSetup,
    private_key_location: PrivateKeyLocation,
}

#[derive(derive_more::From)]
enum PrivateKeyLocationOrFigment {
    Figment(Figment),
    PrivateKeyLocation(PrivateKeyLocation),
}

impl PrivateKeyLocationOrFigment {
    fn for_key_seed(&self) -> PrivateKeyLocation {
        match self {
            PrivateKeyLocationOrFigment::Figment(config) => {
                match config.find_metadata("key_seed") {
                    Some(figment::Metadata {
                        source: Some(figment::Source::File(path)),
                        ..
                    }) => PrivateKeyLocation::KeySeed(ConfigLocation::ConfigFile(
                        path.to_string_lossy().to_string(),
                    )),
                    Some(figment::Metadata {
                        source: None, name, ..
                    }) => PrivateKeyLocation::KeySeed(ConfigLocation::EnvironmentVariable(
                        name.clone().to_string(),
                    )),
                    None
                    | Some(figment::Metadata {
                        source: Some(figment::Source::Code(_)),
                        ..
                    }) => PrivateKeyLocation::Default,
                    other => panic!("Unexpected config location: {:?}", other),
                }
            }
            PrivateKeyLocationOrFigment::PrivateKeyLocation(PrivateKeyLocation::KeyFile(
                config_location,
                _,
            )) => {
                panic!("Unexpected location: {:?}", config_location)
            }
            PrivateKeyLocationOrFigment::PrivateKeyLocation(location) => location.clone(),
        }
    }

    fn for_key_file(&self, server_key_file: &str) -> PrivateKeyLocation {
        match self {
            PrivateKeyLocationOrFigment::Figment(config) => {
                match config.find_metadata("key_file") {
                    Some(figment::Metadata {
                        source: Some(figment::Source::File(path)),
                        ..
                    }) => PrivateKeyLocation::KeyFile(
                        ConfigLocation::ConfigFile(path.to_string_lossy().to_string()),
                        server_key_file.into(),
                    ),
                    Some(figment::Metadata {
                        source: None, name, ..
                    }) => PrivateKeyLocation::KeyFile(
                        ConfigLocation::EnvironmentVariable(name.to_string()),
                        server_key_file.into(),
                    ),
                    None
                    | Some(figment::Metadata {
                        source: Some(figment::Source::Code(_)),
                        ..
                    }) => PrivateKeyLocation::Default,
                    other => panic!("Unexpected config location: {:?}", other),
                }
            }
            PrivateKeyLocationOrFigment::PrivateKeyLocation(PrivateKeyLocation::KeySeed(file)) => {
                panic!("Unexpected location: {:?}", file)
            }
            PrivateKeyLocationOrFigment::PrivateKeyLocation(location) => location.clone(),
        }
    }
}

fn get_server_setup<L: Into<PrivateKeyLocationOrFigment>>(
    file_path: &str,
    key_seed: &str,
    private_key_location: L,
) -> Result<ServerSetupConfig> {
    let private_key_location = private_key_location.into();
    use std::fs::read;
    let path = std::path::Path::new(file_path);
    if !key_seed.is_empty() {
        if path.exists() {
            bail!(
                "A key_seed was given, but a key file already exists at `{}`. Which one to use is ambiguous, aborting.\nNote: If you just migrated from <=v0.4 to >=v0.5, the previous version did not support key_seed, so it was falling back onto a key file. Remove the seed from the configuration.",
                file_path
            );
        } else if file_path == "server_key" {
            eprintln!("WARNING: A key_seed was given, we will ignore the key_file and generate one from the seed! Set key_file to an empty string in the config to silence this message.");
        } else {
            println!("Generating the private key from the key_seed");
        }
        use rand::SeedableRng;
        let mut rng = rand_chacha::ChaCha20Rng::from_seed(stable_hash(key_seed.as_bytes()));
        Ok(ServerSetupConfig {
            server_setup: ServerSetup::new(&mut rng),
            private_key_location: private_key_location.for_key_seed(),
        })
    } else if path.exists() {
        let bytes = read(file_path).context(format!("Could not read key file `{}`", file_path))?;
        Ok(ServerSetupConfig {
            server_setup: ServerSetup::deserialize(&bytes).context(format!(
                "while parsing the contents of the `{}` file",
                file_path
            ))?,
            private_key_location: private_key_location.for_key_file(file_path),
        })
    } else {
        let server_setup = generate_random_private_key();
        write_to_readonly_file(path, &server_setup.serialize()).context(format!(
            "Could not write the generated server setup to file `{}`",
            file_path,
        ))?;
        Ok(ServerSetupConfig {
            server_setup,
            private_key_location: private_key_location.for_key_file(file_path),
        })
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

        if let Some(seed) = self.server_key_seed.as_ref() {
            config.key_seed = Some(SecUtf8::from(seed));
        }

        if let Some(port) = self.ldap_port {
            config.ldap_port = port;
        }

        if let Some(port) = self.http_port {
            config.http_port = port;
        }

        if let Some(url) = self.http_url.as_ref() {
            config.http_url = HttpUrl(url.clone());
        }

        if let Some(database_url) = self.database_url.as_ref() {
            config.database_url = database_url.clone();
        }

        if let Some(force_ldap_user_pass_reset) = self.force_ldap_user_pass_reset {
            config.force_ldap_user_pass_reset = force_ldap_user_pass_reset;
        }

        if let Some(force_update_private_key) = self.force_update_private_key {
            config.force_update_private_key = force_update_private_key;
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
            config.ldaps_options.cert_file.clone_from(path);
        }
        if let Some(path) = self.ldaps_key_file.as_ref() {
            config.ldaps_options.key_file.clone_from(path);
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
            config.smtp_options.from = Some(Mailbox(from.clone()));
        }
        if let Some(reply_to) = &self.smtp_reply_to {
            config.smtp_options.reply_to = Some(Mailbox(reply_to.clone()));
        }
        if let Some(server) = &self.smtp_server {
            config.smtp_options.server.clone_from(server);
        }
        if let Some(port) = self.smtp_port {
            config.smtp_options.port = port;
        }
        if let Some(user) = &self.smtp_user {
            config.smtp_options.user.clone_from(user);
        }
        if let Some(password) = &self.smtp_password {
            config.smtp_options.password = SecUtf8::from(password.clone());
        }
        if let Some(smtp_encryption) = &self.smtp_encryption {
            config.smtp_options.smtp_encryption = smtp_encryption.clone();
        }
        if let Some(tls_required) = self.smtp_tls_required {
            config.smtp_options.tls_required = Some(tls_required);
        }
        if let Some(enable_password_reset) = self.smtp_enable_password_reset {
            config.smtp_options.enable_password_reset = enable_password_reset;
        }
    }
}

fn extract_keys(dict: &figment::value::Dict) -> HashSet<String> {
    use figment::value::{Dict, Value};
    fn process_value(value: &Dict, keys: &mut HashSet<String>, path: &mut Vec<String>) {
        for (key, value) in value {
            match value {
                Value::Dict(_, dict) => {
                    path.push(format!("{}__", key.to_ascii_uppercase()));
                    process_value(dict, keys, path);
                    path.pop();
                }
                _ => {
                    keys.insert(format!(
                        "LLDAP_{}{}",
                        path.join(""),
                        key.to_ascii_uppercase()
                    ));
                }
            }
        }
    }
    let mut keys = HashSet::new();
    let mut path = Vec::new();
    process_value(dict, &mut keys, &mut path);
    keys
}

fn expected_keys(dict: &figment::value::Dict) -> HashSet<String> {
    let mut keys = extract_keys(dict);
    // CLI-only values.
    keys.insert("LLDAP_CONFIG_FILE".to_string());
    keys.insert("LLDAP_TEST_EMAIL_TO".to_string());
    // Alternate spellings from clap.
    keys.insert("LLDAP_SERVER_KEY_FILE".to_string());
    keys.insert("LLDAP_SERVER_KEY_SEED".to_string());
    keys.insert("LLDAP_SMTP_OPTIONS__TO".to_string());
    // Deprecated
    keys.insert("LLDAP_SMTP_OPTIONS__TLS_REQUIRED".to_string());
    keys
}

pub fn init<C>(overrides: C) -> Result<Configuration>
where
    C: TopLevelCommandOpts + ConfigOverrider,
{
    println!(
        "Loading configuration from {}",
        &overrides.general_config().config_file
    );

    let ignore_keys = ["key_file", "cert_file"];
    let env_variable_provider =
        || FileAdapter::wrap(Env::prefixed("LLDAP_").split("__")).ignore(&ignore_keys);
    let figment_config = Figment::from(Serialized::defaults(
        ConfigurationBuilder::default().private_build().unwrap(),
    ))
    .merge(
        FileAdapter::wrap(Toml::file(&overrides.general_config().config_file)).ignore(&ignore_keys),
    )
    .merge(env_variable_provider());
    let mut config: Configuration = figment_config.extract()?;

    overrides.override_config(&mut config);
    if config.verbose {
        println!("Configuration: {:#?}", &config);
    }
    {
        use figment::{Profile, Provider};
        let expected_keys = expected_keys(
            &Figment::from(Serialized::defaults(
                ConfigurationBuilder::default().private_build().unwrap(),
            ))
            .data()
            .unwrap()[&Profile::default()],
        );
        extract_keys(&env_variable_provider().data().unwrap()[&Profile::default()])
            .iter()
            .filter(|k| !expected_keys.contains(k.as_str()))
            .for_each(|k| {
                eprintln!("WARNING: Unknown environment variable: LLDAP_{}", k);
            });
    }
    config.server_setup = Some(get_server_setup(
        &config.key_file,
        config
            .key_seed
            .as_ref()
            .map(SecUtf8::unsecure)
            .unwrap_or_default(),
        figment_config,
    )?);
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

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;
    use figment::Jail;
    use pretty_assertions::assert_eq;

    #[test]
    fn check_generated_server_key() {
        assert_eq!(
            bincode::serialize(
                &get_server_setup("/doesnt/exist", "key seed", PrivateKeyLocation::Tests)
                    .unwrap()
                    .server_setup
            )
            .unwrap(),
            [
                255, 206, 202, 50, 247, 13, 59, 191, 69, 244, 148, 187, 150, 227, 12, 250, 20, 207,
                211, 151, 147, 33, 107, 132, 2, 252, 121, 94, 97, 6, 97, 232, 163, 168, 86, 246,
                249, 186, 31, 204, 59, 75, 65, 134, 108, 159, 15, 70, 246, 250, 150, 195, 54, 197,
                195, 176, 150, 200, 157, 119, 13, 173, 119, 8, 32, 0, 0, 0, 0, 0, 0, 0, 248, 123,
                35, 91, 194, 51, 52, 57, 191, 210, 68, 227, 107, 166, 232, 37, 195, 244, 100, 84,
                88, 212, 190, 12, 195, 57, 83, 72, 127, 189, 179, 16, 32, 0, 0, 0, 0, 0, 0, 0, 128,
                112, 60, 207, 205, 69, 67, 73, 24, 175, 187, 62, 16, 45, 59, 136, 78, 40, 187, 54,
                159, 94, 116, 33, 133, 119, 231, 43, 199, 164, 141, 7, 32, 0, 0, 0, 0, 0, 0, 0,
                212, 134, 53, 203, 131, 24, 138, 211, 162, 28, 23, 233, 251, 82, 34, 66, 98, 12,
                249, 205, 35, 208, 241, 50, 128, 131, 46, 189, 211, 51, 56, 109, 32, 0, 0, 0, 0, 0,
                0, 0, 84, 20, 147, 25, 50, 5, 243, 203, 216, 180, 175, 121, 159, 96, 123, 183, 146,
                251, 22, 44, 98, 168, 67, 224, 255, 139, 159, 25, 24, 254, 88, 3
            ]
        );
    }

    fn default_run_opts() -> RunOpts {
        RunOpts::parse_from::<_, std::ffi::OsString>([])
    }

    fn write_random_key(jail: &Jail, file: &str) {
        use std::io::Write;
        let file = std::fs::File::create(jail.directory().join(file)).unwrap();
        let mut writer = std::io::BufWriter::new(file);
        writer
            .write_all(&generate_random_private_key().serialize())
            .unwrap();
    }

    #[test]
    fn figment_location_extraction_key_file() {
        Jail::expect_with(|jail| {
            jail.create_file("lldap_config.toml", r#"key_file = "test""#)?;
            jail.set_env("LLDAP_KEY_SEED", "a123");
            let ignore_keys = ["key_file", "cert_file"];
            let figment_config = Figment::from(Serialized::defaults(
                ConfigurationBuilder::default().private_build().unwrap(),
            ))
            .merge(FileAdapter::wrap(Toml::file("lldap_config.toml")).ignore(&ignore_keys))
            .merge(FileAdapter::wrap(Env::prefixed("LLDAP_").split("__")).ignore(&ignore_keys));
            assert_eq!(
                PrivateKeyLocationOrFigment::Figment(figment_config).for_key_file("path"),
                PrivateKeyLocation::KeyFile(
                    ConfigLocation::ConfigFile(
                        jail.directory()
                            .join("lldap_config.toml")
                            .to_string_lossy()
                            .to_string()
                    ),
                    "path".into()
                )
            );
            Ok(())
        });
    }

    #[test]
    fn check_server_setup_key_extraction_seed_success_with_nonexistant_file() {
        Jail::expect_with(|jail| {
            jail.create_file("lldap_config.toml", r#"key_file = "test""#)?;
            jail.set_env("LLDAP_KEY_SEED", "a123");
            init(default_run_opts()).unwrap();
            Ok(())
        });
    }

    #[test]
    fn check_server_setup_key_extraction_seed_failure_with_existing_file() {
        Jail::expect_with(|jail| {
            jail.create_file("lldap_config.toml", r#"key_file = "test""#)?;
            jail.set_env("LLDAP_KEY_SEED", "a123");
            write_random_key(jail, "test");
            init(default_run_opts()).unwrap_err();
            Ok(())
        });
    }

    #[test]
    fn check_server_setup_key_extraction_file_success_with_existing_file() {
        Jail::expect_with(|jail| {
            jail.create_file("lldap_config.toml", r#"key_file = "test""#)?;
            write_random_key(jail, "test");
            init(default_run_opts()).unwrap();
            Ok(())
        });
    }

    #[test]
    fn check_server_setup_key_extraction_file_success_with_nonexistent_file() {
        Jail::expect_with(|jail| {
            jail.create_file("lldap_config.toml", r#"key_file = "test""#)?;
            init(default_run_opts()).unwrap();
            Ok(())
        });
    }

    #[test]
    fn check_server_setup_key_extraction_file_with_previous_different_file() {
        Jail::expect_with(|jail| {
            jail.create_file("lldap_config.toml", r#"key_file = "test""#)?;
            write_random_key(jail, "test");
            let config = init(default_run_opts()).unwrap();
            let info = config.get_private_key_info();
            write_random_key(jail, "test");
            let new_config = init(default_run_opts()).unwrap();
            let error_message =
                compare_private_key_hashes(Some(&info), &new_config.get_private_key_info())
                    .unwrap_err()
                    .to_string();
            if let PrivateKeyLocation::KeyFile(_, file) = info.private_key_location {
                assert!(
                    error_message.contains(
                        "The contents of the private key file from \"test\" have changed"
                    ),
                    "{error_message}"
                );
                assert_eq!(file, "test");
            } else {
                panic!(
                    "Unexpected private key location: {:?}",
                    info.private_key_location
                );
            }
            Ok(())
        });
    }

    #[test]
    fn check_server_setup_key_extraction_file_to_seed() {
        Jail::expect_with(|jail| {
            jail.create_file("lldap_config.toml", "")?;
            write_random_key(jail, "server_key");
            init(default_run_opts()).unwrap();
            jail.create_file("lldap_config.toml", r#"key_seed = "test""#)?;
            let error_message = init(default_run_opts()).unwrap_err().to_string();
            assert!(
                error_message.contains("A key_seed was given, but a key file already exists at",),
                "{error_message}"
            );
            Ok(())
        });
    }

    #[test]
    fn check_server_setup_key_extraction_file_to_seed_removed_file() {
        Jail::expect_with(|jail| {
            jail.create_file("lldap_config.toml", "")?;
            write_random_key(jail, "server_key");
            let config = init(default_run_opts()).unwrap();
            let info = config.get_private_key_info();
            std::fs::remove_file(jail.directory().join("server_key")).unwrap();
            jail.create_file("lldap_config.toml", r#"key_seed = "test""#)?;
            let new_config = init(default_run_opts()).unwrap();
            let error_message =
                compare_private_key_hashes(Some(&info), &new_config.get_private_key_info())
                    .unwrap_err()
                    .to_string();
            assert!(
                error_message.contains("but it used to come from default key file",),
                "{error_message}"
            );
            Ok(())
        });
    }
}
