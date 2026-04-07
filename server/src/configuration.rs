use crate::{
    cli::{
        GeneralConfigOpts, HealthcheckOpts, LdapsOpts, RunOpts, SmtpEncryption, SmtpOpts,
        TestEmailOpts, TrueFalseAlways,
    },
    database_string::DatabaseUrl,
};
use anyhow::{Context, Result, anyhow, bail};
use figment::{
    Figment, Provider,
    providers::{Env, Format, Serialized, Toml},
};
use figment_file_provider_adapter::FileAdapter;
use lldap_auth::opaque::{
    KeyPair,
    server::{ServerSetup, generate_random_private_key},
};
use lldap_domain::types::{AttributeName, UserId};
use lldap_sql_backend_handler::sql_tables::{
    ConfigLocation, PrivateKeyHash, PrivateKeyInfo, PrivateKeyLocation,
};
use secstr::SecUtf8;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::path::PathBuf;
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

#[derive(Clone, Debug, Deserialize, Serialize, derive_builder::Builder)]
#[builder(pattern = "owned")]
pub struct HealthcheckOptions {
    #[builder(default = r#"String::from("localhost")"#)]
    pub http_host: String,
    #[builder(default = r#"String::from("localhost")"#)]
    pub ldap_host: String,
}

impl std::default::Default for HealthcheckOptions {
    fn default() -> Self {
        HealthcheckOptionsBuilder::default().build().unwrap()
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
    #[builder(default)]
    pub jwt_secret: Option<SecUtf8>,
    #[builder(default = r#"String::from("dc=example,dc=com")"#)]
    pub ldap_base_dn: String,
    #[builder(default = r#"UserId::new("admin")"#)]
    pub ldap_user_dn: UserId,
    #[builder(default)]
    pub ldap_user_email: String,
    #[builder(default)]
    pub ldap_user_pass: Option<SecUtf8>,
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
    #[builder(default = r#"PathBuf::from("./app")"#)]
    pub assets_path: PathBuf,
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
    #[builder(default)]
    pub healthcheck_options: HealthcheckOptions,
}

impl std::default::Default for Configuration {
    fn default() -> Self {
        ConfigurationBuilder::default().build().unwrap()
    }
}

impl ConfigurationBuilder {
    pub fn build(self) -> Result<Configuration> {
        // Builder-time setup (used by `Configuration::default` and a few
        // tests) never opts into key rotation: it cannot, since the
        // `force_update_private_key` flag is part of the runtime config
        // and is only known after parsing TOML/env in `init()`.
        let force_update_private_key = self.force_update_private_key.unwrap_or(false);
        let server_setup = get_server_setup(
            self.key_file.as_deref().unwrap_or("server_key"),
            self.key_seed
                .as_ref()
                .and_then(|o| o.as_ref())
                .map(SecUtf8::unsecure)
                .unwrap_or_default(),
            PrivateKeyLocation::Default,
            force_update_private_key,
        )?;
        Ok(self.server_setup(Some(server_setup)).private_build()?)
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

    /// Returns the raw bytes of the legacy (opaque-ke 0.7) ServerSetup, if available.
    /// Used for backward-compatible password validation during progressive migration.
    pub fn get_legacy_server_key_bytes(&self) -> Option<&[u8]> {
        self.server_setup.as_ref()?.legacy_server_key_bytes.as_deref()
    }

    pub fn get_server_keys(&self) -> &KeyPair {
        self.get_server_setup().keypair()
    }

    pub fn get_private_key_info(&self) -> PrivateKeyInfo {
        PrivateKeyInfo {
            private_key_hash: PrivateKeyHash(stable_hash(self.get_server_keys().private().serialize().as_slice())),
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
                        bail!(
                            "The private key is configured to be generated from a seed (from {new_location:?}), but it used to come from the file {file_path:?} (defined in {old_location:?}). Did you just upgrade from <=v0.4 to >=v0.5? The key seed was not supported, revert to just using the file."
                        );
                    }
                    (PrivateKeyLocation::Default, PrivateKeyLocation::KeySeed(new_location)) => {
                        bail!(
                            "The private key is configured to be generated from a seed (from {new_location:?}), but it used to come from default key file \"server_key\". Did you just upgrade from <=v0.4 to >=v0.5? The key seed was not yet supported, revert to just using the file."
                        );
                    }
                    (
                        PrivateKeyLocation::KeyFile(old_location, old_path),
                        PrivateKeyLocation::KeyFile(new_location, new_path),
                    ) => {
                        if old_path == new_path {
                            bail!(
                                "The contents of the private key file from {old_path:?} have changed. This usually means that the file was deleted and re-created. If using docker, make sure that the folder is made persistent (by mounting a volume or a directory). If you have several instances of LLDAP, make sure they share the same file (or switch to a key seed)."
                            );
                        } else {
                            bail!(
                                "The private key file used to be {old_path:?} (defined in {old_location:?}), but now is {new_path:?} (defined in {new_location:?}. Make sure to copy the old file in the new location."
                            );
                        }
                    }
                    (PrivateKeyLocation::Tests, _) | (_, PrivateKeyLocation::Tests) => {
                        panic!("Test keys unexpected")
                    }
                    (old_location, new_location) => {
                        bail!(
                            "The private key has changed. It used to come from {old_location:?}, but now it comes from {new_location:?}."
                        );
                    }
                }
            }
        }
    }
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

/// Replace `path` with `new_bytes` atomically.
///
/// Writes to a sibling temporary file first (`.{name}.tmp.{pid}`), then
/// renames it over `path`. The temp file is cleaned up on rename failure
/// so we never leak a partial file in the data directory.
fn rotate_key_file_atomically(path: &std::path::Path, new_bytes: &[u8]) -> Result<()> {
    let parent = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or_else(|| std::path::Path::new("."));
    let file_name = path
        .file_name()
        .ok_or_else(|| anyhow::anyhow!("Key file path `{}` has no file name", path.display()))?;
    let mut tmp_path = parent.to_path_buf();
    tmp_path.push(format!(
        ".{}.tmp.{}",
        file_name.to_string_lossy(),
        std::process::id()
    ));

    write_to_readonly_file(&tmp_path, new_bytes).context(format!(
        "Could not write new server setup to temporary file `{}`",
        tmp_path.display()
    ))?;
    if let Err(rename_err) = std::fs::rename(&tmp_path, path) {
        let _ = std::fs::remove_file(&tmp_path);
        return Err(anyhow::anyhow!(rename_err)).context(format!(
            "Could not atomically replace key file `{}` with new server setup",
            path.display()
        ));
    }
    Ok(())
}

#[derive(Debug, Clone)]
pub struct ServerSetupConfig {
    server_setup: ServerSetup,
    private_key_location: PrivateKeyLocation,
    /// Raw bytes of the legacy (opaque-ke 0.7) ServerSetup, if available.
    /// Preserved when upgrading from an older opaque-ke version.
    legacy_server_key_bytes: Option<Vec<u8>>,
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
                    other => panic!("Unexpected config location: {other:?}"),
                }
            }
            PrivateKeyLocationOrFigment::PrivateKeyLocation(PrivateKeyLocation::KeyFile(
                config_location,
                _,
            )) => {
                panic!("Unexpected location: {config_location:?}")
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
                    other => panic!("Unexpected config location: {other:?}"),
                }
            }
            PrivateKeyLocationOrFigment::PrivateKeyLocation(PrivateKeyLocation::KeySeed(file)) => {
                panic!("Unexpected location: {file:?}")
            }
            PrivateKeyLocationOrFigment::PrivateKeyLocation(location) => location.clone(),
        }
    }
}

fn get_server_setup<L: Into<PrivateKeyLocationOrFigment>>(
    file_path: &str,
    key_seed: &str,
    private_key_location: L,
    force_update_private_key: bool,
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
            eprintln!(
                "WARNING: A key_seed was given, we will ignore the key_file and generate one from the seed! Set key_file to an empty string in the config to silence this message."
            );
        } else {
            println!("Generating the private key from the key_seed");
        }
        use rand::SeedableRng;
        let mut rng = rand_chacha::ChaCha20Rng::from_seed(stable_hash(key_seed.as_bytes()));
        Ok(ServerSetupConfig {
            server_setup: ServerSetup::new(&mut rng),
            private_key_location: private_key_location.for_key_seed(),
            legacy_server_key_bytes: None,
        })
    } else if path.exists() {
        let bytes = read(file_path).context(format!("Could not read key file `{file_path}`"))?;
        match ServerSetup::deserialize(&bytes) {
            Ok(server_setup) => Ok(ServerSetupConfig {
                server_setup,
                private_key_location: private_key_location.for_key_file(file_path),
                legacy_server_key_bytes: None,
            }),
            Err(deserialize_err) => {
                // The on-disk key file does not parse as the current opaque-ke
                // version. This could be:
                //   a) a legitimate version upgrade (opaque-ke 0.7 → 4.0), or
                //   b) corruption (bit-rot, partial write, wrong file).
                //
                // We never silently rotate the key here: doing so on case (b)
                // would invalidate every password unrecoverably, and worse, it
                // would happen for ANY command that loads the config (e.g.
                // `lldap test-email`, `lldap healthcheck`). Instead the admin
                // must explicitly opt in via `force_update_private_key`, which
                // is the same flag the existing `compare_private_key_hashes`
                // safety check uses for intentional key rotations.
                if !force_update_private_key {
                    return Err(anyhow::anyhow!(deserialize_err)).context(format!(
                        "while parsing the contents of the `{file_path}` file. \
                         If you are upgrading from a previous opaque-ke version, \
                         restart the server with --force-update-private-key=true \
                         (or LLDAP_FORCE_UPDATE_PRIVATE_KEY=true) to migrate to a \
                         new server key. Existing passwords will be auto-upgraded \
                         on next login via the legacy OPAQUE handshake — they are \
                         NOT lost, as long as the original key file is preserved \
                         on disk until at least one successful login per user."
                    ));
                }

                // Explicit rotation requested. Preserve the legacy bytes in
                // memory for backward-compatible password validation, then
                // atomically replace the on-disk key with a fresh v4.0 key.
                let legacy_bytes = bytes.clone();
                let server_setup = generate_random_private_key();
                rotate_key_file_atomically(path, &server_setup.serialize())?;

                eprintln!(
                    "WARNING: Key file `{file_path}` was rotated to a new opaque-ke \
                     format on the admin's request (--force-update-private-key=true). \
                     Existing passwords will be progressively upgraded on next login \
                     via the legacy OPAQUE handshake."
                );
                Ok(ServerSetupConfig {
                    server_setup,
                    private_key_location: private_key_location.for_key_file(file_path),
                    legacy_server_key_bytes: Some(legacy_bytes),
                })
            }
        }
    } else {
        let server_setup = generate_random_private_key();
        write_to_readonly_file(path, &server_setup.serialize()).context(format!(
            "Could not write the generated server setup to file `{file_path}`",
        ))?;
        Ok(ServerSetupConfig {
            server_setup,
            private_key_location: private_key_location.for_key_file(file_path),
            legacy_server_key_bytes: None,
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

        self.server_key_file
            .as_ref()
            .inspect(|path| config.key_file = path.to_string());

        self.server_key_seed
            .as_ref()
            .inspect(|seed| config.key_seed = Some(SecUtf8::from(seed.as_str())));

        self.ldap_port.inspect(|&port| config.ldap_port = port);

        self.http_port.inspect(|&port| config.http_port = port);

        self.http_url
            .as_ref()
            .inspect(|&url| config.http_url = HttpUrl(url.clone()));

        self.database_url
            .as_ref()
            .inspect(|&database_url| config.database_url = database_url.clone());

        self.force_ldap_user_pass_reset
            .inspect(|&force_ldap_user_pass_reset| {
                config.force_ldap_user_pass_reset = force_ldap_user_pass_reset;
            });

        self.force_update_private_key
            .inspect(|&force_update_private_key| {
                config.force_update_private_key = force_update_private_key;
            });

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
        self.ldaps_enabled
            .inspect(|&enabled| config.ldaps_options.enabled = enabled);

        self.ldaps_port
            .inspect(|&port| config.ldaps_options.port = port);

        self.ldaps_cert_file
            .as_ref()
            .inspect(|path| config.ldaps_options.cert_file.clone_from(path));

        self.ldaps_key_file
            .as_ref()
            .inspect(|path| config.ldaps_options.key_file.clone_from(path));
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
        self.smtp_from
            .as_ref()
            .inspect(|&from| config.smtp_options.from = Some(Mailbox(from.clone())));

        self.smtp_reply_to
            .as_ref()
            .inspect(|&reply_to| config.smtp_options.reply_to = Some(Mailbox(reply_to.clone())));

        self.smtp_server
            .as_ref()
            .inspect(|server| config.smtp_options.server.clone_from(server));

        self.smtp_port
            .inspect(|&port| config.smtp_options.port = port);

        self.smtp_user
            .as_ref()
            .inspect(|user| config.smtp_options.user.clone_from(user));

        self.smtp_password
            .as_ref()
            .inspect(|&password| config.smtp_options.password = SecUtf8::from(password.clone()));

        self.smtp_encryption.as_ref().inspect(|&smtp_encryption| {
            config.smtp_options.smtp_encryption = smtp_encryption.clone();
        });

        self.smtp_tls_required
            .inspect(|&tls_required| config.smtp_options.tls_required = Some(tls_required));

        self.smtp_enable_password_reset
            .inspect(|&enable_password_reset| {
                config.smtp_options.enable_password_reset = enable_password_reset;
            });
    }
}

impl ConfigOverrider for HealthcheckOpts {
    fn override_config(&self, config: &mut Configuration) {
        self.healthcheck_http_host
            .as_ref()
            .inspect(|host| config.healthcheck_options.http_host.clone_from(host));

        self.healthcheck_ldap_host
            .as_ref()
            .inspect(|host| config.healthcheck_options.ldap_host.clone_from(host));
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

fn check_for_unexpected_env_variables<P: Provider>(env_variable_provider: P) {
    use figment::Profile;
    let expected_keys = expected_keys(
        &Figment::from(Serialized::defaults(
            ConfigurationBuilder::default().private_build().unwrap(),
        ))
        .data()
        .unwrap()[&Profile::default()],
    );
    extract_keys(&env_variable_provider.data().unwrap()[&Profile::default()])
        .iter()
        .filter(|k| !expected_keys.contains(k.as_str()))
        .for_each(|k| {
            eprintln!("WARNING: Unknown environment variable: {k}");
        });
}

fn generate_jwt_sample_error() -> String {
    use rand::{Rng, seq::SliceRandom};
    struct Symbols;

    impl rand::distributions::Distribution<char> for Symbols {
        fn sample<R: Rng + ?Sized>(&self, rng: &mut R) -> char {
            *b"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz+,-./:;<=>?_~!@#$%^&*()[]{}:;".choose(rng).unwrap() as char
        }
    }
    format!(
        "The JWT secret must be initialized to a random string, preferably at least 32 characters long. \
            Either set the `jwt_secret` config value or the `LLDAP_JWT_SECRET` environment variable. \
            You can generate the value by running\n\
            LC_ALL=C tr -dc 'A-Za-z0-9!#%&'\\''()*+,-./:;<=>?@[\\]^_{{|}}~' </dev/urandom | head -c 32; echo ''\n\
            or you can use this random value: {}",
        rand::thread_rng()
            .sample_iter(&Symbols)
            .take(32)
            .collect::<String>()
    )
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
    check_for_unexpected_env_variables(env_variable_provider());
    config.server_setup = Some(get_server_setup(
        &config.key_file,
        config
            .key_seed
            .as_ref()
            .map(SecUtf8::unsecure)
            .unwrap_or_default(),
        figment_config,
        // Only rotate the on-disk key file if the admin explicitly opted in.
        // Without this gate, any deserialize failure (corruption, partial
        // write, version mismatch) would silently invalidate every password.
        config.force_update_private_key,
    )?);
    config
        .jwt_secret
        .as_ref()
        .ok_or_else(|| anyhow!("{}", generate_jwt_sample_error()))?;
    if config.smtp_options.tls_required.is_some() {
        println!(
            "DEPRECATED: smtp_options.tls_required field is deprecated, it never did anything. You can replace it with smtp_options.smtp_encryption."
        );
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
        // Verify that seed-based key generation is deterministic: same seed → same key.
        // (The exact byte representation depends on the opaque-ke version and is not
        // asserted here, since the upgrade changes the binary format.)
        let setup1 =
            get_server_setup("/doesnt/exist", "key seed", PrivateKeyLocation::Tests, false)
                .unwrap()
                .server_setup;
        let setup2 =
            get_server_setup("/doesnt/exist", "key seed", PrivateKeyLocation::Tests, false)
                .unwrap()
                .server_setup;
        assert_eq!(
            bincode::serialize(&setup1).unwrap(),
            bincode::serialize(&setup2).unwrap(),
            "Seed-based key generation must be deterministic"
        );
    }

    fn default_run_opts() -> RunOpts {
        RunOpts::parse_from::<_, std::ffi::OsString>([])
    }

    /// Regression test for the silent-key-rotation issue.
    ///
    /// If `get_server_setup` encounters a key file it cannot deserialize
    /// (corruption, version mismatch, partial write, …), it MUST NOT
    /// silently rotate the key. The deserialize error has to be propagated
    /// so the admin notices and decides whether to migrate. Rotation only
    /// happens when the admin opts in via `force_update_private_key=true`.
    #[test]
    fn unparseable_key_file_is_not_silently_rotated() {
        Jail::expect_with(|jail| {
            // Drop a deliberately bogus blob in place of a server_key file.
            std::fs::write(jail.directory().join("server_key"), b"not a real opaque-ke key")
                .unwrap();
            let path_str = jail.directory().join("server_key").to_string_lossy().into_owned();
            let original_bytes = std::fs::read(jail.directory().join("server_key")).unwrap();

            // Without the explicit flag, get_server_setup must fail.
            let err = get_server_setup(&path_str, "", PrivateKeyLocation::Tests, false)
                .expect_err("Unparseable key file must not silently rotate");
            // Make sure the error message points the admin at the migration
            // flag rather than just bubbling up an opaque deserialize error.
            let msg = format!("{:#}", err);
            assert!(
                msg.contains("force-update-private-key"),
                "Error message should mention --force-update-private-key. Got: {msg}"
            );

            // The on-disk file MUST be untouched.
            let after = std::fs::read(jail.directory().join("server_key")).unwrap();
            assert_eq!(after, original_bytes, "Key file must not be touched on failure");
            Ok(())
        });
    }

    /// When the admin explicitly opts in via `force_update_private_key=true`,
    /// rotation is allowed and the legacy bytes are preserved in memory for
    /// progressive password migration.
    #[test]
    fn unparseable_key_file_is_rotated_when_forced() {
        Jail::expect_with(|jail| {
            let original = b"not a real opaque-ke key".to_vec();
            std::fs::write(jail.directory().join("server_key"), &original).unwrap();
            let path_str = jail.directory().join("server_key").to_string_lossy().into_owned();

            let setup = get_server_setup(&path_str, "", PrivateKeyLocation::Tests, true)
                .expect("Forced rotation should succeed");

            // Legacy bytes preserved in memory.
            assert_eq!(
                setup.legacy_server_key_bytes.as_deref(),
                Some(original.as_slice()),
                "Legacy bytes should be preserved for progressive migration"
            );

            // On-disk file replaced with the new key (different from original).
            let after = std::fs::read(jail.directory().join("server_key")).unwrap();
            assert_ne!(after, original, "Key file should have been rotated");
            assert!(
                ServerSetup::deserialize(&after).is_ok(),
                "New on-disk key must be a valid opaque-ke 4.0 ServerSetup"
            );
            Ok(())
        });
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
            jail.clear_env();
            jail.set_env("LLDAP_KEY_SEED", "a123");
            jail.set_env("LLDAP_JWT_SECRET", "secret");
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
            jail.clear_env();
            jail.set_env("LLDAP_KEY_SEED", "a123");
            jail.set_env("LLDAP_JWT_SECRET", "secret");
            init(default_run_opts()).unwrap();
            Ok(())
        });
    }

    #[test]
    fn check_server_setup_key_extraction_seed_failure_with_existing_file() {
        Jail::expect_with(|jail| {
            jail.create_file("lldap_config.toml", r#"key_file = "test""#)?;
            jail.clear_env();
            jail.set_env("LLDAP_KEY_SEED", "a123");
            jail.set_env("LLDAP_JWT_SECRET", "secret");
            write_random_key(jail, "test");
            init(default_run_opts()).unwrap_err();
            Ok(())
        });
    }

    #[test]
    fn check_server_setup_key_extraction_file_success_with_existing_file() {
        Jail::expect_with(|jail| {
            jail.create_file("lldap_config.toml", r#"key_file = "test""#)?;
            jail.clear_env();
            jail.set_env("LLDAP_JWT_SECRET", "secret");
            write_random_key(jail, "test");
            init(default_run_opts()).unwrap();
            Ok(())
        });
    }

    #[test]
    fn check_server_setup_key_extraction_file_success_with_nonexistent_file() {
        Jail::expect_with(|jail| {
            jail.create_file("lldap_config.toml", r#"key_file = "test""#)?;
            jail.clear_env();
            jail.set_env("LLDAP_JWT_SECRET", "secret");
            init(default_run_opts()).unwrap();
            Ok(())
        });
    }

    #[test]
    fn check_server_setup_key_extraction_file_with_previous_different_file() {
        Jail::expect_with(|jail| {
            jail.create_file("lldap_config.toml", r#"key_file = "test""#)?;
            jail.clear_env();
            jail.set_env("LLDAP_JWT_SECRET", "secret");
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
            jail.clear_env();
            jail.set_env("LLDAP_JWT_SECRET", "secret");
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
            jail.clear_env();
            jail.set_env("LLDAP_JWT_SECRET", "secret");
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
