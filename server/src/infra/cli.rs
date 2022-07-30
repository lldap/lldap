use clap::Parser;
use lettre::message::Mailbox;
use serde::{Deserialize, Serialize};

/// lldap is a lightweight LDAP server
#[derive(Debug, Parser, Clone)]
#[clap(version, author)]
pub struct CLIOpts {
    /// Export
    #[clap(subcommand)]
    pub command: Command,
}

#[allow(clippy::large_enum_variant)]
#[derive(Debug, Parser, Clone)]
pub enum Command {
    /// Export the GraphQL schema to *.graphql.
    #[clap(name = "export_graphql_schema")]
    ExportGraphQLSchema(ExportGraphQLSchemaOpts),
    /// Run the LDAP and GraphQL server.
    #[clap(name = "run")]
    Run(RunOpts),
    /// Send a test email.
    #[clap(name = "send_test_email")]
    SendTestEmail(TestEmailOpts),
}

#[derive(Debug, Parser, Clone)]
pub struct GeneralConfigOpts {
    /// Change config file name.
    #[clap(
        short,
        long,
        default_value = "lldap_config.toml",
        env = "LLDAP_CONFIG_FILE"
    )]
    pub config_file: String,

    /// Set verbose logging.
    #[clap(short, long)]
    pub verbose: bool,
}

#[derive(Debug, Parser, Clone)]
pub struct RunOpts {
    #[clap(flatten)]
    pub general_config: GeneralConfigOpts,

    /// Path to the file that contains the private server key.
    /// It will be created if it doesn't exist.
    #[clap(long, env = "LLDAP_SERVER_KEY_FILE")]
    pub server_key_file: Option<String>,

    /// Change ldap port. Default: 3890
    #[clap(long, env = "LLDAP_LDAP_PORT")]
    pub ldap_port: Option<u16>,

    /// Change HTTP API port. Default: 17170
    #[clap(long, env = "LLDAP_HTTP_PORT")]
    pub http_port: Option<u16>,

    /// URL of the server, for password reset links.
    #[clap(long, env = "LLDAP_HTTP_URL")]
    pub http_url: Option<String>,

    #[clap(flatten)]
    pub smtp_opts: SmtpOpts,

    #[clap(flatten)]
    pub ldaps_opts: LdapsOpts,
}

#[derive(Debug, Parser, Clone)]
pub struct TestEmailOpts {
    #[clap(flatten)]
    pub general_config: GeneralConfigOpts,

    /// Email address to send an email to.
    #[clap(long, env = "LLDAP_TEST_EMAIL_TO")]
    pub to: String,

    #[clap(flatten)]
    pub smtp_opts: SmtpOpts,
}

#[derive(Debug, Parser, Clone)]
#[clap(next_help_heading = Some("LDAPS"), setting = clap::AppSettings::DeriveDisplayOrder)]
pub struct LdapsOpts {
    /// Enable LDAPS. Default: false.
    #[clap(long, env = "LLDAP_LDAPS_OPTIONS__ENABLED")]
    pub ldaps_enabled: Option<bool>,

    /// Change ldap ssl port. Default: 6360
    #[clap(long, env = "LLDAP_LDAPS_OPTIONS__PORT")]
    pub ldaps_port: Option<u16>,

    /// Ldaps certificate file. Default: cert.pem
    #[clap(long, env = "LLDAP_LDAPS_OPTIONS__CERT_FILE")]
    pub ldaps_cert_file: Option<String>,

    /// Ldaps certificate key file. Default: key.pem
    #[clap(long, env = "LLDAP_LDAPS_OPTIONS__KEY_FILE")]
    pub ldaps_key_file: Option<String>,
}

clap::arg_enum! {
#[derive(Clone, Debug, Deserialize, Serialize)]
pub enum SmtpEncryption {
    TLS,
    STARTTLS,
}
}

#[derive(Debug, Parser, Clone)]
#[clap(next_help_heading = Some("SMTP"), setting = clap::AppSettings::DeriveDisplayOrder)]
pub struct SmtpOpts {
    /// Sender email address.
    #[clap(long, env = "LLDAP_SMTP_OPTIONS__FROM")]
    pub smtp_from: Option<Mailbox>,

    /// Reply-to email address.
    #[clap(long, env = "LLDAP_SMTP_OPTIONS__TO")]
    pub smtp_reply_to: Option<Mailbox>,

    /// SMTP server.
    #[clap(long, env = "LLDAP_SMTP_OPTIONS__SERVER")]
    pub smtp_server: Option<String>,

    /// SMTP port, 587 by default.
    #[clap(long, env = "LLDAP_SMTP_OPTIONS__PORT")]
    pub smtp_port: Option<u16>,

    /// SMTP user.
    #[clap(long, env = "LLDAP_SMTP_OPTIONS__USER")]
    pub smtp_user: Option<String>,

    /// SMTP password.
    #[clap(long, env = "LLDAP_SMTP_OPTIONS__PASSWORD", hide_env_values = true)]
    pub smtp_password: Option<String>,

    /// Whether TLS should be used to connect to SMTP.
    #[clap(long, env = "LLDAP_SMTP_OPTIONS__TLS_REQUIRED", setting=clap::ArgSettings::Hidden)]
    pub smtp_tls_required: Option<bool>,

    #[clap(long, env = "LLDAP_SMTP_OPTIONS__ENCRYPTION", possible_values = SmtpEncryption::variants(), case_insensitive = true)]
    pub smtp_encryption: Option<SmtpEncryption>,
}

#[derive(Debug, Parser, Clone)]
pub struct ExportGraphQLSchemaOpts {
    /// Output to a file. If not specified, the config is printed to the standard output.
    #[clap(short, long)]
    pub output_file: Option<String>,
}

pub fn init() -> CLIOpts {
    CLIOpts::parse()
}
