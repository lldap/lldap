use clap::Clap;
use lettre::message::Mailbox;

/// lldap is a lightweight LDAP server
#[derive(Debug, Clap, Clone)]
#[clap(version = "0.1", author = "The LLDAP team")]
pub struct CLIOpts {
    /// Export
    #[clap(subcommand)]
    pub command: Command,
}

#[allow(clippy::large_enum_variant)]
#[derive(Debug, Clap, Clone)]
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

#[derive(Debug, Clap, Clone)]
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

#[derive(Debug, Clap, Clone)]
pub struct RunOpts {
    #[clap(flatten)]
    pub general_config: GeneralConfigOpts,

    /// Change ldap port. Default: 3890
    #[clap(long, env = "LLDAP_LDAP_PORT")]
    pub ldap_port: Option<u16>,

    /// Change ldap ssl port. Default: 6360
    #[clap(long, env = "LLDAP_LDAPS_PORT")]
    pub ldaps_port: Option<u16>,

    /// Change HTTP API port. Default: 17170
    #[clap(long, env = "LLDAP_HTTP_PORT")]
    pub http_port: Option<u16>,

    /// URL of the server, for password reset links.
    #[clap(long, env = "LLDAP_HTTP_URL")]
    pub http_url: Option<String>,

    #[clap(flatten)]
    pub smtp_opts: SmtpOpts,
}

#[derive(Debug, Clap, Clone)]
pub struct TestEmailOpts {
    #[clap(flatten)]
    pub general_config: GeneralConfigOpts,

    /// Email address to send an email to.
    #[clap(long, env = "LLDAP_TEST_EMAIL_TO")]
    pub to: String,

    #[clap(flatten)]
    pub smtp_opts: SmtpOpts,
}

#[derive(Debug, Clap, Clone)]
pub struct SmtpOpts {
    /// Sender email address.
    #[clap(long)]
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
    #[clap(long, env = "LLDAP_SMTP_OPTIONS__TLS_REQUIRED")]
    pub smtp_tls_required: Option<bool>,
}

#[derive(Debug, Clap, Clone)]
pub struct ExportGraphQLSchemaOpts {
    /// Output to a file. If not specified, the config is printed to the standard output.
    #[clap(short, long)]
    pub output_file: Option<String>,
}

pub fn init() -> CLIOpts {
    CLIOpts::parse()
}
