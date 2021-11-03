use clap::Clap;

/// lldap is a lightweight LDAP server
#[derive(Debug, Clap, Clone)]
#[clap(version = "0.1", author = "The LLDAP team")]
pub struct CLIOpts {
    /// Export
    #[clap(subcommand)]
    pub command: Command,
}

#[derive(Debug, Clap, Clone)]
pub enum Command {
    /// Export the GraphQL schema to *.graphql.
    #[clap(name = "export_graphql_schema")]
    ExportGraphQLSchema(ExportGraphQLSchemaOpts),
    /// Run the LDAP and GraphQL server.
    #[clap(name = "run")]
    Run(RunOpts),
}

#[derive(Debug, Clap, Clone)]
pub struct RunOpts {
    /// Change config file name.
    #[clap(short, long, default_value = "lldap_config.toml")]
    pub config_file: String,

    /// Change ldap port. Default: 3890
    #[clap(long)]
    pub ldap_port: Option<u16>,

    /// Change ldap ssl port. Default: 6360
    #[clap(long)]
    pub ldaps_port: Option<u16>,

    /// Change HTTP API port. Default: 17170
    #[clap(long)]
    pub http_port: Option<u16>,

    /// Set verbose logging.
    #[clap(short, long)]
    pub verbose: bool,
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
