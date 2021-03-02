use clap::Clap;

/// lldap is a lightweight LDAP server
#[derive(Debug, Clap, Clone)]
#[clap(version = "0.1", author = "The LLDAP team")]
pub struct CLIOpts {
    /// Change config file name
    #[clap(short, long, default_value = "lldap_config.toml")]
    pub config_file: String,

    /// Set verbose logging
    #[clap(short, long)]
    pub verbose: bool,
}

pub fn init() -> CLIOpts {
    CLIOpts::parse()
}
