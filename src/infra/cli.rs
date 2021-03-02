use clap::Clap;

/// lldap is a lightweight LDAP server
#[derive(Debug, Clap, Clone)]
#[clap(version = "0.1", author = "The LLDAP team")]
pub struct CLIOpts {
    /// Change config file name
    #[clap(short, long, default_value = "lldap_config.toml")]
    pub config_file: String,

    /// Change ldap port. Default: 389
    #[clap(long)]
    pub ldap_port: Option<u16>,

    /// Change ldap ssl port. Default: 636
    #[clap(long)]
    pub ldaps_port: Option<u16>,

    /// Set verbose logging
    #[clap(short, long)]
    pub verbose: bool,
}

pub fn init() -> CLIOpts {
    CLIOpts::parse()
}
