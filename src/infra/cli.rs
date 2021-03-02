use clap::Clap;

/// lldap is a lightweight LDAP server
#[derive(Debug, Clap)]
#[clap(version = "0.1", author = "The LLDAP team")]
pub struct CLIOpts;

pub fn init() -> CLIOpts {
    CLIOpts::parse()
}
