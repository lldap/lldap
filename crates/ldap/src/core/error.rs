use ldap3_proto::LdapResultCode;

#[derive(Debug, PartialEq)]
pub struct LdapError {
    pub code: LdapResultCode,
    pub message: String,
}

impl std::fmt::Display for LdapError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for LdapError {}

pub type LdapResult<T> = std::result::Result<T, LdapError>;
