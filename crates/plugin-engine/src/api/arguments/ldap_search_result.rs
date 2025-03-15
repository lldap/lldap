use ldap3_proto::proto::LdapOp;
use lldap_domain::types::{Group, UserAndGroups};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum SearchResult {
    UsersAndGroups(Vec<UserAndGroups>, Vec<Group>),
    Ldap(Vec<LdapOp>),
    Empty,
}
