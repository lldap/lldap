use std::env::var;

pub const DB_KEY: &str = "LLDAP_DATABASE_URL";

pub fn database_url() -> String {
    let url = var(DB_KEY).ok();
    let url = url.unwrap_or("sqlite://e2e_test.db?mode=rwc".to_string());
    url.to_string()
}

pub fn ldap_url() -> String {
    let port = var("LLDAP_LDAP_PORT").ok();
    let port = port.unwrap_or("3890".to_string());
    let mut url = String::from("ldap://localhost:");
    url += &port;
    url
}

pub fn http_url() -> String {
    let port = var("LLDAP_HTTP_PORT").ok();
    let port = port.unwrap_or("17170".to_string());
    let mut url = String::from("http://localhost:");
    url += &port;
    url
}

pub fn admin_dn() -> String {
    let user = var("LLDAP_LDAP_USER_DN").ok();
    let user = user.unwrap_or("admin".to_string());
    user.to_string()
}

pub fn admin_password() -> String {
    let pass = var("LLDAP_LDAP_USER_PASS").ok();
    let pass = pass.unwrap_or("password".to_string());
    pass.to_string()
}

pub fn base_dn() -> String {
    let dn = var("LLDAP_LDAP_BASE_DN").ok();
    let dn = dn.unwrap_or("dc=example,dc=com".to_string());
    dn.to_string()
}
