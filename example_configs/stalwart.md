# Stalwart Mailserver

[Stalwart-mailserver](https://github.com/stalwartlabs/mail-server) is a Production-ready full-stack but simple mail server (SMTP, JMAP, IMAP, Sieve, LDAP, Antispam, Antivirus, etc.) written in Rust.

To integrate with LLDAP, 

1. Create "manager" user, & make sure to add it to lldap_strict_readonly group for bind permission
   
3. Create "mail" group, & add users requiring email access 

4. Ensure you correctly add the following ldap settings to your Stalwart `config.toml`.

## Config.toml File Sample - (only the ldap portion)
```toml
[storage]
  directory = "ldap"

[directory]
  [directory.ldap]
    base-dn = "dc=example,dc=org"
    timeout = "30s"
    type = "ldap"
    url = "ldap://ldap.domain.example.org:3890"
    [directory.ldap.attributes]
      class = "objectClass"
      email = "mail"
      groups = "member"
      name = "uid"
      secret = "dummyStalwartSecret"
      [directory.ldap.attributes.description]
        0 = "displayName"
    [directory.ldap.bind]
      dn = "uid=manager,ou=people,dc=example,dc=org"
      secret = "<YOUR_MANAGER_PASSWORD>"
      [directory.ldap.bind.auth]
        dn = "uid=?,ou=people,dc=example,dc=org"
        enable = true
        search = true
      [directory.ldap.bind.filter]
        email = "(&(|(objectClass=person)(member=cn=mail,ou=groups,dc=example,dc=org))(mail=?))"
        name = "(&(|(objectClass=person)(member=cn=mail,ou=groups,dc=example,dc=org))(uid=?))"
    [directory.ldap.cache]
      entries = 500
    [directory.ldap.filter]
      email = "(&(objectclass=person)(mail=?))"
      name = "(&(objectclass=person)(uid=?))"
    [directory.ldap.tls]
      allow-invalid-certs = true
      enable = false
```

## Email alias
If you want to enable [email aliases](https://stalw.art/docs/mta/inbound/rcpt/#catch-all-addresses), you have to create a new *User-defined attribute* under *User schema* of type string. Currently, LLDAP doesn't support multi-value filters. If you want multiple aliases, you will have to create multiple attributes (`mailAlias1`, `mailAlias2`, ..., `mailAliasN`), where `N` is the maximum number of aliases an account will have.

You also need to change your ldap filter for emails.
```toml
[directory.ldap.filter]
    email = "(&(objectclass=person)(|(mail=?)(mailAlias1=?)(mailAlias2=?)(mailAliasN=?)))"
```
