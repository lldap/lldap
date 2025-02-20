# Stalwart Mailserver

[Stalwart-mailserver](https://github.com/stalwartlabs/mail-server) is a Production-ready full-stack but simple mail server (SMTP, IMAP, LDAP, Antispam, Antivirus, etc.) written in Rust.

To integrate with LLDAP, ensure you correctly add these ldap setting to your `config.toml`.

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
      secret = "userPassword"
      [directory.ldap.attributes.description]
        0 = "displayName"
    [directory.ldap.bind]
      dn = "uid=admin,ou=people,dc=example,dc=org"
      secret = "<YOUR_SECRET>"
      [directory.ldap.bind.auth]
        dn = "uid=?,ou=people,dc=example,dc=org"
        enable = true
        search = true
      [directory.ldap.bind.filter]
        email = "(&(|(objectClass=person)((memberof=cn=mail,ou=groups,dc=example,dc=org))(|(mail=?)(mailAlias=?)(mailList=?)))"
        name = "(&(|(objectClass=person)((memberof=cn=mail,ou=groups,dc=example,dc=org))(uid=?))"
    [directory.ldap.cache]
      entries = 500
    [directory.ldap.filter]
      mail = "(&(objectclass=person)(mail=?))"
      name = "(&(objectclass=person)(uid=?))"
    [directory.ldap.tls]
      allow-invalid-certs = true
      enable = false
```
