# Stalwart Mailserver

[Stalwart-mailserver](https://github.com/stalwartlabs/mail-server) is a Production-ready full-stack but simple mail server (SMTP, IMAP, LDAP, Antispam, Antivirus, etc.) written in Rust.

To integrate with LLDAP, 

1. Add manager user, & make sure to add to lldap_admin group for read/write permission
   
2. Create mail group, add users requiring email access 

3. Ensure you correctly add the following ldap settings to your Stalwart `config.toml`.

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
      secret = "<YOUR_SECRET>"
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
      mail = "(&(objectclass=person)(mail=?))"
      name = "(&(objectclass=person)(uid=?))"
    [directory.ldap.tls]
      allow-invalid-certs = true
      enable = false
```
