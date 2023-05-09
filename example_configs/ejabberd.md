# Basic LDAP auth for a Ejabberd XMPP server

[Main documentation here.](https://docs.ejabberd.im/admin/configuration/ldap/)

For simple user auth add this to main ejabberd.yml:

```
host_config:
  xmpp.example.org:
    auth_method: [ldap]
    ldap_servers:
      - 127.0.0.1 #IP or hostname of LLDAP server
    ldap_port: 3890
    ldap_uids:
      - uid
    ldap_rootdn: "uid=lldap_readonly,ou=people,dc=example,dc=org"
    ldap_password: "secret"
    ldap_base: "ou=people,dc=example,dc=org"
```

## vCard from LDAP
Theoretically possible, [see the documentation.](https://docs.ejabberd.im/admin/configuration/ldap/#vcard-in-ldap)

TODO

## Shared roster groups from LDAP

Theoretically possible, [see the documentation.](https://docs.ejabberd.im/admin/configuration/ldap/#shared-roster-in-ldap)

TODO
