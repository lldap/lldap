# Configuration of Radicale authentication with LLDAP

## Native configuration (requires Radicale >=3.3.0)

```ini
[auth]
type = ldap
ldap_uri = ldap://lldap:3890
ldap_base = dc=example,dc=com
ldap_reader_dn = uid=admin,ou=people,dc=example,dc=com
ldap_secret = CHANGEME
ldap_filter = (&(objectClass=person)(uid={0}))
lc_username = True
```

## Plugin configuration (requires [radicale-auth-ldap](https://github.com/shroomify-it/radicale-auth-ldap-plugin) plugin and Radicale >=3.0)

```ini
[auth]
type = radicale_auth_ldap
ldap_url = ldap://lldap:3890
ldap_base = dc=example,dc=com
ldap_attribute = uid
ldap_filter = (objectClass=person)
ldap_binddn = uid=admin,ou=people,dc=example,dc=com
ldap_password = CHANGEME
ldap_scope = LEVEL
ldap_support_extended = no
```
