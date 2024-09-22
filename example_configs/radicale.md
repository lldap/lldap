# Configuration of Radicale authentication with LLDAP.

Requires Radicale 3.2.4

```ini
[auth]
type = ldap
ldap_uri = ldap://localhost:3890
ldap_base = dc=example,dc=com
ldap_reader_dn = uid=admin,ou=people,dc=example,dc=com
ldap_secret = CHANGEME
ldap_filter = (&(objectClass=person)(uid={0}))
lc_username = True
```
