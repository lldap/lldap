# Configuration of RADICALE authentification with lldap.

# Fork of the radicale LDAP plugin to work with LLDAP : https://github.com/shroomify-it/radicale-auth-ldap-plugin

# Full docker-compose stack : https://github.com/shroomify-it/docker-deploy_radicale-agendav-lldap

# Radicale config file v0.3 (inside docker container /etc/radicale/config https://radicale.org/v3.html#configuration)

```
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
