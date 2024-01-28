# Configuration of RADICALE authentification with lldap.

# See how to implement the correct plugin (v0.3) for radicale : https://github.com/shroomify-it/radicale-auth-ldap-plugin

# Full docker-compose stack : https://github.com/shroomify-it/docker-deploy_radicale-agendav-lldap

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

[server]
hosts = 0.0.0.0:5232, [::]:5232

[storage]
filesystem_folder = /data/.var/lib/radicale/collections

[logging]
#level = debug, info, warning, error, critical
level = error
mask_passwords = true
