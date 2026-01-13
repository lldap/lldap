# Configuration for Semaphore

Semaphore configuration is in `config.json`

Just add the following lines:
```json
  "ldap_enable": true,
  "ldap_needtls": true,
  "ldap_server": "ldaps_server:6360",
  "ldap_binddn": "uid=semaphorebind,ou=people,dc=example,dc=com",
  "ldap_bindpassword": "verysecretpassword",
  "ldap_searchdn": "ou=people,dc=example,dc=com",
  "ldap_searchfilter": "(|(uid=%[1]s)(mail=%[1]s))",
  "ldap_mappings": {
    "dn": "dn",
    "mail": "mail",
    "uid": "uid",
    "cn": "cn"
  }
```

If you use docker environments

You can log in with username or email.
