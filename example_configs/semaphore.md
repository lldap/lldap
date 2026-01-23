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

If you use environment variables:
```bash
Environment=SEMAPHORE_LDAP_ENABLE=true
Environment=SEMAPHORE_LDAP_SERVER="ldaps_server:6360"
Environment=SEMAPHORE_LDAP_NEEDTLS=true
Environment=SEMAPHORE_LDAP_BIND_DN="uid=semaphorebind,ou=people,dc=example,dc=com"
Environment=SEMAPHORE_LDAP_BIND_PASSWORD="verysecretpassword"
Environment=SEMAPHORE_LDAP_SEARCH_DN="ou=people,dc=example,dc=com"
Environment=SEMAPHORE_LDAP_SEARCH_FILTER="(|(uid=%[1]s)(mail=%[1]s))"
Environment=SEMAPHORE_LDAP_MAPPING_UID="uid"
Environment=SEMAPHORE_LDAP_MAPPING_CN="cn"
Environment=SEMAPHORE_LDAP_MAPPING_MAIL="mail"
Environment=SEMAPHORE_LDAP_MAPPING_DN="dn"
```

You can log in with username or email.
