# Configuration for shaarli

LDAP configuration is in ```/data/config.json.php```

Just add the following lines:
```
    "ldap": {
        "host": "ldap://lldap_server:3890",
        "dn": "uid=%s,ou=people,dc=example,dc=com"
    }
```
