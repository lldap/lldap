# Configuration for Organizr
####  System Settings > Main > Authentication
---

### Host Address
```
ldap://localhost:3890
```
Replace `localhost:3890` with your LLDAP host & port

### Host Base DN
```
cn=%s,ou=people,dc=example,dc=com
```

### Account prefix
```
cn=
```

### Account Suffix
```
,ou=people,dc=example,dc=com
```

### Bind Username
```
cn=admin,ou=people,dc=example,dc=com
```

### Bind Password
```
Your password from your LDAP config
```
### LDAP Backend Type
```
OpenLDAP
```

Replace `dc=example,dc=com` with your LLDAP configured domain for all occurances
