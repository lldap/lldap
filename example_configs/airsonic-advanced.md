# Configuration for Airsonic Advanced

Replace `dc=example,dc=com` with your LLDAP configured domain.

### LDAP URL
```
ldap://lldap:3890/ou=people,dc=example,dc=com
```
### LDAP search filter
```
(&(uid={0})(memberof=cn=airsonic,ou=groups,dc=example,dc=com))
```

### LDAP manager DN
```
cn=admin,ou=people,dc=example,dc=com
```

### Password
```
admin-password
```

Make sure the box `Automatically create users in Airsonic` is checked.

Restart airsonic-advanced
